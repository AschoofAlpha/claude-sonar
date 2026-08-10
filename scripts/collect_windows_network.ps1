[CmdletBinding()]
param(
    [string]$ConfigDir = (Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'),
    [string]$PolicyGroupPattern = '(?i)(OpenAI|Claude|Anthropic|ChatGPT|Gemini|(?:^|[^A-Za-z0-9])AI(?:$|[^A-Za-z0-9]))',
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-YamlScalar {
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$KeyPattern
    )

    $match = [regex]::Match($Text, "(?im)^\s*(?:$KeyPattern)\s*:\s*(?<value>[^#\r\n]+?)\s*$")
    if (-not $match.Success) {
        return $null
    }

    return $match.Groups['value'].Value.Trim().Trim("'`"")
}

function ConvertTo-NullableBoolean {
    param([AllowNull()][string]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -match '^(?i:true|yes|on|1)$') {
        return $true
    }
    if ($Value -match '^(?i:false|no|off|0)$') {
        return $false
    }
    return $null
}

function Get-YamlBlock {
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Section
    )

    $pattern = "(?ms)^$([regex]::Escape($Section))\s*:\s*(?:#.*)?\r?\n(?<body>(?:(?:^[ \t]+.*|^\s*)\r?\n?)*)"
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) {
        return ''
    }
    return $match.Groups['body'].Value
}

function Read-TextIfPresent {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }
    return [System.IO.File]::ReadAllText($Path)
}

function Get-PropertyValue {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-EnvironmentStatusRows {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$ContentValue
    )
    $rows = @()
    foreach ($scope in @('Process','User','Machine')) {
        $value = [Environment]::GetEnvironmentVariable($Name, $scope)
        $active = if ($ContentValue) { $null -ne $value -and $value -match '^(?:1|file:.+)$' } else { $value -ceq '1' }
        $rows += [pscustomobject][ordered]@{ Scope = $scope; Present = $null -ne $value; Active = $active }
    }
    return $rows
}

function Test-ProxyServerLoopback {
    param([AllowEmptyString()][string]$ProxyServer)
    $targets = @($ProxyServer -split ';' | ForEach-Object { ($_ -replace '^[^=]+=', '').Trim() } | Where-Object { $_ })
    if ($targets.Count -eq 0) { return $false }
    return @($targets | Where-Object { $_ -notmatch '^(?:(?:https?|socks5?)://)?(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$' }).Count -eq 0
}

function Get-DnsServerClass {
    param([AllowEmptyString()][string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return 'Unknown' }
    if ([Net.IPAddress]::IsLoopback($parsed)) { return 'Loopback' }
    if ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $bytes = $parsed.GetAddressBytes()
        if ($bytes[0] -eq 198 -and $bytes[1] -in @(18,19)) { return 'FakeIp' }
    }
    return 'Other'
}

function Get-BrowserWebRtcAudit {
    param(
        [Parameter(Mandatory)][string]$UserDataPath,
        [Parameter(Mandatory)][string[]]$ExecutablePaths,
        [Parameter(Mandatory)][string]$PolicyRegistryPath
    )

    $managedWebRtcPolicyPresent = $false
    $restrictiveWebRtcPolicyDetected = $false
    foreach ($scope in @('HKCU','HKLM')) {
        $registryPath = "${scope}:\SOFTWARE\Policies\$PolicyRegistryPath"
        $policy = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if ($null -eq $policy) {
            continue
        }
        $policyValues = @(
            (Get-PropertyValue -Object $policy -Name 'WebRtcIPHandling'),
            (Get-PropertyValue -Object $policy -Name 'WebRtcIPHandlingUrl'),
            (Get-PropertyValue -Object $policy -Name 'WebRtcLocalhostIpHandling')
        )
        $managedWebRtcPolicyPresent = $managedWebRtcPolicyPresent -or (@($policyValues | Where-Object { $null -ne $_ }).Count -gt 0)
        $restrictiveWebRtcPolicyDetected = $restrictiveWebRtcPolicyDetected -or (($policyValues | Out-String) -match 'disable_non_proxied_udp')
    }

    $installed = Test-Path -LiteralPath $UserDataPath -PathType Container
    foreach ($path in $ExecutablePaths) {
        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            $installed = $true
            break
        }
    }

    return [pscustomobject][ordered]@{
        Installed = $installed
        ManagedWebRtcPolicyPresent = $managedWebRtcPolicyPresent
        RestrictiveWebRtcPolicyDetected = $restrictiveWebRtcPolicyDetected
    }
}

function Test-FirefoxRestrictivePreference {
    param([AllowNull()][string]$Name, [AllowNull()]$Value)

    if (-not $Name) { return $false }
    $normalized = [string]$Name
    $text = if ($null -eq $Value) { '' } else { [string]$Value }

    if ($normalized -match '(?i)^media\.peerconnection\.enabled$' -and $text -match '^(?i:false|0)$') {
        return $true
    }
    if ($normalized -match '(?i)^media\.peerconnection\.ice\.(?:proxy_only|default_address_only|no_host)$' -and $text -match '^(?i:true|1)$') {
        return $true
    }
    if ($normalized -match '(?i)DisableWebRTC' -and $text -match '^(?i:true|1)$') {
        return $true
    }
    return $false
}

function Get-FirefoxWebRtcAudit {
    # Best-effort Firefox WebRTC policy detection (registry + distribution policies.json).
    # Does not read user profiles. Same JSON shape as Chromium browser audits.
    $executablePaths = @(
        (Join-Path $env:ProgramFiles 'Mozilla Firefox\firefox.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Mozilla Firefox\firefox.exe'),
        (Join-Path $env:LOCALAPPDATA 'Mozilla Firefox\firefox.exe')
    )
    $userDataPath = Join-Path $env:APPDATA 'Mozilla\Firefox'
    $installed = Test-Path -LiteralPath $userDataPath -PathType Container
    foreach ($path in $executablePaths) {
        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            $installed = $true
            break
        }
    }

    $managedWebRtcPolicyPresent = $false
    $restrictiveWebRtcPolicyDetected = $false

    foreach ($scope in @('HKCU', 'HKLM')) {
        $basePath = "${scope}:\SOFTWARE\Policies\Mozilla\Firefox"
        $policy = Get-ItemProperty -LiteralPath $basePath -ErrorAction SilentlyContinue
        if ($null -ne $policy) {
            $disableWebRtc = Get-PropertyValue -Object $policy -Name 'DisableWebRTC'
            if ($null -ne $disableWebRtc) {
                $managedWebRtcPolicyPresent = $true
                if ("$disableWebRtc" -match '^(?i:true|1)$') {
                    $restrictiveWebRtcPolicyDetected = $true
                }
            }
        }

        # Preferences may be nested under Preferences\ or Preferences subkeys.
        $prefRoot = Join-Path $basePath 'Preferences'
        if (Test-Path -LiteralPath $prefRoot) {
            $prefItem = Get-ItemProperty -LiteralPath $prefRoot -ErrorAction SilentlyContinue
            if ($null -ne $prefItem) {
                foreach ($prop in $prefItem.PSObject.Properties) {
                    if ($prop.Name -match '^(?:PSPath|PSParentPath|PSChildName|PSDrive|PSProvider)$') { continue }
                    if ($prop.Name -match '(?i)peerconnection|webrtc|DisableWebRTC') {
                        $managedWebRtcPolicyPresent = $true
                        if (Test-FirefoxRestrictivePreference -Name $prop.Name -Value $prop.Value) {
                            $restrictiveWebRtcPolicyDetected = $true
                        }
                    }
                }
            }
            Get-ChildItem -LiteralPath $prefRoot -ErrorAction SilentlyContinue | ForEach-Object {
                $name = $_.PSChildName
                $valueObj = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                $value = if ($null -ne $valueObj) {
                    @(
                        (Get-PropertyValue -Object $valueObj -Name 'Value'),
                        (Get-PropertyValue -Object $valueObj -Name '(default)'),
                        (Get-PropertyValue -Object $valueObj -Name $name)
                    ) | Where-Object { $null -ne $_ } | Select-Object -First 1
                } else { $null }
                if ($name -match '(?i)peerconnection|webrtc|DisableWebRTC') {
                    $managedWebRtcPolicyPresent = $true
                    if (Test-FirefoxRestrictivePreference -Name $name -Value $value) {
                        $restrictiveWebRtcPolicyDetected = $true
                    }
                }
            }
        }
    }

    # distribution/policies.json next to install (enterprise policy file)
    $policyJsonCandidates = @(
        (Join-Path $env:ProgramFiles 'Mozilla Firefox\distribution\policies.json'),
        (Join-Path ${env:ProgramFiles(x86)} 'Mozilla Firefox\distribution\policies.json'),
        (Join-Path $env:LOCALAPPDATA 'Mozilla Firefox\distribution\policies.json')
    )
    foreach ($jsonPath in $policyJsonCandidates) {
        if (-not $jsonPath -or -not (Test-Path -LiteralPath $jsonPath -PathType Leaf)) { continue }
        try {
            $raw = [System.IO.File]::ReadAllText($jsonPath)
            if ($raw -match '(?i)DisableWebRTC\s*"?\s*:\s*"?true') {
                $managedWebRtcPolicyPresent = $true
                $restrictiveWebRtcPolicyDetected = $true
            }
            if ($raw -match '(?i)media\.peerconnection') {
                $managedWebRtcPolicyPresent = $true
            }
            if ($raw -match '(?i)media\.peerconnection\.enabled["\s:]+false' -or
                $raw -match '(?i)media\.peerconnection\.ice\.(?:proxy_only|default_address_only|no_host)["\s:]+true') {
                $restrictiveWebRtcPolicyDetected = $true
            }
        }
        catch {
            # Best-effort only; leave flags unchanged on parse failures.
        }
    }

    # When Firefox is installed but no policy evidence exists, report false (not null)
    # so the schema stays boolean-compatible with Chrome/Edge audits.
    return [pscustomobject][ordered]@{
        Installed = $installed
        ManagedWebRtcPolicyPresent = $managedWebRtcPolicyPresent
        RestrictiveWebRtcPolicyDetected = if ($installed) { $restrictiveWebRtcPolicyDetected } else { $null }
    }
}

function Get-DnsUpstreamAudit {
    param([AllowEmptyString()][string]$DnsConfig)

    $upstreams = @()
    $uriMatches = [regex]::Matches($DnsConfig, "(?im)(?<scheme>https|tls|quic|h3)://(?<host>[^/\s#'`"]+)")
    foreach ($uriMatch in $uriMatches) {
        $upstreams += [pscustomobject][ordered]@{
            Scheme = $uriMatch.Groups['scheme'].Value.ToLowerInvariant()
        }
    }
    return @($upstreams | Sort-Object Scheme -Unique)
}

function Find-ByteSequence {
    param(
        [Parameter(Mandatory)][byte[]]$Data,
        [Parameter(Mandatory)][byte[]]$Needle,
        [int]$Start = 0
    )

    for ($index = $Start; $index -le $Data.Length - $Needle.Length; $index++) {
        $found = $true
        for ($offset = 0; $offset -lt $Needle.Length; $offset++) {
            if ($Data[$index + $offset] -ne $Needle[$offset]) {
                $found = $false
                break
            }
        }
        if ($found) {
            return $index
        }
    }
    return -1
}

function ConvertFrom-HttpChunkedBody {
    param([Parameter(Mandatory)][byte[]]$Body)

    $crlf = [byte[]](13,10)
    $position = 0
    $output = [System.IO.MemoryStream]::new()
    try {
        while ($true) {
            $lineEnd = Find-ByteSequence -Data $Body -Needle $crlf -Start $position
            if ($lineEnd -lt 0) { throw 'Invalid chunk-size line.' }
            $sizeText = [Text.Encoding]::ASCII.GetString($Body, $position, $lineEnd - $position).Split(';')[0]
            $size = 0
            if (-not [int]::TryParse($sizeText, [Globalization.NumberStyles]::HexNumber, [Globalization.CultureInfo]::InvariantCulture, [ref]$size)) {
                throw 'Invalid chunk size.'
            }
            $position = $lineEnd + 2
            if ($size -eq 0) { break }
            if ($position + $size + 2 -gt $Body.Length) { throw 'Chunk exceeds response body.' }
            $output.Write($Body, $position, $size)
            $position += $size
            if ($Body[$position] -ne 13 -or $Body[$position + 1] -ne 10) { throw 'Missing chunk terminator.' }
            $position += 2
        }
        return $output.ToArray()
    }
    finally {
        $output.Dispose()
    }
}

function Get-MihomoNamedPipeProxies {
    param(
        [Parameter(Mandatory)][string]$PipePath,
        [AllowEmptyString()][string]$Secret
    )

    $pipeName = $PipePath -replace '^\\\\\.\\pipe\\', ''
    if (-not $pipeName -or $pipeName -match '[\\/]') { throw 'Unsupported named-pipe path.' }
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
    $memory = [System.IO.MemoryStream]::new()
    try {
        $pipe.Connect(3000)
        $authorization = if ($Secret) { "Authorization: Bearer $Secret`r`n" } else { '' }
        $request = [Text.Encoding]::ASCII.GetBytes("GET /proxies HTTP/1.1`r`nHost: localhost`r`n${authorization}Connection: close`r`n`r`n")
        $pipe.Write($request, 0, $request.Length)
        $pipe.Flush()

        $buffer = New-Object byte[] 8192
        while ($true) {
            $readTask = $pipe.ReadAsync($buffer, 0, $buffer.Length)
            if (-not $readTask.Wait(5000)) { throw 'Named-pipe response timed out.' }
            $count = $readTask.Result
            if ($count -eq 0) { break }
            $memory.Write($buffer, 0, $count)
            if ($memory.Length -gt 8MB) { throw 'Named-pipe response exceeded 8 MB.' }
        }

        $response = $memory.ToArray()
        $headerEnd = Find-ByteSequence -Data $response -Needle ([byte[]](13,10,13,10))
        if ($headerEnd -lt 0) { throw 'Invalid named-pipe HTTP response.' }
        $headers = [Text.Encoding]::ASCII.GetString($response, 0, $headerEnd)
        if ($headers -notmatch '^HTTP/\S+\s+200\b') { throw 'Mihomo named-pipe request failed.' }
        $body = New-Object byte[] ($response.Length - $headerEnd - 4)
        [Array]::Copy($response, $headerEnd + 4, $body, 0, $body.Length)
        if ($headers -match '(?im)^Transfer-Encoding:\s*chunked') {
            $body = ConvertFrom-HttpChunkedBody -Body $body
        }
        $json = [Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json
        return Get-PropertyValue -Object $json -Name 'proxies'
    }
    finally {
        $memory.Dispose()
        $pipe.Dispose()
    }
}

function Get-MihomoControllerSettings {
    param(
        [AllowEmptyString()][string]$RuntimeConfig,
        [AllowEmptyString()][string]$ControllerConfig
    )

    # The generated runtime config is authoritative when it supplies a value;
    # the app config is retained as a fallback for settings not copied there.
    $settings = [ordered]@{}
    foreach ($key in @('external[-_]controller', 'external[-_]controller[-_]pipe', 'secret')) {
        $value = Get-YamlScalar -Text $RuntimeConfig -KeyPattern $key
        if (-not $value) {
            $value = Get-YamlScalar -Text $ControllerConfig -KeyPattern $key
        }
        $settings[$key] = $value
    }
    return [pscustomobject]@{
        Controller = $settings['external[-_]controller']
        Pipe = $settings['external[-_]controller[-_]pipe']
        Secret = $settings['secret']
    }
}

function Get-MihomoPolicyAudit {
    param(
        [AllowEmptyString()][string]$RuntimeConfig,
        [AllowEmptyString()][string]$ControllerConfig,
        [Parameter(Mandatory)][string]$GroupPattern
    )

    $staticGroups = @()
    $staticGroupNames = @()
    $staticGroupReferences = @{}
    $groupMatches = [regex]::Matches($RuntimeConfig, '(?ms)^[ \t]*-[ \t]*name:\s*(?<name>[^\r\n#]+)\r?\n[ \t]+type:\s*(?<type>[^\r\n#]+)')
    foreach ($groupMatch in $groupMatches) {
        $groupName = $groupMatch.Groups['name'].Value.Trim().Trim("'`"")
        if ($groupName -notmatch $GroupPattern) {
            continue
        }
        $referencedByRule = $RuntimeConfig -match "(?im),\s*$([regex]::Escape($groupName))\s*$"
        $staticGroupNames += $groupName
        $staticGroupReferences[$groupName] = $referencedByRule
        $staticGroups += [pscustomobject][ordered]@{
            Type = $groupMatch.Groups['type'].Value.Trim().Trim("'`"")
            ReferencedByRule = $referencedByRule
        }
    }

    $controllerSettings = Get-MihomoControllerSettings -RuntimeConfig $RuntimeConfig -ControllerConfig $ControllerConfig
    $controllerValue = $controllerSettings.Controller
    $controllerPipe = $controllerSettings.Pipe
    $secret = $controllerSettings.Secret
    $controllerReachable = $false
    $controllerSkipped = $false
    $controllerTransport = $null
    $runtimeGroups = @()
    $proxyObjects = $null

    if ($controllerValue) {
        try {
            $controllerUri = if ($controllerValue -match '^https?://') { [uri]$controllerValue } else { [uri]("http://$controllerValue") }
            $controllerHost = $controllerUri.Host.Trim('[', ']')
            if ($controllerHost -notin @('127.0.0.1','localhost','0.0.0.0','::1')) {
                $controllerSkipped = $true
            }
            else {
                $hostName = if ($controllerHost -eq '0.0.0.0') { '127.0.0.1' } else { $controllerHost }
                $uriHost = if ($hostName -match ':') { "[$hostName]" } else { $hostName }
                $baseUri = "http://${uriHost}:$($controllerUri.Port)"
                $headers = @{}
                if ($secret) {
                    $headers.Authorization = "Bearer $secret"
                }
                $response = Invoke-RestMethod -Uri "$baseUri/proxies" -Headers $headers -Method Get -TimeoutSec 3 -ErrorAction Stop
                $proxyObjects = Get-PropertyValue -Object $response -Name 'proxies'
                $controllerReachable = $null -ne $proxyObjects
                if ($controllerReachable) { $controllerTransport = 'Http' }
            }
        }
        catch {
            $controllerReachable = $false
        }
    }

    if (-not $controllerReachable -and $controllerPipe) {
        try {
            $proxyObjects = Get-MihomoNamedPipeProxies -PipePath $controllerPipe -Secret $secret
            $controllerReachable = $null -ne $proxyObjects
            if ($controllerReachable) { $controllerTransport = 'NamedPipe' }
        }
        catch {
            $controllerReachable = $false
        }
    }

    if ($controllerReachable) {
        $groupNames = @($staticGroupNames)
        $groupNames += @($proxyObjects.PSObject.Properties.Name | Where-Object { $_ -match $GroupPattern })
        foreach ($groupName in @($groupNames | Sort-Object -Unique)) {
            $chain = @()
            $seen = @{}
            $currentName = $groupName
            $usesAutomaticSelection = $false
            while ($currentName -and -not $seen.ContainsKey($currentName) -and $chain.Count -lt 12) {
                $seen[$currentName] = $true
                $proxy = Get-PropertyValue -Object $proxyObjects -Name $currentName
                if ($null -eq $proxy) {
                    break
                }
                $type = [string](Get-PropertyValue -Object $proxy -Name 'type')
                $next = [string](Get-PropertyValue -Object $proxy -Name 'now')
                if ($type -match '(?i)URLTest|Fallback|LoadBalance|Smart') {
                    $usesAutomaticSelection = $true
                }
                $chain += [pscustomobject][ordered]@{ Type = $type }
                $currentName = $next
            }
            $runtimeGroups += [pscustomobject][ordered]@{
                ReferencedByRule = if ($staticGroupReferences.ContainsKey($groupName)) { $staticGroupReferences[$groupName] } else { $null }
                Resolved = $chain.Count -gt 0
                UsesAutomaticSelection = $usesAutomaticSelection
                SelectionTypes = @($chain | ForEach-Object Type | Sort-Object -Unique)
            }
        }
    }

    $selectionAssessment = if (-not $controllerReachable -and $staticGroups.Count -eq 0) {
        'MatchedGroupNotFound'
    }
    elseif (-not $controllerReachable) {
        'ManualCheckRequired'
    }
    elseif ($runtimeGroups.Count -eq 0) {
        'MatchedGroupNotFound'
    }
    elseif (@($runtimeGroups | Where-Object { -not $_.Resolved }).Count -gt 0) {
        'ManualCheckRequired'
    }
    elseif (@($runtimeGroups | Where-Object UsesAutomaticSelection).Count -gt 0) {
        'AutomaticSelectionDetected'
    }
    else {
        'FixedSelection'
    }

    return [pscustomobject][ordered]@{
        StaticGroups = $staticGroups
        LocalControllerConfigured = [bool]$controllerValue
        NamedPipeControllerConfigured = [bool]$controllerPipe
        LocalControllerReachable = $controllerReachable
        NonLocalControllerSkipped = $controllerSkipped
        ControllerTransport = $controllerTransport
        SelectionAssessment = $selectionAssessment
        RuntimeGroups = $runtimeGroups
    }
}

if ($SelfTest) {
    $sample = @'
mode: rule
allow-lan: false
mixed-port: 7897
tun:
  strict-route: true
'@
    if ((Get-YamlScalar -Text $sample -KeyPattern 'mode') -ne 'rule') { throw 'Scalar parsing failed.' }
    if ((ConvertTo-NullableBoolean (Get-YamlScalar -Text $sample -KeyPattern 'allow-lan')) -ne $false) { throw 'Boolean parsing failed.' }
    if ((Get-YamlScalar -Text $sample -KeyPattern 'mixed[-_]port') -ne '7897') { throw 'Hyphenated key parsing failed.' }
    $sampleTun = Get-YamlBlock -Text $sample -Section 'tun'
    if ((ConvertTo-NullableBoolean (Get-YamlScalar -Text $sampleTun -KeyPattern 'strict-route')) -ne $true) { throw 'Section parsing failed.' }
    $runtimeFirst = "mode: rule" + [Environment]::NewLine + "mode: global"
    if ((Get-YamlScalar -Text $runtimeFirst -KeyPattern 'mode') -ne 'rule') { throw 'Runtime config precedence failed.' }
    if (-not (Test-ProxyServerLoopback -ProxyServer 'http=127.0.0.1:7897;https=[::1]:7897')) { throw 'Loopback proxy parsing failed.' }
    if (Test-ProxyServerLoopback -ProxyServer 'http=127.0.0.1:7897;https=proxy.example:443') { throw 'Remote proxy target was treated as loopback.' }
    if ((Get-DnsServerClass '127.0.0.1') -ne 'Loopback' -or (Get-DnsServerClass '198.19.2.3') -ne 'FakeIp' -or (Get-DnsServerClass '203.0.113.8') -ne 'Other') { throw 'DNS server classification failed.' }
    $dnsSample = 'nameserver: [https://dns.example/dns-query, tls://resolver.example]'
    if ((Get-DnsUpstreamAudit -DnsConfig $dnsSample).Count -ne 2) { throw 'DNS upstream parsing failed.' }
    if ('Hawaiian residential' -match $PolicyGroupPattern) { throw 'Policy-group pattern produced a false positive.' }
    if ('group AI service' -notmatch $PolicyGroupPattern) { throw 'Policy-group pattern missed an AI group.' }
    $controllerSettings = Get-MihomoControllerSettings -RuntimeConfig "external-controller: '[::1]:9090'`nsecret: runtime-secret" -ControllerConfig "external-controller-pipe: \\.\pipe\mihomo`nsecret: app-secret"
    if ($controllerSettings.Controller -ne '[::1]:9090' -or $controllerSettings.Pipe -ne '\\.\pipe\mihomo' -or $controllerSettings.Secret -ne 'runtime-secret') { throw 'Controller settings parsing failed.' }
    $fallbackSettings = Get-MihomoControllerSettings -RuntimeConfig '' -ControllerConfig "external-controller: 127.0.0.1:9090`nsecret: app-secret"
    if ($fallbackSettings.Controller -ne '127.0.0.1:9090' -or $fallbackSettings.Secret -ne 'app-secret') { throw 'App controller settings fallback failed.' }
    $controllerUri = [uri]("http://$($controllerSettings.Controller)")
    $selfTestUriHost = $controllerUri.Host.Trim('[', ']')
    if ($selfTestUriHost -match ':') { $selfTestUriHost = "[$selfTestUriHost]" }
    if ("http://${selfTestUriHost}:$($controllerUri.Port)" -notmatch '^http://\[[0-9a-f:]+\]:9090$') { throw 'IPv6 controller URI formatting failed.' }
    $selfTestEnv = 'CLAUDE_SHIELD_SELFTEST_ENV'
    $originalSelfTestEnv = [Environment]::GetEnvironmentVariable($selfTestEnv, 'Process')
    try {
        [Environment]::SetEnvironmentVariable($selfTestEnv, 'not-one', 'Process')
        $envRows = @(Get-EnvironmentStatusRows -Name $selfTestEnv)
        if ($envRows[0].Active -or $envRows[0].PSObject.Properties['Value']) { throw 'Privacy environment status leaked a value.' }
        [Environment]::SetEnvironmentVariable($selfTestEnv, '1', 'Process')
        if (-not (Get-EnvironmentStatusRows -Name $selfTestEnv | Select-Object -First 1).Active) { throw 'Privacy environment active parsing failed.' }
        [Environment]::SetEnvironmentVariable($selfTestEnv, 'file:C:\private\trace', 'Process')
        $contentRows = @(Get-EnvironmentStatusRows -Name $selfTestEnv -ContentValue)
        if (-not $contentRows[0].Active -or ($contentRows | ConvertTo-Json) -match 'private|trace') { throw 'Content logging status leaked a value.' }
    }
    finally {
        [Environment]::SetEnvironmentVariable($selfTestEnv, $originalSelfTestEnv, 'Process')
    }
    $unicodeName = ([char]0x65E5).ToString() + ([char]0x672C)
    $chunkText = '{"name":"' + $unicodeName + '"}'
    $chunkPayload = [Text.Encoding]::UTF8.GetBytes($chunkText)
    $chunkStream = [System.IO.MemoryStream]::new()
    try {
        $chunkPrefix = [Text.Encoding]::ASCII.GetBytes($chunkPayload.Length.ToString('X') + "`r`n")
        $chunkSuffix = [Text.Encoding]::ASCII.GetBytes("`r`n0`r`n`r`n")
        $chunkStream.Write($chunkPrefix, 0, $chunkPrefix.Length)
        $chunkStream.Write($chunkPayload, 0, $chunkPayload.Length)
        $chunkStream.Write($chunkSuffix, 0, $chunkSuffix.Length)
        $decodedChunk = ConvertFrom-HttpChunkedBody -Body $chunkStream.ToArray()
        if ([Text.Encoding]::UTF8.GetString($decodedChunk) -ne $chunkText) { throw 'Chunked UTF-8 decoding failed.' }
    }
    finally {
        $chunkStream.Dispose()
    }
    'Self-test passed.'
    return
}

$appConfigPath = Join-Path $ConfigDir 'config.yaml'
$runtimeConfigPath = Join-Path $ConfigDir 'clash-verge.yaml'
$appConfig = Read-TextIfPresent -Path $appConfigPath
$runtimeConfig = Read-TextIfPresent -Path $runtimeConfigPath
$combinedConfig = $runtimeConfig + [Environment]::NewLine + $appConfig
$tunConfig = Get-YamlBlock -Text $combinedConfig -Section 'tun'
$dnsConfig = Get-YamlBlock -Text $runtimeConfig -Section 'dns'
$dnsUpstreams = Get-DnsUpstreamAudit -DnsConfig $dnsConfig

$mixedPortText = Get-YamlScalar -Text $combinedConfig -KeyPattern 'mixed[-_]port'
$mixedPort = 7897
if ($mixedPortText -match '^\d{1,5}$') {
    $mixedPort = [int]$mixedPortText
}

$portListening = $false
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $portListening = $null -ne (Get-NetTCPConnection -State Listen -LocalPort $mixedPort -ErrorAction SilentlyContinue | Select-Object -First 1)
}

$internetSettings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$proxyEnabled = $false
$proxyPointsToLoopback = $false
if ($null -ne $internetSettings) {
    $proxyEnabledProperty = $internetSettings.PSObject.Properties['ProxyEnable']
    $proxyServerProperty = $internetSettings.PSObject.Properties['ProxyServer']
    if ($null -ne $proxyEnabledProperty) {
        $proxyEnabled = [bool]$proxyEnabledProperty.Value
    }
    $proxyServer = ''
    if ($null -ne $proxyServerProperty) {
        $proxyServer = [string]$proxyServerProperty.Value
    }
    $proxyPointsToLoopback = Test-ProxyServerLoopback -ProxyServer $proxyServer
}

$teredo = [ordered]@{ Available = $false; Type = $null; Disabled = $null }
if (Get-Command Get-NetTeredoConfiguration -ErrorAction SilentlyContinue) {
    $teredoConfig = Get-NetTeredoConfiguration -ErrorAction SilentlyContinue
    if ($null -ne $teredoConfig) {
        $teredo.Available = $true
        $teredo.Type = [string]$teredoConfig.Type
        $teredo.Disabled = $teredo.Type -match '(?i)disabled'
    }
}

$isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$serviceModeActive = $false
try {
    $serviceModeActive = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match '(?i)clash|mihomo|verge' -or $_.DisplayName -match '(?i)clash|mihomo|verge' -or $_.PathName -match '(?i)clash|mihomo|verge'
    } | Where-Object State -eq 'Running').Count -gt 0
}
catch {
    $serviceModeActive = $false
}

$userLanguages = @()
if (Get-Command Get-WinUserLanguageList -ErrorAction SilentlyContinue) {
    $languageList = Get-WinUserLanguageList
    foreach ($language in $languageList) {
        $userLanguages += [string]$language.LanguageTag
    }
}
$systemLocale = if (Get-Command Get-WinSystemLocale -ErrorAction SilentlyContinue) { (Get-WinSystemLocale).Name } else { $null }
$uiLanguageOverride = if (Get-Command Get-WinUILanguageOverride -ErrorAction SilentlyContinue) { [string](Get-WinUILanguageOverride) } else { $null }

$ipv6Bindings = @()
$adapterClassifications = @{}
if ((Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) -and (Get-Command Get-NetAdapterBinding -ErrorAction SilentlyContinue)) {
    $activeAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up'
    foreach ($adapter in $activeAdapters) {
        $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        if ($null -ne $binding) {
            $description = [string]$adapter.InterfaceDescription
            $hardwareInterface = Get-PropertyValue -Object $adapter -Name 'HardwareInterface'
            $classification = if ("$($adapter.Name) $description" -match '(?i)mihomo|clash|wintun|wireguard|tap|vpn') {
                'TunnelOrVpn'
            }
            elseif ($hardwareInterface -eq $true) {
                'Physical'
            }
            else {
                'VirtualOrOther'
            }
            $adapterClassifications[[string]$adapter.Name] = $classification
            $ipv6Bindings += [pscustomobject][ordered]@{
                Classification = $classification
                Enabled = [bool]$binding.Enabled
                CandidateForIPv6Disable = ($classification -eq 'Physical' -and [bool]$binding.Enabled)
            }
        }
    }
}

$localDns = @()
if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
    $dnsRows = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 }
    foreach ($row in $dnsRows) {
        $classification = if ($adapterClassifications.ContainsKey([string]$row.InterfaceAlias)) { $adapterClassifications[[string]$row.InterfaceAlias] } else { 'Unknown' }
        $localDns += [ordered]@{
            Classification = $classification
            Family = [string]$row.AddressFamily
            ServerClasses = @($row.ServerAddresses | ForEach-Object { Get-DnsServerClass ([string]$_) } | Sort-Object -Unique)
        }
    }
}

$proxyEnvironmentVariables = @()
foreach ($scope in @('Process','User','Machine')) {
    foreach ($variableName in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')) {
        $value = [Environment]::GetEnvironmentVariable($variableName, $scope)
        if ($value) {
            $proxyEnvironmentVariables += [pscustomobject][ordered]@{ Scope = $scope; Name = $variableName; Present = $true }
        }
    }
}

$claudeDisableTelemetry = @(Get-EnvironmentStatusRows -Name 'DISABLE_TELEMETRY')
$claudeDisableErrorReporting = @(Get-EnvironmentStatusRows -Name 'DISABLE_ERROR_REPORTING')
$claudeDisableNonessentialTraffic = @(Get-EnvironmentStatusRows -Name 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC')
$claudeSkipPromptHistory = @(Get-EnvironmentStatusRows -Name 'CLAUDE_CODE_SKIP_PROMPT_HISTORY')
$claudeSubprocessEnvScrub = @(Get-EnvironmentStatusRows -Name 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB')
$otelLogUserPrompts = @(Get-EnvironmentStatusRows -Name 'OTEL_LOG_USER_PROMPTS')
$otelLogToolContent = @(Get-EnvironmentStatusRows -Name 'OTEL_LOG_TOOL_CONTENT')
$otelLogToolDetails = @(Get-EnvironmentStatusRows -Name 'OTEL_LOG_TOOL_DETAILS')
$otelLogRawApiBodies = @(Get-EnvironmentStatusRows -Name 'OTEL_LOG_RAW_API_BODIES' -ContentValue)

$otherProxyClientCount = 0
$clientNames = @('sing-box','v2rayN','v2ray','xray','nekobox')
foreach ($cn in $clientNames) {
    $proc = Get-Process -Name $cn -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $proc) {
        $otherProxyClientCount++
    }
}

$claudeAudit = [ordered]@{
    DisableTelemetryVars = $claudeDisableTelemetry
    DisableTelemetryActive = [bool]($claudeDisableTelemetry[0].Active)
    DisableErrorReportingVars = $claudeDisableErrorReporting
    DisableErrorReportingActive = [bool]($claudeDisableErrorReporting[0].Active)
    DisableNonessentialTrafficVars = $claudeDisableNonessentialTraffic
    DisableNonessentialTrafficActive = [bool]($claudeDisableNonessentialTraffic[0].Active)
    SkipPromptHistoryVars = $claudeSkipPromptHistory
    SkipPromptHistoryActive = [bool]($claudeSkipPromptHistory[0].Active)
    SubprocessEnvScrubVars = $claudeSubprocessEnvScrub
    SubprocessEnvScrubActive = [bool]($claudeSubprocessEnvScrub[0].Active)
    OtelLogUserPromptsVars = $otelLogUserPrompts
    OtelLogUserPromptsActive = [bool]($otelLogUserPrompts[0].Active)
    OtelLogToolContentVars = $otelLogToolContent
    OtelLogToolContentActive = [bool]($otelLogToolContent[0].Active)
    OtelLogToolDetailsVars = $otelLogToolDetails
    OtelLogToolDetailsActive = [bool]($otelLogToolDetails[0].Active)
    OtelLogRawApiBodiesVars = $otelLogRawApiBodies
    OtelLogRawApiBodiesActive = [bool]($otelLogRawApiBodies[0].Active)
}

$dnsHijackAny53 = $combinedConfig -match "(?im)^\s*-\s*['`"]?any:53['`"]?\s*(?:#.*)?$"
$processRunning = $null -ne (Get-Process -Name 'verge-mihomo','mihomo','clash-meta','clash' -ErrorAction SilentlyContinue | Select-Object -First 1)
$chromeAudit = Get-BrowserWebRtcAudit -UserDataPath (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') -PolicyRegistryPath 'Google\Chrome' -ExecutablePaths @(
    (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe'),
    (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe')
)
$edgeAudit = Get-BrowserWebRtcAudit -UserDataPath (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') -PolicyRegistryPath 'Microsoft\Edge' -ExecutablePaths @(
    (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe')
)
$firefoxAudit = Get-FirefoxWebRtcAudit
$policyAudit = Get-MihomoPolicyAudit -RuntimeConfig $runtimeConfig -ControllerConfig $appConfig -GroupPattern $PolicyGroupPattern

$result = [ordered]@{
    SchemaVersion = 7
    CollectedAt = (Get-Date).ToUniversalTime().ToString('o')
    System = [ordered]@{
        IsAdministrator = $isAdministrator
        MihomoProcessRunning = $processRunning
        OtherProxyClientCount = $otherProxyClientCount
        ServiceModeActive = $serviceModeActive
        MixedPort = $mixedPort
        MixedPortListening = $portListening
        SystemProxy = [ordered]@{
            Enabled = $proxyEnabled
            PointsToLoopback = $proxyPointsToLoopback
        }
        TimeZone = (Get-TimeZone).Id
        Culture = (Get-Culture).Name
        UICulture = (Get-UICulture).Name
        UILanguageOverride = $uiLanguageOverride
        UserLanguageList = $userLanguages
        SystemLocale = $systemLocale
        Teredo = $teredo
        ActiveAdapterIPv6Bindings = $ipv6Bindings
        LocalDnsServers = $localDns
        ProxyEnvironmentVariables = $proxyEnvironmentVariables
    }
    Mihomo = [ordered]@{
        AppConfigPresent = [bool]$appConfig
        RuntimeConfigPresent = [bool]$runtimeConfig
        Mode = Get-YamlScalar -Text $combinedConfig -KeyPattern 'mode'
        AllowLan = ConvertTo-NullableBoolean (Get-YamlScalar -Text $combinedConfig -KeyPattern 'allow[-_]lan')
        IPv6 = ConvertTo-NullableBoolean (Get-YamlScalar -Text $combinedConfig -KeyPattern 'ipv6')
        TunEnabled = ConvertTo-NullableBoolean (Get-YamlScalar -Text $tunConfig -KeyPattern 'enable')
        StrictRoute = ConvertTo-NullableBoolean (Get-YamlScalar -Text $tunConfig -KeyPattern 'strict[-_]route')
        TunStack = Get-YamlScalar -Text $tunConfig -KeyPattern 'stack'
        DnsEnabled = ConvertTo-NullableBoolean (Get-YamlScalar -Text $dnsConfig -KeyPattern 'enable')
        DnsRespectRules = ConvertTo-NullableBoolean (Get-YamlScalar -Text $dnsConfig -KeyPattern 'respect[-_]rules')
        DnsMode = Get-YamlScalar -Text $dnsConfig -KeyPattern 'enhanced[-_]mode'
        DnsIPv6 = ConvertTo-NullableBoolean (Get-YamlScalar -Text $dnsConfig -KeyPattern 'ipv6')
        DnsHijackAny53 = $dnsHijackAny53
        EncryptedDnsUpstreams = $dnsUpstreams
        PolicyGroups = $policyAudit
    }
    Browsers = [ordered]@{
        Chrome = $chromeAudit
        Edge = $edgeAudit
        Firefox = $firefoxAudit
    }
    ClaudeCode = $claudeAudit
}

$result | ConvertTo-Json -Depth 10
