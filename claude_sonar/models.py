from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class Evidence:
    type: str
    description: str
    data: Any

@dataclass
class Recommendation:
    action_type: str
    description: str
    requires_admin: bool

@dataclass
class AuditCheck:
    id: str
    title: str
    category: str
    status: str
    severity: str
    confidence: str
    evidence: List[Evidence] = field(default_factory=list)
    explanation: str = ""
    recommendation: str = ""
    requires_admin: bool = False
    remediation_available: bool = False
    rollback_available: bool = False

@dataclass
class PlatformInfo:
    os: str
    version: str
    hostname: str

@dataclass
class PrivacyMetadata:
    redaction_enabled: bool
    salt_used: bool

@dataclass
class ToolError:
    code: str
    message: str

@dataclass
class ArtifactReference:
    type: str
    path: str

@dataclass
class AuditReport:
    schema_version: str
    tool_version: str
    generated_at: str
    platform: PlatformInfo
    privacy: PrivacyMetadata
    checks: List[AuditCheck]
    summary: Dict[str, int]
    errors: List[ToolError] = field(default_factory=list)

    @property
    def findings(self):
        import warnings
        warnings.warn("The 'findings' attribute is deprecated and will be removed in schema version 2.0. Use 'checks' instead.", DeprecationWarning, stacklevel=2)
        return self.checks

def to_dict(obj):
    if hasattr(obj, "__dataclass_fields__"):
        return {k: to_dict(getattr(obj, k)) for k in obj.__dataclass_fields__}
    elif isinstance(obj, list):
        return [to_dict(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    else:
        return obj
