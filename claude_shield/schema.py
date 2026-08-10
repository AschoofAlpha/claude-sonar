from typing import Dict, Any

SUPPORTED_MAJOR_VERSION = 1

class SchemaValidationError(Exception):
    pass

def validate_report(report_dict: Dict[str, Any]):
    if not isinstance(report_dict, dict):
        raise SchemaValidationError("Report must be an object")
    schema_version = report_dict.get('schema_version')
    if not isinstance(schema_version, str) or not schema_version:
        raise SchemaValidationError("Missing schema_version")
    parts = schema_version.split('.')
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise SchemaValidationError(f"Invalid schema_version format: {schema_version}")
    major = int(parts[0])
        
    if major > SUPPORTED_MAJOR_VERSION:
        raise SchemaValidationError(f"Unsupported major schema version: {major}. Max supported is {SUPPORTED_MAJOR_VERSION}")

    if 'findings' in report_dict and 'checks' not in report_dict:
        report_dict['checks'] = report_dict.pop('findings')
    elif 'findings' in report_dict and 'checks' in report_dict:
        raise SchemaValidationError("Cannot contain both 'findings' and 'checks'.")
        
    for k in report_dict.keys():
        if k not in ('schema_version', 'tool_version', 'generated_at', 'platform', 'privacy', 'checks', 'summary', 'errors'):
            raise SchemaValidationError(f"Unknown root field: {k}")

    # Validate allowed enums for checks
    checks = report_dict.get('checks', [])
    if not isinstance(checks, list):
        raise SchemaValidationError("checks must be a list")
    for check in checks:
        if not isinstance(check, dict):
            raise SchemaValidationError("Each check must be an object")
        status = check.get('status')
        if status not in ('pass', 'fail', 'warning', 'unknown', 'skipped', 'error'):
            raise SchemaValidationError(f"Invalid status '{status}' in check {check.get('id')}")
            
        if status == 'skipped' and not check.get('explanation'):
            raise SchemaValidationError(f"Check {check.get('id')} is skipped but missing explanation")

        severity = check.get('severity')
        if severity not in ('critical', 'high', 'medium', 'low', 'info'):
            raise SchemaValidationError(f"Invalid severity '{severity}' in check {check.get('id')}")

        confidence = check.get('confidence')
        if confidence not in ('confirmed', 'probable', 'possible', 'unknown'):
            raise SchemaValidationError(f"Invalid confidence '{confidence}' in check {check.get('id')}")
            
    return True
