import json

from aeppo import __version__
from aeppo.scanner import RULES


_SARIF_LEVELS = {"high": "error", "medium": "warning", "low": "note"}
# GitHub code scanning reads ``security-severity`` (0.0-10.0) to rank security alerts.
_SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}


def format_text(findings):
    if not findings:
        return "No findings."
    lines = []
    for finding in findings:
        lines.append("{}:{}: [{}|{}] {} ({}, confidence={})".format(finding.path, finding.line, finding.rule_id, finding.severity, finding.message, finding.category, finding.confidence))
        lines.append("  Recommendation: {}".format(finding.recommendation))
    return "\n".join(lines)


def format_json(findings):
    return json.dumps([finding.__dict__ for finding in findings], indent=2)


def format_sarif(findings, uri_for=lambda finding: finding.path):
    """Render findings as SARIF 2.1.0; ``uri_for`` maps a finding to its artifact URI."""
    rule_ids = sorted(RULES)
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = []
    for rule_id in rule_ids:
        rule = RULES[rule_id]
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule.message},
                "help": {"text": rule.recommendation},
                "defaultConfiguration": {"level": _SARIF_LEVELS[rule.severity]},
                "properties": {
                    "tags": ["security", rule.category],
                    "precision": rule.confidence,
                    "security-severity": _SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": _SARIF_LEVELS.get(finding.severity, "warning"),
                "message": {"text": "{} {}".format(finding.message, finding.recommendation)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri_for(finding)},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
                "partialFingerprints": {"aeppo/v1": finding.fingerprint},
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aeppo",
                        "version": __version__,
                        "informationUri": "https://github.com/emanuellzoe/aeppo",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)
