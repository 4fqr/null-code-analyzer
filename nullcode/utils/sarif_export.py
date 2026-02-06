"""
SARIF (Static Analysis Results Interchange Format) export
Standard format for security tools
"""

import json
from typing import List
from datetime import datetime
from ..core import VulnerabilityMatch


class SARIFExporter:
    """Export scan results to SARIF format"""

    SARIF_VERSION = "2.1.0"
    TOOL_NAME = "Null-Code-Analyzer"
    TOOL_VERSION = "1.0.0"

    def export(self, vulnerabilities: List[VulnerabilityMatch], output_path: str) -> None:
        """
        Export vulnerabilities to SARIF format
        
        Args:
            vulnerabilities: List of vulnerabilities
            output_path: Output file path
        """
        sarif = self._build_sarif(vulnerabilities)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)

    def _build_sarif(self, vulnerabilities: List[VulnerabilityMatch]) -> dict:
        """Build SARIF structure"""
        return {
            "version": self.SARIF_VERSION,
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": "https://github.com/nullcode/analyzer",
                            "rules": self._build_rules(vulnerabilities)
                        }
                    },
                    "results": self._build_results(vulnerabilities),
                    "properties": {
                        "scanTimestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            ]
        }

    def _build_rules(self, vulnerabilities: List[VulnerabilityMatch]) -> List[dict]:
        """Build SARIF rules from unique vulnerability types"""
        unique_types = {}
        
        for vuln in vulnerabilities:
            if vuln.cwe_id not in unique_types:
                unique_types[vuln.cwe_id] = {
                    "id": vuln.cwe_id,
                    "name": vuln.type,
                    "shortDescription": {
                        "text": vuln.description
                    },
                    "fullDescription": {
                        "text": vuln.description
                    },
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html",
                    "properties": {
                        "security-severity": self._map_severity_to_score(vuln.severity)
                    }
                }
        
        return list(unique_types.values())

    def _build_results(self, vulnerabilities: List[VulnerabilityMatch]) -> List[dict]:
        """Build SARIF results from vulnerabilities"""
        results = []
        
        for vuln in vulnerabilities:
            results.append({
                "ruleId": vuln.cwe_id,
                "level": self._map_severity(vuln.severity),
                "message": {
                    "text": vuln.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "file:///" + str(vuln.code_snippet)  # Would need file path
                            },
                            "region": {
                                "startLine": vuln.line_number,
                                "snippet": {
                                    "text": vuln.code_snippet
                                }
                            }
                        }
                    }
                ],
                "properties": {
                    "confidence": vuln.confidence,
                    "severity": vuln.severity
                }
            })
        
        return results

    def _map_severity(self, severity: str) -> str:
        """Map internal severity to SARIF level"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note"
        }
        return mapping.get(severity, "warning")

    def _map_severity_to_score(self, severity: str) -> str:
        """Map severity to CVSS-like score"""
        mapping = {
            "critical": "9.0",
            "high": "7.0",
            "medium": "5.0",
            "low": "3.0"
        }
        return mapping.get(severity, "5.0")
