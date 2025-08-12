#!/usr/bin/env python3
import os, json
from backend.parsers.python_parser import parse_python_code
from backend.detectors.sql_injection import SQLInjectionDetector
from backend.reporting.vulnerability_reporter import VulnerabilityReporter

def main():
    vulns = []
    for root, _, files in os.walk("backend"):
        for f in files:
            if f.endswith(".py"):
                code = open(os.path.join(root, f), encoding="utf-8").read()
                vulns.extend(SQLInjectionDetector().analyze_sql_injection(code))
    report = VulnerabilityReporter().generate_report(
        vulns, {"repository": os.getenv("GITHUB_REPOSITORY", "local")}
    )
    with open("audit_report.json", "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
    print("Audit report generated: audit_report.json")

if __name__ == "__main__":
    main()
