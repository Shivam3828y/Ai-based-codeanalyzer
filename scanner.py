import re


SUSPICIOUS_PATTERNS = {
    "Dynamic Code Execution": [
        r"\beval\s*\(",
        r"\bexec\s*\(",
    ],

    "System Command Execution": [
        r"\bos\.system\s*\(",
        r"\bsubprocess\.",
        r"\bos\.popen\s*\(",
    ],

    "External Code Loading": [
        r"\brequire\s*\(",
        r"\bimportlib\b",
        r"\b__import__\s*\(",
    ],

    "Network Activity": [
        r"\brequests\.(get|post|put|delete)\s*\(",
        r"\burllib\.",
        r"\bsocket\.",
    ],

    "Encoded / Obfuscated Content": [
        r"\bbase64\b",
        r"\bb64decode\s*\(",
        r"\\x[0-9a-fA-F]{2}",
    ],

    "Credential / Secret Access": [
        r"\bpassword\b",
        r"\bpasswd\b",
        r"\bapi[_-]?key\b",
        r"\bsecret[_-]?key\b",
        r"\bauthorization\b",
    ],
}


def scan_code(source_code):
    """
    Analyze source code without executing it.
    """

    findings = []

    lines = source_code.splitlines()

    for line_number, line in enumerate(lines, start=1):

        for category, patterns in SUSPICIOUS_PATTERNS.items():

            for pattern in patterns:

                if re.search(pattern, line, re.IGNORECASE):

                    findings.append({
                        "category": category,
                        "line": line_number,
                        "code": line.strip(),
                    })

                    # Don't report the same category
                    # multiple times for the same line.
                    break

    return findings


def calculate_indicators(findings):
    """
    Convert scanner findings into fuzzy input values.
    """

    indicators = {
        "obfuscation": 0,
        "external_loading": 0,
        "dynamic_execution": 0,
        "suspicious_operations": 0,
    }

    for finding in findings:

        category = finding["category"]

        if category == "Encoded / Obfuscated Content":
            indicators["obfuscation"] += 35

        elif category == "External Code Loading":
            indicators["external_loading"] += 40

        elif category == "Dynamic Code Execution":
            indicators["dynamic_execution"] += 45

        elif category in [
            "System Command Execution",
            "Network Activity",
            "Credential / Secret Access"
        ]:
            indicators["suspicious_operations"] += 25

    # Keep values between 0 and 100.
    for key in indicators:
        indicators[key] = min(indicators[key], 100)

    return indicators