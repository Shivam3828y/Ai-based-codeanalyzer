import re


# Suspicious patterns for the MVP.
# These are indicators, NOT proof of malware.
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
    Perform static analysis on source code.

    The code is NEVER executed.
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

                    break

    return findings







if __name__ == "__main__":

    test_code = """
import requests
import base64

data = base64.b64decode("SGVsbG8=")

eval(data)

requests.get("https://example.com")

os.system("whoami")
"""

    results = scan_code(test_code)

    for result in results:
        print(result)

