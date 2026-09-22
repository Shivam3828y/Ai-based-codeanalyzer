import re


# ============================================================
# SUSPICIOUS CODE PATTERNS
# ============================================================

SUSPICIOUS_PATTERNS = {

    # --------------------------------------------------------
    # Dynamic Code Execution
    # --------------------------------------------------------
    "Dynamic Code Execution": [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bcompile\s*\(",
        r"\bFunction\s*\(",
        r"\bloadstring\s*\(",
    ],

    # --------------------------------------------------------
    # System Command Execution
    # --------------------------------------------------------
    "System Command Execution": [
        r"\bos\s*\.\s*system\s*\(",
        r"\bos\s*\.\s*popen\s*\(",
        r"\bsubprocess\s*\.",
        r"\bcommands\s*\.",
        r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
    ],

    # --------------------------------------------------------
    # External Code Loading
    # --------------------------------------------------------
    "External Code Loading": [
        r"\brequire\s*\(",
        r"\bimportlib\s*\.\s*import_module\s*\(",
        r"\bimportlib\b",
        r"\b__import__\s*\(",
        r"\bdofile\s*\(",
        r"\bloadfile\s*\(",
    ],

    # --------------------------------------------------------
    # Network Activity
    # --------------------------------------------------------
    "Network Activity": [
        r"\brequests\s*\.\s*(get|post|put|delete|patch|request)\s*\(",
        r"\burllib\b",
        r"\bsocket\s*\.",
        r"\bhttp[s]?\s*:",
        r"\bfetch\s*\(",
        r"\bXMLHttpRequest\b",
    ],

    # --------------------------------------------------------
    # Encoded / Obfuscated Content
    # --------------------------------------------------------
    #
    # IMPORTANT:
    # "import base64" is NOT suspicious by itself.
    #
    # We detect actual encoding/decoding operations instead.
    # --------------------------------------------------------
    "Encoded / Obfuscated Content": [
        r"\bbase64\s*\.\s*b64decode\s*\(",
        r"\bbase64\s*\.\s*b64encode\s*\(",
        r"\bb64decode\s*\(",
        r"\bb64encode\s*\(",
        r"\\x[0-9a-fA-F]{2}",
        r"\\u[0-9a-fA-F]{4}",
    ],

    # --------------------------------------------------------
    # Credential / Secret Access
    # --------------------------------------------------------
    "Credential / Secret Access": [
        r"\bpassword\b",
        r"\bpasswd\b",
        r"\bapi[\-_]?key\b",
        r"\bsecret[\-_]?key\b",
        r"\bauthorization\b",
        r"\baccess[\-_]?token\b",
        r"\bauth[\-_]?token\b",
        r"\bos\s*\.\s*environ\b",
        r"\bos\s*\.\s*getenv\s*\(",
    ],
}


# ============================================================
# STATIC CODE SCANNER
# ============================================================

def scan_code(source_code):
    """
    Analyze source code without executing it.

    The scanner searches for suspicious patterns and returns
    structured findings containing the category, line number,
    and source-code line.
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

                    # Do not report the same category
                    # multiple times for the same line.
                    break

    return findings


# ============================================================
# CONVERT FINDINGS TO FUZZY INDICATORS
# ============================================================

def calculate_indicators(findings):
    """
    Convert scanner findings into fuzzy input values.

    The resulting values are between 0 and 100.
    """

    indicators = {
        "obfuscation": 0,
        "external_loading": 0,
        "dynamic_execution": 0,
        "suspicious_operations": 0,
    }

    for finding in findings:

        category = finding["category"]

        # ----------------------------------------------------
        # Obfuscation
        # ----------------------------------------------------
        if category == "Encoded / Obfuscated Content":

            indicators["obfuscation"] += 35

        # ----------------------------------------------------
        # External Code Loading
        # ----------------------------------------------------
        elif category == "External Code Loading":

            indicators["external_loading"] += 40

        # ----------------------------------------------------
        # Dynamic Execution
        # ----------------------------------------------------
        elif category == "Dynamic Code Execution":

            indicators["dynamic_execution"] += 45

        # ----------------------------------------------------
        # Other Suspicious Operations
        # ----------------------------------------------------
        elif category in [
            "System Command Execution",
            "Network Activity",
            "Credential / Secret Access"
        ]:

            indicators["suspicious_operations"] += 25

    # --------------------------------------------------------
    # Keep all values between 0 and 100
    # --------------------------------------------------------

    for key in indicators:

        indicators[key] = min(
            indicators[key],
            100
        )

    return indicators