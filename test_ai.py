from ai_engine import generate_security_explanation

findings = [
    {
        "category": "Dynamic Code Execution",
        "line": 7,
        "code": 'eval("print(\'test\')")'
    },
    {
        "category": "Network Activity",
        "line": 9,
        "code": 'requests.get("https://example.com")'
    }
]

indicators = {
    "obfuscation": 70,
    "external_loading": 0,
    "dynamic_execution": 45,
    "suspicious_operations": 50
}

result = generate_security_explanation(
    filename="test_suspicious.py",
    findings=findings,
    indicators=indicators,
    risk_score=57.97,
    risk_level="MEDIUM",
    recommendation="REVIEW"
)

print("\n========== AI ANALYSIS ==========\n")
print(result)