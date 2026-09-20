from scanner import scan_code, calculate_indicators
from fuzzy_engine import calculate_risk, get_risk_level


with open("test_suspicious.py", "r", encoding="utf-8") as file:
    source_code = file.read()


# 1. Static analysis
findings = scan_code(source_code)

print("\n========== FINDINGS ==========")

for finding in findings:
    print(
        f"[{finding['category']}] "
        f"Line {finding['line']}: "
        f"{finding['code']}"
    )


# 2. Convert findings into fuzzy inputs
indicators = calculate_indicators(findings)

print("\n========== FUZZY INPUTS ==========")

for name, value in indicators.items():
    print(f"{name}: {value}")


# 3. Fuzzy risk calculation
risk = calculate_risk(
    obfuscation=indicators["obfuscation"],
    external_loading=indicators["external_loading"],
    dynamic_execution=indicators["dynamic_execution"],
    suspicious_operations=indicators["suspicious_operations"]
)


# 4. Recommendation
level, recommendation = get_risk_level(risk)

print("\n========== FINAL RESULT ==========")

print(f"Risk Score: {risk}/100")
print(f"Risk Level: {level}")
print(f"Recommendation: {recommendation}")