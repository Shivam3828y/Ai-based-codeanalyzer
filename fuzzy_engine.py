import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl


def create_fuzzy_system():
    """
    Create the CodeTrust fuzzy inference system.

    Inputs:
        obfuscation
        external_loading
        dynamic_execution
        suspicious_operations

    Output:
        security_risk
    """

    # -----------------------------
    # INPUT VARIABLES
    # -----------------------------

    obfuscation = ctrl.Antecedent(
        np.arange(0, 101, 1),
        "obfuscation"
    )

    external_loading = ctrl.Antecedent(
        np.arange(0, 101, 1),
        "external_loading"
    )

    dynamic_execution = ctrl.Antecedent(
        np.arange(0, 101, 1),
        "dynamic_execution"
    )

    suspicious_operations = ctrl.Antecedent(
        np.arange(0, 101, 1),
        "suspicious_operations"
    )

    # -----------------------------
    # OUTPUT VARIABLE
    # -----------------------------

    security_risk = ctrl.Consequent(
        np.arange(0, 101, 1),
        "security_risk"
    )

    # -----------------------------
    # MEMBERSHIP FUNCTIONS
    # -----------------------------

    for variable in [
        obfuscation,
        external_loading,
        dynamic_execution,
        suspicious_operations
    ]:

        variable["low"] = fuzz.trimf(
            variable.universe,
            [0, 0, 40]
        )

        variable["medium"] = fuzz.trimf(
            variable.universe,
            [20, 50, 80]
        )

        variable["high"] = fuzz.trimf(
            variable.universe,
            [60, 100, 100]
        )

    # Risk membership functions

    security_risk["low"] = fuzz.trimf(
        security_risk.universe,
        [0, 0, 35]
    )

    security_risk["medium"] = fuzz.trimf(
        security_risk.universe,
        [25, 50, 75]
    )

    security_risk["high"] = fuzz.trimf(
        security_risk.universe,
        [65, 100, 100]
    )

    # -----------------------------
    # FUZZY RULES
    # -----------------------------

    rules = [

        ctrl.Rule(
            obfuscation["high"] &
            external_loading["high"],
            security_risk["high"]
        ),

        ctrl.Rule(
            dynamic_execution["high"] &
            suspicious_operations["high"],
            security_risk["high"]
        ),

        ctrl.Rule(
            external_loading["high"] &
            dynamic_execution["medium"],
            security_risk["high"]
        ),

        ctrl.Rule(
            obfuscation["medium"] &
            external_loading["medium"],
            security_risk["medium"]
        ),

        ctrl.Rule(
            dynamic_execution["medium"] &
            suspicious_operations["medium"],
            security_risk["medium"]
        ),

        ctrl.Rule(
            obfuscation["low"] &
            external_loading["low"] &
            dynamic_execution["low"] &
            suspicious_operations["low"],
            security_risk["low"]
        ),

        ctrl.Rule(
            obfuscation["high"],
            security_risk["high"]
        ),

        ctrl.Rule(
            suspicious_operations["high"],
            security_risk["high"]
        ),
    ]

    # -----------------------------
    # CONTROL SYSTEM
    # -----------------------------

    system = ctrl.ControlSystem(rules)

    return system


def calculate_risk(
    obfuscation,
    external_loading,
    dynamic_execution,
    suspicious_operations
):
    """
    Calculate fuzzy security risk from 0 to 100.
    """

    system = create_fuzzy_system()

    simulation = ctrl.ControlSystemSimulation(system)

    simulation.input["obfuscation"] = obfuscation
    simulation.input["external_loading"] = external_loading
    simulation.input["dynamic_execution"] = dynamic_execution
    simulation.input["suspicious_operations"] = suspicious_operations

    simulation.compute()

    risk = simulation.output["security_risk"]

    return round(float(risk), 2)


def get_risk_level(risk):
    """
    Convert numerical risk into a recommendation.
    """

    if risk < 30:
        return "LOW", "USE"

    elif risk < 70:
        return "MEDIUM", "REVIEW"

    else:
        return "HIGH", "DO NOT USE"


if __name__ == "__main__":

    # Test values
    risk = calculate_risk(
        obfuscation=80,
        external_loading=90,
        dynamic_execution=70,
        suspicious_operations=80
    )

    level, recommendation = get_risk_level(risk)

    print("--------------------------------")
    print("CodeTrust Fuzzy Risk Test")
    print("--------------------------------")
    print(f"Risk Score: {risk}/100")
    print(f"Risk Level: {level}")
    print(f"Recommendation: {recommendation}")