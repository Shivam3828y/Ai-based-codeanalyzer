import os

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate


# Load variables from .env
load_dotenv()


# ============================================================
# CREATE GEMINI MODEL
# ============================================================

def create_ai_model():
    """
    Create and return the Gemini model through LangChain.
    """

    api_key = os.getenv("GOOGLE_API_KEY")

    if not api_key:
        raise ValueError(
            "GOOGLE_API_KEY is missing. "
            "Check your .env file."
        )

    model = ChatGoogleGenerativeAI(
        model="gemini-3.5-flash-lite",
        google_api_key=api_key,
        temperature=0.2,
        max_retries=2
    )

    return model


# ============================================================
# GENERATE SECURITY EXPLANATION
# ============================================================

def generate_security_explanation(
    filename,
    findings,
    indicators,
    risk_score,
    risk_level,
    recommendation
):
    """
    Use LangChain + Gemini to explain the static security analysis.
    """

    model = create_ai_model()

    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You are CodeTrust, a software security analysis assistant.

Your job is to explain the results of a static code security analysis.

Important rules:

1. Do not claim that suspicious code is definitely malware.
2. Explain only the observable indicators found by the scanner.
3. Explain why the combination of indicators affects risk.
4. Use the supplied fuzzy risk score.
5. Explain the recommendation clearly.
6. Keep the explanation concise and technical.
7. Mention that static analysis cannot guarantee malware detection.
"""
        ),
        (
            "human",
            """
Analyze this CodeTrust security report.

File:
{filename}

Findings:
{findings}

Fuzzy indicators:
{indicators}

Fuzzy risk score:
{risk_score}/100

Risk level:
{risk_level}

Recommendation:
{recommendation}

Provide:

1. Main security concerns.
2. Suspicious behaviors detected.
3. Why the fuzzy system produced this risk level.
4. What the developer should do based on the recommendation.
5. A short limitation of static analysis.
"""
        )
    ])

    chain = prompt | model

    response = chain.invoke({
        "filename": filename,
        "findings": findings,
        "indicators": indicators,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "recommendation": recommendation
    })

    # ========================================================
    # EXTRACT RESPONSE TEXT
    # ========================================================

    content = response.content

    if isinstance(content, list):

        text_parts = []

        for item in content:

            if (
                isinstance(item, dict)
                and item.get("type") == "text"
            ):
                text_parts.append(
                    item.get("text", "")
                )

        return "\n".join(text_parts).strip()

    return str(content).strip()


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":
    print("CodeTrust AI engine loaded successfully.")