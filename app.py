import streamlit as st

from scanner import scan_code, calculate_indicators
from fuzzy_engine import calculate_risk, get_risk_level
from ai_engine import generate_security_explanation


# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------

st.set_page_config(
    page_title="CodeTrust",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ CodeTrust")

st.subheader(
    "AI & Fuzzy Logic Based Code and Asset Security Risk Analyzer"
)

st.write(
    "Upload a code or script file. CodeTrust performs static analysis, "
    "evaluates suspicious indicators using Fuzzy Logic, and uses AI to "
    "explain the security findings."
)

st.info(
    "CodeTrust performs static analysis only. "
    "It does not execute, delete, or modify uploaded code."
)


# --------------------------------------------------
# FILE UPLOAD
# --------------------------------------------------

uploaded_file = st.file_uploader(
    "Upload a code or script file",
    type=[
        "py",
        "js",
        "ts",
        "lua",
        "luau",
        "java",
        "php",
        "txt"
    ]
)


# --------------------------------------------------
# ANALYSIS
# --------------------------------------------------

if uploaded_file:

    st.divider()

    st.subheader("📄 File Information")

    col1, col2 = st.columns(2)

    with col1:
        st.write("**File:**", uploaded_file.name)

    with col2:
        st.write("**Size:**", f"{uploaded_file.size:,} bytes")

    # Read uploaded file as text
    content = uploaded_file.read().decode(
        "utf-8",
        errors="replace"
    )

    # --------------------------------------------------
    # FILE PREVIEW
    # --------------------------------------------------

    with st.expander("View Uploaded Code", expanded=False):
        st.code(
            content[:10000],
            language="text"
        )

    # --------------------------------------------------
    # ANALYZE BUTTON
    # --------------------------------------------------

    analyze = st.button(
        "🔍 Analyze Security Risk",
        type="primary",
        use_container_width=True
    )

    if analyze:

        # --------------------------------------------------
        # 1. STATIC SCANNER
        # --------------------------------------------------

        with st.spinner("Scanning code for suspicious indicators..."):

            findings = scan_code(content)

            indicators = calculate_indicators(findings)

        # --------------------------------------------------
        # 2. FUZZY LOGIC
        # --------------------------------------------------

        with st.spinner("Calculating fuzzy security risk..."):

            risk_score = calculate_risk(
                obfuscation=indicators["obfuscation"],
                external_loading=indicators["external_loading"],
                dynamic_execution=indicators["dynamic_execution"],
                suspicious_operations=indicators["suspicious_operations"]
            )

            risk_level, recommendation = get_risk_level(
                risk_score
            )

        # --------------------------------------------------
        # 3. RISK SUMMARY
        # --------------------------------------------------

        st.divider()

        st.subheader("🛡️ Security Assessment")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )

        with col2:
            st.metric(
                "Risk Level",
                risk_level
            )

        with col3:
            st.metric(
                "Recommendation",
                recommendation
            )

        # --------------------------------------------------
        # 4. FUZZY INPUTS
        # --------------------------------------------------

        st.subheader("🧠 Fuzzy Logic Indicators")

        indicator_col1, indicator_col2 = st.columns(2)

        with indicator_col1:

            st.write(
                f"**Obfuscation:** "
                f"{indicators['obfuscation']}/100"
            )

            st.progress(
                min(indicators["obfuscation"], 100) / 100
            )

            st.write(
                f"**External Loading:** "
                f"{indicators['external_loading']}/100"
            )

            st.progress(
                min(indicators["external_loading"], 100) / 100
            )

        with indicator_col2:

            st.write(
                f"**Dynamic Execution:** "
                f"{indicators['dynamic_execution']}/100"
            )

            st.progress(
                min(indicators["dynamic_execution"], 100) / 100
            )

            st.write(
                f"**Suspicious Operations:** "
                f"{indicators['suspicious_operations']}/100"
            )

            st.progress(
                min(indicators["suspicious_operations"], 100) / 100
            )

        # --------------------------------------------------
        # 5. FINDINGS
        # --------------------------------------------------

        st.divider()

        st.subheader("🔎 Suspicious Findings")

        if findings:

            st.warning(
                f"{len(findings)} suspicious indicator(s) detected."
            )

            for finding in findings:

                with st.expander(
                    f"{finding['category']} — Line {finding['line']}"
                ):

                    st.write(
                        f"**Category:** {finding['category']}"
                    )

                    st.write(
                        f"**Line:** {finding['line']}"
                    )

                    st.code(
                        finding["code"],
                        language="text"
                    )

        else:

            st.success(
                "No suspicious indicators were detected "
                "by the current static analysis rules."
            )

        # --------------------------------------------------
        # 6. AI ANALYSIS
        # --------------------------------------------------

        st.divider()

        st.subheader("🤖 AI Security Analysis")

        with st.spinner(
            "LangChain + Gemini is analyzing the findings..."
        ):

            try:

                ai_explanation = generate_security_explanation(
                    filename=uploaded_file.name,
                    findings=findings,
                    indicators=indicators,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    recommendation=recommendation
                )

                if ai_explanation:
                    st.markdown(ai_explanation)
                else:
                    st.warning(
                        "The AI service returned an empty response. "
                        "The static and fuzzy analysis results are still valid."
                    )

            except Exception as error:

                error_message = str(error)

                # Handle temporary Gemini availability problems
                if (
                    "503" in error_message
                    or "UNAVAILABLE" in error_message
                    or "high demand" in error_message.lower()
                ):

                    st.warning(
                        "AI explanation is temporarily unavailable "
                        "because the Gemini service is experiencing "
                        "high demand."
                    )

                    st.info(
                        "The static analysis and fuzzy-logic risk "
                        "assessment were completed successfully. "
                        "AI explanation is an additional analysis layer "
                        "and does not affect the calculated risk score."
                    )

                elif (
                    "GOOGLE_API_KEY" in error_message
                    or "API key" in error_message
                ):

                    st.error(
                        "AI analysis is unavailable because the "
                        "Gemini API configuration could not be verified."
                    )

                else:

                    st.warning(
                        "AI explanation could not be generated at this time."
                    )

        # --------------------------------------------------
        # 7. FINAL RECOMMENDATION
        # --------------------------------------------------

        st.divider()

        st.subheader("📌 Final Recommendation")

        if recommendation == "USE":

            st.success(
                "USE — No significant suspicious indicators "
                "were detected by the current analysis."
            )

        elif recommendation == "REVIEW":

            st.warning(
                "REVIEW — Suspicious indicators were detected. "
                "Review the code before using it."
            )

        else:

            st.error(
                "DO NOT USE — The analysis detected a high "
                "combination of suspicious indicators."
            )

        st.caption(
            "Important: CodeTrust is a static risk analyzer, "
            "not a guaranteed malware detector. "
            "A low-risk result does not prove that code is safe."
        )