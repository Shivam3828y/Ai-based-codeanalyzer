# CodeTrust

## AI and Fuzzy Logic Based Code and Asset Security Risk Analyzer

CodeTrust is a static security analysis system that checks uploaded source-code and script files for potentially suspicious patterns.

It combines static code analysis, Fuzzy Logic, and AI-assisted explanation using LangChain and Google Gemini.

The system does not execute, modify, or delete the uploaded code.

---

## Student Information

| Field | Details |
|---|---|
| Student Name | Shivam |
| Roll Number | 19067 |
| Class | TY IT |
| Department | Information Technology |
| Subject | Indian Knowledge Systems (IKS) |
| College | SIWS College |
| Academic Year | 2026–27 |

---

## Project Overview

CodeTrust analyzes source-code files and identifies potentially suspicious patterns.

The system checks for indicators such as:

- Dynamic code execution
- System command execution
- External code loading
- Network activity
- Encoded or obfuscated content
- Credential or secret access

The detected indicators are processed by a Fuzzy Logic engine to calculate a security risk score between 0 and 100.

The result is classified as:

- LOW
- MEDIUM
- HIGH

The system also provides a recommendation:

- USE
- REVIEW
- DO NOT USE

An AI layer using LangChain and Google Gemini provides an explanation of the detected indicators and the calculated risk.

---

## Objectives

The main objectives of CodeTrust are:

1. Analyze source code without executing it.
2. Detect potentially suspicious code patterns.
3. Convert detected patterns into security indicators.
4. Apply Fuzzy Logic to calculate security risk.
5. Generate a risk score between 0 and 100.
6. Classify the result as LOW, MEDIUM, or HIGH.
7. Provide a recommendation based on the risk level.
8. Generate an AI-assisted explanation of the analysis.
9. Apply Fuzzy Logic concepts from the IKS curriculum to a practical computing problem.

---

## Features

### Static Code Analysis

CodeTrust scans uploaded files without executing them.

Supported file types include:

- Python
- JavaScript
- TypeScript
- Lua
- Luau
- Java
- PHP
- TXT

### Suspicious Pattern Detection

The scanner checks for:

- Dynamic code execution
- System command execution
- External code loading
- Network activity
- Encoded or obfuscated content
- Credential and secret access

### Fuzzy Logic Risk Assessment

The detected patterns are converted into four main indicators:

- Obfuscation
- External Loading
- Dynamic Execution
- Suspicious Operations

These indicators are processed by the Fuzzy Logic engine to calculate a risk score from 0 to 100.

### AI-Assisted Explanation

LangChain connects the application with Google Gemini.

The AI explains:

- Detected security concerns
- Suspicious behaviors
- Why the calculated risk was produced
- The recommended action
- Limitations of static analysis

### Risk Classification

| Risk Score | Risk Level | Recommendation |
|---:|---|---|
| 0–29 | LOW | USE |
| 30–69 | MEDIUM | REVIEW |
| 70–100 | HIGH | DO NOT USE |

The final risk score is calculated using the membership functions and Fuzzy Logic rules implemented in the system.

---

## System Architecture

```text
Developer
    ↓
Upload Code / Script
    ↓
Static Code Analyzer
    ↓
Suspicious Pattern Detection
    ↓
Fuzzy Logic Engine
    ↓
Risk Score
    ↓
Risk Level and Recommendation
    ↓
LangChain + Google Gemini
    ↓
AI Security Explanation