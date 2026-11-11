# Assignment4-IT355
# Multi-LLM Vulnerability Analysis and Defensive Patching

Scans the OWASP WebGoat codebase for vulnerabilities using three LLM APIs (Gemini, Claude, and Groq), generates patches, and compares the results.

## What it does

1. **Scan:** Sends WebGoat source files to each model and gets back the file path, line numbers, and CWE ID/name for each vulnerability.
2. **Patch:** Sends the vulnerable code back to the model to rewrite it securely.
3. **Verify:** We manually review each patch to check that it fixes the CWE.
4. **Compare:** We classify results as True Vulnerability + True Patch, True Vulnerability + False Patch, or Hallucination.

## Setup

1. Install Java (17 or later).
2. Clone WebGoat into this project:
   ```powershell
   git clone https://github.com/WebGoat/WebGoat.git webgoat
   ```
3. Set your API keys in PowerShell:
   ```powershell
   $env:GEMINI_API_KEY="your-key"
   $env:ANTHROPIC_API_KEY="your-key"
   $env:GROQ_API_KEY="your-key"
   ```
   These only last for the current PowerShell session, so set them again if you open a new window.

## Run

```powershell
java MultiModelPipeline.java
```

Java runs the source file directly, so no separate compile step is needed.

## Output

Each finding includes:
- File name and path
- Line number(s)
- CWE ID and name (e.g., CWE-89, SQL Injection)

## Team

- Nathan Wolniak
- Aaron Rosenberg
- Brady Ehman
- Andrew Kosy
- John Ortiz
