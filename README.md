---
title: AI Vulnerability Scanner
emoji: 🛡️
colorFrom: green
colorTo: blue
sdk: gradio
sdk_version: 4.44.1
python_version: "3.11"
app_file: app.py
pinned: false
license: mit
---

# AI Vulnerability Scanner

This private Hugging Face Space runs the web-based vulnerability scanner MVP.

It combines:

- Rule-based vulnerability pattern detection
- CodeBERT auxiliary prediction
- Confidence threshold handling with `UNCERTAIN`

The AI output is an auxiliary signal, not a final security judgment.
