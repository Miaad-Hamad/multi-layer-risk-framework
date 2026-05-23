# A Multi-Layer Risk Assessment Framework for Mitigating Social Engineering Attacks

This is a bilingual Streamlit-based research prototype for assessing social engineering risk across three independent layers:

1. Human Layer
2. Technical Layer
3. Organizational Layer

The interface displays questions and response options in Arabic and English, while the stored statistics remain in English for reporting and analysis.

## Features

- Bilingual Arabic/English assessment interface
- Independent layer-based risk scoring
- NIST-aligned recommendations
- Phishing URL feature analysis
- Hidden Admin Panel for statistics
- CSV result storage

## How to Run Locally

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

## Admin Panel

Default admin password inside `app.py`:

```text
admin123
```

Change it before deployment.
