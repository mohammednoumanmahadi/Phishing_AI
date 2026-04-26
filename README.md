## 🛡️ AI-Powered Phishing Detection — Built for the SOC, Runs Offline Analyze. Score. Report. No cloud. No compromise.
✨ Features • 🏗️ Architecture • ⚙️ Tech Stack • 📁 Project Structure • 🚀 Quick Start • 🔮 Roadmap • 👤 Author
</div>



## ✨ Features

| Feature | Description |
|---------|-------------|
| 📧 **Email (.eml) Analysis** | Parse and extract headers, body, links, attachments, and metadata from raw email files |
| 🌐 **Threat Intelligence Lookup** | Enrich IOCs (IPs, domains, URLs, hashes) against threat intelligence sources automatically |
| 🎯 **Risk Scoring Engine** | Deterministic scoring model evaluates emails across multiple risk dimensions and produces a confidence-rated verdict |
| 🤖 **LLM-Based Report Generation** | Local Mistral model via Ollama generates human-readable, analyst-grade phishing investigation reports |
| 🔒 **Fully Offline / Air-Gap Ready** | Entire pipeline runs locally — no OpenAI, no cloud APIs, no external data transmission |
| 🖥️ **GUI Interface** | Clean local web interface for non-CLI analysts to submit and review results |


## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     PhishGuard AI                        │
│                                                          │
│   ┌─────────┐     ┌─────────────┐     ┌──────────────┐  │
│   │  .eml   │────▶│ Core Engine │────▶│ Risk Scoring │  │
│   │  Input  │     │  (Parser +  │     │   Engine     │  │
│   └─────────┘     │IOC Extractor│     └──────┬───────┘  │
│                   └──────┬──────┘            │          │
│                          │                   ▼          │
│                   ┌──────▼──────┐     ┌──────────────┐  │
│                   │Threat Intel │     │  Local LLM   │  │
│                   │ Enrichment  │     │   (Mistral)  │  │
│                   └─────────────┘     └──────┬───────┘  │
│                                              │          │
│                                      ┌───────▼──────┐   │
│                                      │   Analyst    │   │
│                                      │    Report    │   │
│                                      └──────────────┘   │
└──────────────────────────────────────────────────────────┘
```


## 🚀 Quick Start

### Prerequisites

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull Mistral model
ollama pull mistral

# Install Python dependencies
pip install -r requirements.txt
```

### Run PhishGuard AI

```bash
# Analyze a single email
python main --email suspicious.eml

# Launch GUI mode
python main --gui

# Batch analysis
python scripts/run_batch.py --folder /path/to/emails/
```

## ⚙️ Tech Stack

<div align="center">

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Language** | Python 3.x | Core detection logic, parsing, scoring |
| **Frontend** | JavaScript | GUI interface |
| **LLM Runtime** | [Ollama](https://ollama.ai) | Local LLM inference engine |
| **LLM Model** | Mistral 7B | Report generation & analysis |
| **Email Parsing** | Python `eml-parser` | .eml file processing |
| **Caching** | Local JSON / SQLite | IOC result caching to avoid repeated API calls |
| **TI Enrichment** | Shodan / Requests | Threat intelligence lookups |

</div>

## 📁 Project Structure

```
PhishGuard-AI/
│
├── core/                   # 🧠 Detection & analysis engine
│   ├── parser.py           #    .eml parsing & IOC extraction
│   ├── enrichment.py       #    Threat intelligence lookups
│   ├── cache.py            #    IOC caching engine
│   ├── scorer.py           #    Risk scoring logic
│   └── llm_report.py       #    LLM report generation via Ollama
│
├── gui/                    # 🖥️ Web-based analyst interface
│   ├── app.js              #    Frontend logic
│   └── index.html          #    UI layout
│
├── scripts/                # ⚙️ Automation & test utilities
│   ├── test_samples/       #    Sample .eml files for testing
│   └── run_batch.py        #    Batch analysis script
│
├── requirements.txt        # 📦 Python dependencies
├── main                    # 🚀 Entry point
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull Mistral model
ollama pull mistral

# Install Python dependencies
pip install -r requirements.txt
```

### Run PhishGuard AI

```bash
# Analyze a single email
python main --email suspicious.eml

# Launch GUI mode
python main --gui

# Batch analysis
python scripts/run_batch.py --folder /path/to/emails/
```

### Sample Output

```
╔══════════════════════════════════════════════╗
║       PHISHGUARD AI - ANALYSIS REPORT        ║
╠══════════════════════════════════════════════╣
║  File       : invoice_urgent.eml             ║
║  Risk Score : 87/100  🔴 HIGH RISK           ║
║  Verdict    : PHISHING — High Confidence     ║
╠══════════════════════════════════════════════╣
║  IOCs Detected:                              ║
║    • Domain: secure-login[.]ru (Malicious)   ║
║    • IP: 185.220.101.47 (TOR Exit Node)      ║
║    • URL: hxxp://secure-login[.]ru/auth      ║
╠══════════════════════════════════════════════╣
║  Cache: 3 IOCs served from cache ⚡          ║
║  API Calls Made: 1 (new IOC only)            ║
╠══════════════════════════════════════════════╣
║  LLM Summary:                                ║
║    "This email exhibits strong credential    ║
║     harvesting patterns with spoofed         ║
║     sender identity and urgency tactics..."  ║
╚══════════════════════════════════════════════╝
```

---

## 💡 Why PhishGuard AI?

Most phishing detection tools are cloud-dependent, expensive, or not designed for analyst workflows. PhishGuard AI was built to solve a real problem faced daily in SOC environments:

- ✅ **Privacy-first** — sensitive emails never leave your environment
- ✅ **SOC-native UX** — output is formatted for analyst consumption, not developers
- ✅ **API-efficient** — IOC caching ensures repeated indicators never waste API quota
- ✅ **No vendor lock-in** — swap the LLM model or TI source freely
- ✅ **Explainable AI** — every score is backed by traceable indicators, not a black box

---

## 🔮 Roadmap

- [x] Core `.eml` parsing engine
- [x] IOC extraction (IPs, domains, URLs, hashes)
- [x] IOC caching engine (no repeated API calls)
- [x] Risk scoring engine
- [x] Local LLM report generation
- [x] GUI interface
- [ ] MITRE ATT&CK TTPs mapping
- [ ] SIEM integration (Sentinel / Splunk webhook)
- [ ] Automated SOAR playbook trigger
- [ ] Multi-language phishing detection
- [ ] RAG integration with Vector DB for contextual threat memory
- [ ] Custom threat intelligence feed ingestion (STIX/TAXII)
- [ ] Docker container packaging

## 👤 Author

<div align="center">

**Mohammed Nouman Mahadi**
*SOC Analyst | Threat Detection Engineer | Security Tooling*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github)](https://github.com/mohammednoumanmahadi)

<img width="1257" height="865" alt="image" src="https://github.com/user-attachments/assets/028e6e8d-d8a3-4857-8443-b384477e4eb6" />
<img width="800" height="421" alt="image" src="https://github.com/user-attachments/assets/20a56223-963f-4384-a4bd-d21f94fe3196" />
<img width="1178" height="734" alt="image" src="https://github.com/user-attachments/assets/d8615277-5707-45a3-8980-45fa1e521645" />

*Built with 🛡️ from the SOC floor*

</div>

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

⭐ **If this project helped you, please consider giving it a star!** ⭐

*PhishGuard AI — Because phishing emails deserve to be caught, not forwarded.*

</div>
