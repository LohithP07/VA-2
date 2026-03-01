<div align="center">

# 🛡️ Veracity Agent v2.0
### *Autonomous AI-Powered Document Trust & Integrity System*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

**A multi-issuer document integrity, authenticity & blockchain provenance system — powered by cryptographic signing, a local blockchain, and autonomous AI anomaly response.**

</div>

---

## 📖 Overview

**Veracity Agent** is an end-to-end document verification platform that guarantees the **integrity**, **authenticity**, and **provenance** of digital files. Every document uploaded to the system is:

1. **Hashed** — a SHA-256 fingerprint is generated for the file
2. **Signed** — digitally signed with RSA-PSS-SHA256 by a trusted issuer
3. **Anchored** — recorded as a block in a local blockchain ledger
4. **Monitored** — continuously watched by an AI anomaly detection agent

The system supports **multiple trusted issuers** (e.g., universities, government bodies, external CAs) and features an **autonomous response agent** that can automatically revoke credentials upon detecting suspicious activity.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔐 **Cryptographic Signing** | RSA-PSS-SHA256 signatures per issuer with independent key pairs |
| ⛓️ **Local Blockchain** | SHA-256 linked chain anchors every document hash immutably |
| 🏛️ **Multi-Issuer Identity** | DID-based issuer registry (MLRITM, External CA, Govt Registry) |
| 🧠 **AI Anomaly Detection** | Isolation Forest ML model detects abnormal upload/verify patterns |
| 🤖 **Autonomous Response** | Auto-revokes credentials when anomalies are detected |
| 📦 **Batch Operations** | Register and verify multiple files in a single API call |
| 📊 **Spreadsheet Parsing** | Preview and validate Excel/CSV content on upload |
| ✅ **File Type Validation** | MIME-type and extension-based validation for documents, images, videos, and spreadsheets |
| 🌐 **Interactive Dashboard** | Streamlit-powered UI for all operations |
| 📘 **Auto-Documented API** | Swagger UI available at `/docs` out of the box |

---

## 🏗️ Architecture

```
VA 2/
├── backend/
│   ├── main.py                  # FastAPI application & all API routes
│   ├── identity/
│   │   ├── issuers.py           # DID-based issuer registry
│   │   ├── keygen.py            # RSA key pair generation per issuer
│   │   ├── sign.py              # Sign & verify with RSA-PSS-SHA256
│   │   └── keys.py              # Key loading utilities
│   ├── blockchain/
│   │   └── blockchain.py        # Local SHA-256 linked blockchain
│   ├── anomaly/
│   │   ├── detector.py          # Isolation Forest anomaly detection
│   │   └── logger.py            # Event logger for anomaly analysis
│   ├── response/
│   │   └── responder.py         # Autonomous credential revocation agent
│   ├── utils/
│   │   ├── hashing.py           # SHA-256 file hashing
│   │   ├── file_validator.py    # MIME-type & extension validation
│   │   └── excel_parser.py      # Excel/CSV parsing & preview
│   └── storage/
│       └── local_ledger.json    # Off-chain document registry
├── dashboard/
│   └── app.py                   # Streamlit frontend dashboard
├── start.bat                    # One-click launcher (Windows)
└── req.txt                      # Full dependency list
```

---

## 🔌 API Endpoints

### 📥 Document Registration
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/upload` | Register, sign, and blockchain-anchor a single file |
| `POST` | `/upload/batch` | Batch register multiple files under one issuer |

### 🔍 Verification
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/verify` | Verify integrity and authenticity of a single file |
| `POST` | `/verify/batch` | Batch verify multiple files |

### 📘 Ledger & Blockchain
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/ledger/view` | View all records in the off-chain ledger |
| `DELETE` | `/ledger/clear` | Clear all ledger records |
| `GET` | `/blockchain/verify` | Validate integrity of the entire blockchain |
| `GET` | `/blockchain/blocks` | Browse all blockchain blocks |

### 🏛️ Issuers & Agents
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/issuers` | List all trusted issuers in the registry |
| `GET` | `/anomaly/check` | Run anomaly detection on recent events |
| `POST` | `/agent/respond` | Trigger autonomous agent response to anomalies |

### 📊 Utilities
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/parse/spreadsheet` | Preview spreadsheet content without registering |

> **Interactive API Docs:** `http://127.0.0.1:8000/docs`

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- Windows OS (for `start.bat` launcher) — or run manually on any OS

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/veracity-agent.git
cd veracity-agent
```

### 2. Create a Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate  # macOS / Linux
```

### 3. Install Dependencies
```bash
pip install -r req.txt
```

### 4. Launch the Application

**Option A — One-click launcher (Windows):**
```
Double-click start.bat
```

**Option B — Manual launch:**
```bash
# Terminal 1 — Backend API
uvicorn backend.main:app --reload

# Terminal 2 — Dashboard
streamlit run dashboard/app.py
```

### 5. Access the Services
| Service | URL |
|---|---|
| 🌐 Streamlit Dashboard | http://localhost:8501 |
| ⚡ FastAPI Backend | http://127.0.0.1:8000 |
| 📘 Swagger API Docs | http://127.0.0.1:8000/docs |

---

## 🔐 How Document Verification Works

```
Upload File
     │
     ▼
┌─────────────────┐
│  Validate File  │  ← MIME type + extension check
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Generate Hash  │  ← SHA-256 fingerprint
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Sign (RSA-PSS) │  ← Issuer private key
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Save to Ledger  │  ← Off-chain JSON ledger
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Anchor to Chain │  ← SHA-256 linked blockchain block
└─────────────────┘
```

**On Verification:**
- The file is re-hashed and looked up in the ledger
- The issuer's RSA signature is verified against the stored record
- The result is one of: `VERIFIED` ✅ | `TAMPERED OR UNKNOWN` ❌ | `REVOKED` 🚫 | `REJECTED` ⛔

---

## 🏛️ Trusted Issuers

The system ships with three pre-configured DID-based issuers, each with their own RSA key pair:

| DID | Name | Short |
|---|---|---|
| `did:veracity:mlritm` | MLR Institute of Technology and Management | MLRITM |
| `did:veracity:external` | External Certification Authority | External CA |
| `did:veracity:govt` | Government Digital Registry | Govt Registry |

> Keys are auto-generated on first startup if they do not exist.

---

## 🧠 Anomaly Detection & Autonomous Response

The anomaly detection module uses **scikit-learn's Isolation Forest** to monitor event patterns (uploads, verifications) in real time.

- **Features analyzed:** Request count, event type encoding
- **Trigger:** If the latest event is flagged as an outlier (`prediction == -1`)
- **Response:** The `/agent/respond` endpoint automatically invokes credential revocation for all unrevoked records in the ledger

---

## 📦 Dependencies

```
# Backend (FastAPI)
fastapi
uvicorn
python-multipart
cryptography

# Frontend (Streamlit Dashboard)
streamlit
requests
Pillow

# Data & ML (Anomaly Detection)
pandas
numpy
scikit-learn

# Spreadsheet Parsing
openpyxl
```

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
Made with ❤️ for document trust and integrity
</div>
