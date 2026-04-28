# Fortress Upload 🛡️

A defense-in-depth FastAPI demonstration for securely handling user media uploads. This project protects backend servers from common upload vulnerabilities including disguised malware, polyglot files, and metadata injection (RCE vectors).

![Python](https://img.shields.io/badge/Python-3.13%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.121%2B-00a393)
![Security](https://img.shields.io/badge/Security-Defense--in--Depth-red)

## Overview

When a web application accepts file uploads, it exposes itself to severe risks if files aren't heavily validated and sanitized. Attackers frequently bypass simple `.extension` checks. This project implements a **4-Layer Defense Pipeline**:

1. **Magic Number Validation** — Verifies actual file headers (bytes) rather than trusting user-provided extension or MIME type
2. **Signature Scanning** — Scans incoming byte stream for known malware signatures (simulating ClamAV)
3. **Media Sanitization** — Re-encodes images using Pillow, stripping EXIF data, hidden chunks, and polyglot payloads
4. **URL Quarantine** — Safely fetches files from URLs with SSRF protection, timeout limits, and streaming to prevent zip bombs

## Architecture

```mermaid
flowchart TB
    subgraph Client["Client"]
        UI[("Web UI<br/>localhost:8000")]
    end

    subgraph Server["Fortress Upload Server"]
        subgraph Endpoints["FastAPI Endpoints"]
            GET_ROOT["GET /"]
            POST_UPLOAD["POST /upload"]
            POST_URL["POST /upload-url"]
        end

        subgraph Defense["4-Layer Defense Pipeline"]
            L1[Magic Number<br/>Validation]
            L2[Signature<br/>Scanning]
            L3[Media<br/>Sanitization]
            L4[URL<br/>Quarantine]
        end

        subgraph Utils["Utilities"]
            MAGIC[python-magic]
            PIL[Pillow]
            TEST_GEN[Test File<br/>Generator]
        end
    end

    subgraph Storage["Storage"]
        TEST_DIR["test_files/"]
        SAFE_DIR["safe_*.png"]
    end

    UI --> GET_ROOT
    UI --> POST_UPLOAD
    UI --> POST_URL

    POST_UPLOAD --> L1
    POST_URL --> L4
    L4 --> L1

    L1 --> MAGIC
    L1 --> L2
    L2 --> L3
    L3 --> PIL
    L3 --> TEST_DIR
    L3 --> SAFE_DIR
    TEST_GEN --> TEST_DIR
```

## Defense Pipeline Flow

```mermaid
flowchart LR
    subgraph Input["Input Sources"]
        LOCAL[("Local File<br/>Upload")]
        REMOTE[("URL<br/>Fetch")]
    end

    subgraph Pipeline["Security Pipeline"]
        direction TB
        L1["🔍 Layer 1: Magic Number<br/>Validate file headers<br/>Reject invalid MIME types"]
        L2["🦠 Layer 2: Signature Scan<br/>Check for malware<br/>signatures (EICAR)"]
        L3["🧼 Layer 3: Sanitization<br/>Re-encode image<br/>Strip metadata/chunks"]
        L4["🔒 Layer 4: URL Quarantine<br/>SSRF protection<br/>Size limits & streaming"]
    end

    subgraph Output["Results"]
        SUCCESS[("✅ Safe File<br/>Saved to disk")]
        REJECTED[("❌ Rejected<br/>Error response")]
    end

    LOCAL --> L1
    REMOTE --> L4
    L4 --> L1
    L1 --> L2 --> L3 --> SUCCESS
    L1 -.-> REJECTED
    L2 -.-> REJECTED
    L3 -.-> REJECTED
    L4 -.-> REJECTED

    style REJECTED fill:#fee2e2,stroke:#ef4444
    style SUCCESS fill:#dcfce7,stroke:#22c55e
```

## Features

- **Real-time File Validation** — Rejects non-media files instantly using `python-magic`
- **URL Quarantine** — Safely fetches files from URLs with SSRF protection, timeout limits, and streaming to prevent zip bombs
- **Chunked Upload Processing** — Reads files in 8KB chunks to prevent memory exhaustion
- **Automated Test File Generation** — Creates safe, EICAR-simulated, and polyglot test files on startup
- **Polyglot Neutralization** — Strips hidden PHP web-shells injected into PNG chunks
- **Zero-Disk-Write Validation** — All scans and sanitization happen in memory (`io.BytesIO`) before writing to disk

## Prerequisites

- Python 3.13+
- `libmagic` (required for file header validation)
  - **Ubuntu/Debian:** `sudo apt-get install libmagic1`
  - **macOS:** `brew install libmagic`
  - **Windows:** Use `pip install python-magic-bin`

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/fortress-upload.git
cd fortress-upload

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install fastapi uvicorn python-multipart Pillow python-magic
# Windows: pip install python-magic-bin instead of python-magic
```

## Running the Application

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Navigate to `http://localhost:8000` to access the upload interface with two modes:

- **Upload Local File** — Drag & drop or select a file from your device
- **Fetch from URL** — Enter a URL to download and scan an image remotely

## Testing the Defenses

When the server starts, it automatically generates a `test_files/` directory with three files. Upload each through the web UI to observe the defense pipeline:

| File | Expected Result | Why |
|------|-----------------|-----|
| `clean_image.png` | ✅ Success | Standard PNG format, no malicious signatures, clean metadata |
| `eicar_simulated_virus.png` | ❌ Blocked (406) | Contains EICAR test string, blocked by Layer 2 |
| `polyglot_webshell.png` | ⚠️ Success (modified) | Hidden PHP in PNG tEXt chunk destroyed by Layer 3 |

## Project Structure

```
fortress-upload/
├── main.py                # Core FastAPI app and security pipeline
├── README.md              # This file
├── test_files/            # Auto-generated test files
│   ├── clean_image.png
│   ├── eicar_simulated_virus.png
│   └── polyglot_webshell.png
└── safe_*.png             # Sanitized output files
```

## Disclaimer

This is an educational project demonstrating defensive programming techniques. The "malware" is strictly simulated (EICAR strings and harmless text) and safe to run locally. Do not use the simulated scanner in production — replace `simulate_clamav_scan` with actual ClamAV bindings.