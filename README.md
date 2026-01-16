# SENTINNELLE Intelligence System

**Production-grade OSINT intelligence platform for lawful intelligence gathering**

[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)]()

## Overview

SENTINNELLE is a pure Python, defense-grade OSINT (Open-Source Intelligence) platform designed to generate actionable, explainable intelligence from lawful public data sources.

## Architecture

SENTINNELLE v2.0 is a unified, modular Python platform:

- **Core**: Intelligence graph modeling, entity resolution, and confidence scoring.
- **SocialEngine**: Native social media reconnaissance engine (integrated Social Media Search).
- **MailEngine**: Native deep email OSINT engine (integrated Mail OSINT).
- **NetworkEngine**: IP, DNS, WHOIS, and Phone number intelligence.
- **Interface**: Rich-based Command Line Interface.

## Project Structure

```text
sentinelle/
├── src/
│   └── sentinelle/
│       ├── core/                  # Shared Domain & Logic
│       │   ├── graph/             # Intelligence Graph
│       │   └── resolution/        # Identity resolution
│       ├── engines/               # Native Internal Engines
│       │   ├── mail/              # MailEngine
│       │   ├── social/            # SocialEngine
│       │   └── network/           # Network & Phone Engine
│       └── interface/             # Rich-based CLI
├── main.py                        # Entry point
└── pyproject.toml                 # Packaging & Dependencies
```

## Installation

```bash
# Install as editable package
pip3 install -e .
```

## Usage

```bash
# Run the platform
python3 main.py
```

## Security

SENTINNELLE v2.0 enforces fail-safe and defensive design:
- **Strict Validation**: All external inputs are validated before processing.
- **Credential Safety**: All API keys must be managed via `.env` files.
- **Async Robustness**: High-concurrency operations powered by `httpx` and `trio`.

---

**SENTINNELLE** - High-Assurance Intelligence for Lawful Use
