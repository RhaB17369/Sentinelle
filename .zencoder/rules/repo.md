---
description: Repository Information Overview
alwaysApply: true
---

# SENTINNELLE Intelligence System Information

## Summary
SENTINNELLE is a production-grade OSINT (Open-Source Intelligence) platform designed for lawful intelligence gathering. It uses a hybrid architecture with a high-performance C++ core for security-critical operations and a Python intelligence layer for data correlation, graph modeling, and confidence scoring.

## Structure
- **cli/**: Main entry point and CLI implementation (UI, modules, runner).
- **collectors/**: Specialized modules for data acquisition (WHOIS, DNS, IP, Geolocation).
- **core/**: Memory-safe C++ implementation of cryptographic functions and input validation.
- **ingest/**: C++ layer for high-performance HTTP communication and data parsing.
- **intelligence/**: Python layer for entity resolution, blockchain analysis, and graph-based modeling.
- **engine_mail_collector/**: Deep email OSINT engine with platform-specific detectors.
- **phone_location/**: Phone number intelligence and geolocation modules.
- **scanners/**: Network and vulnerability scanning capabilities.
- **bindings/**: pybind11 definitions for C++ and Python integration.
- **tests/**: Multi-layered testing suite including C++ unit tests, Python unit tests, and integration tests.

## Language & Runtime
**Language**: Python, C++  
**Version**: Python 3.8+, C++17  
**Build System**: CMake (C++), Pip (Python)  
**Package Manager**: pip

## Dependencies
**Main Dependencies**:
- **Python**: `networkx`, `python-whois`, `dnspython`, `phonenumbers`, `requests`, `ipwhois`, `httpx`, `trio`, `rich`, `tqdm`, `opencage`, `cryptography`.
- **C++**: `OpenSSL`, `libcurl`, `libxml2`, `nlohmann/json`, `pybind11`.

**Development Dependencies**:
- `pytest`, `pytest-cov`, `googletest`.

## Build & Installation
```bash
# Install system dependencies (Debian/Ubuntu)
sudo apt-get install build-essential cmake libssl-dev libcurl4-openssl-dev libxml2-dev python3-dev

# Install Python dependencies
pip3 install -r requirements.txt

# Build C++ components
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install as editable package
cd ..
pip3 install -e .
```

## Main Files & Resources
- **CLI Wrapper**: `sentinelle_cli.py`
- **Main App**: `cli/core/app.py`
- **C++ Core**: `core/crypto.cpp`, `core/validation.cpp`
- **Configuration**: `.env.example` (copy to `.env`)

## Testing
**Framework**: Pytest (Python), Google Test (C++)  
**Test Location**: `tests/python/`, `tests/cpp/`, `tests/integration/`  
**Naming Convention**: `test_*.py` (Python), `test_*.cpp` (C++)  

**Run Command**:
```bash
# Python tests
pytest tests/python/ -v

# C++ tests
cd build && ctest --output-on-failure

# Integration tests
pytest tests/integration/ -v
```
