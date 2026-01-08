# SENTINNELLE Intelligence System

**Production-grade OSINT intelligence platform for lawful intelligence gathering**

[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()
[![C++](https://img.shields.io/badge/C++-17-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)]()

## Overview

SENTINNELLE is a defense-grade, high-assurance OSINT (Open-Source Intelligence) platform designed to generate actionable, explainable intelligence from lawful public data sources. The system operates under strict ethical and legal boundaries, refusing any requests for illegal surveillance, unauthorized access, or harassment.

### Key Features

- **Multi-Source Intelligence**: Correlates data from WHOIS, DNS, SSL certificates, geolocation, and more
- **Confidence Scoring**: Bayesian confidence estimation with source reliability weighting
- **Explainability**: Complete reasoning paths with evidence chains and source attribution
- **Graph-Based Modeling**: NetworkX-powered intelligence graph with temporal relationships
- **Ethical Boundaries**: Explicit refusal of illegal or unethical queries
- **Security-First**: Memory-safe C++ core with input validation and cryptographic integrity
- **Production-Ready**: Comprehensive testing, fuzzing, and validation

### Supported Query Types

1. **Domains/Websites**: WHOIS, DNS, SSL certificates, HTTP headers, technology detection
2. **IP Addresses**: ASN, geolocation, reverse DNS, network information
3. **Persons** (OSINT only): Public digital footprint, breach exposure
4. **Locations**: Geocoding, reverse geocoding, geospatial data
5. **Phone Numbers**: Carrier, country, timezone, number type

## Architecture

SENTINNELLE uses a hybrid C++/Python architecture:

- **C++ Core**: Performance-critical operations (HTTP client, parsers, crypto, validation)
- **Python Intelligence Layer**: Correlation, confidence scoring, graph modeling, explainability
- **pybind11 Bindings**: Seamless C++↔Python integration

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## Installation

### Prerequisites

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Compiler**: GCC 9+ or Clang 10+
- **Python**: 3.8+
- **CMake**: 3.15+

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    python3-dev \
    python3-pip

# RHEL/CentOS
sudo yum install -y \
    gcc-c++ \
    cmake \
    openssl-devel \
    libcurl-devel \
    libxml2-devel \
    python3-devel
```

### Build and Install

```bash
# Clone repository
cd /home/bazooka/Desktop/sentinelle

# Install Python dependencies
pip3 install -r requirements.txt

# Build C++ components
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run tests
ctest --output-on-failure

# Install Python module
cd ..
pip3 install -e .
```

## Usage

### Command-Line Interface

```bash
# Query a domain
python3 main.py example.com

# Query an IP address
python3 main.py 8.8.8.8

# Query a phone number
python3 main.py "+14155552671"

# JSON output
python3 main.py example.com --format json

# Set minimum confidence threshold
python3 main.py example.com --min-confidence 0.7

# Verbose logging
python3 main.py example.com --verbose
```

### Example Output

```
================================================================================
SENTINNELLE INTELLIGENCE REPORT
================================================================================

Query: example.com
Type: domain
Target: example.com
Timestamp: 2025-12-13T13:30:00

--------------------------------------------------------------------------------
CONFIDENCE ASSESSMENT
--------------------------------------------------------------------------------
Score: 0.87
Justification: High confidence based on 3 sources with strong agreement
(primary sources: whois, dns, ssl_cert).

--------------------------------------------------------------------------------
INTELLIGENCE DATA
--------------------------------------------------------------------------------
whois:
  registrar: Example Registrar Inc.
  creation_date: 1995-08-14
  expiration_date: 2025-08-13
  
dns:
  A: ['93.184.216.34']
  AAAA: ['2606:2800:220:1:248:1893:25c8:1946']
  MX: ['0 .]
  
ssl_certificate:
  subject: {'commonName': 'www.example.org'}
  issuer: {'organizationName': 'DigiCert Inc'}
  not_after: 2026-01-01

--------------------------------------------------------------------------------
EXPLAINABILITY
--------------------------------------------------------------------------------
Conclusion: Intelligence gathered on example.com (domain)

Evidence Chain:
  1. direct_observation: Observed: whois data
     Confidence: 0.95
     Sources: domain_collector
  2. direct_observation: Observed: DNS records
     Confidence: 0.95
     Sources: domain_collector

================================================================================
```

## Configuration

Copy `.env.example` to `.env` and configure API keys:

```bash
cp .env.example .env
```

Edit `.env`:
```
HIBP_API_KEY=your_haveibeenpwned_api_key
```

## Testing

### Run All Tests

```bash
# C++ tests
cd build
ctest --output-on-failure

# Python tests
pytest tests/python/ -v

# Integration tests
pytest tests/integration/ -v
```

### Fuzzing (Optional, requires Clang)

```bash
cd build
cmake .. -DBUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
make fuzz_parsers
./fuzz_parsers -max_total_time=300
```

## Security

SENTINNELLE is designed with security-by-construction principles:

- **Memory Safety**: RAII, smart pointers, bounds-checked containers
- **Input Validation**: All external inputs validated before processing
- **Cryptographic Integrity**: SHA-256/512, HMAC using OpenSSL
- **TLS Enforcement**: TLS 1.2+ required for all HTTPS connections
- **Secure Compilation**: Stack protector, PIE, FORTIFY_SOURCE

See [SECURITY.md](SECURITY.md) for detailed security documentation.

## Limitations

See [LIMITATIONS.md](LIMITATIONS.md) for complete list of system limitations and prohibited uses.

**Key Limitations:**
- OSINT only (no access to non-public data)
- API rate limits apply
- IP geolocation is probabilistic (city-level at best)
- Person intelligence limited to public digital footprint

## Legal and Ethical Constraints

**SENTINNELLE OPERATES UNDER STRICT LEGAL AND ETHICAL BOUNDARIES:**

✅ **Permitted:**
- Lawful OSINT intelligence gathering
- Public data source analysis
- Security research and threat intelligence
- Compliance and audit investigations

❌ **Prohibited:**
- Illegal surveillance or stalking
- Unauthorized system access
- Harassment or doxxing
- Circumventing access controls
- Any use violating applicable law

**All queries are logged for accountability and compliance audits.**

## License

Proprietary. All rights reserved.

## Support

For issues, questions, or security concerns, contact the development team.

---

**SENTINNELLE** - High-Assurance Intelligence for Lawful Use
