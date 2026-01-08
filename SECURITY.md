# SENTINNELLE Security Documentation

## Security Model

SENTINNELLE is designed with **security-by-construction** and **defense-in-depth** principles.

### Threat Model

**Assumed Adversaries:**
- APT-level threat actors
- Malicious OSINT data sources
- Injection attacks via query inputs
- Memory corruption exploits
- Timing attacks on cryptographic operations

**Assets to Protect:**
- System integrity and availability
- User query privacy (audit logs)
- API keys and credentials
- Intelligence data accuracy

## Security Architecture

### 1. Memory Safety (C++ Components)

#### RAII and Smart Pointers
- **All heap allocations** use RAII wrappers or smart pointers
- **No raw pointers** for ownership
- **Automatic cleanup** prevents memory leaks

```cpp
// Example: SecureBuffer with automatic zeroization
SecureBuffer buf(32);  // Automatically zeroized on destruction
```

#### Bounds Checking
- All array/vector access is bounds-checked
- Input size limits enforced (10 MB max for parsers)
- No buffer overflows possible

#### No Undefined Behavior
- All code paths handle errors explicitly
- No uninitialized variables
- No signed integer overflow
- No null pointer dereferences

### 2. Input Validation

**All external inputs are validated before processing:**

#### URL Validation
- RFC 3986 compliance
- Maximum length: 2048 characters
- Scheme whitelist: http, https, ftp
- Prevents SSRF via validation

#### IP Address Validation
- IPv4/IPv6 format validation using `inet_pton`
- Prevents injection attacks

#### Domain Validation
- RFC 1035 compliance
- Label length limits (63 chars)
- Total length limit (253 chars)
- Prevents DNS rebinding

#### Query Validation
- Maximum length: 1024 characters
- Null byte detection
- Control character filtering
- Prohibited pattern detection

### 3. Cryptographic Operations

#### Hash Functions
- **SHA-256** and **SHA-512** using OpenSSL
- No custom crypto implementations
- Constant-time comparisons using `CRYPTO_memcmp`

#### HMAC
- **HMAC-SHA256** for message authentication
- Secure key handling with zeroization

#### Secure Memory
- Explicit zeroization using `OPENSSL_cleanse`
- Prevents secrets from remaining in memory
- Protected against compiler optimization

```cpp
void SecureBuffer::zero() {
    if (data_) {
        OPENSSL_cleanse(data_, size_);  // Guaranteed zeroization
        delete[] data_;
    }
}
```

### 4. Network Security

#### TLS/SSL
- **TLS 1.2+ enforced** for all HTTPS connections
- Certificate validation enabled by default
- No support for SSLv2, SSLv3, TLS 1.0, TLS 1.1

```cpp
curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
```

#### Rate Limiting
- Configurable per-client rate limiting
- Prevents abuse of external APIs
- Respects upstream rate limits

#### Timeout Controls
- Connection timeout: 10 seconds
- Total request timeout: 30 seconds
- Prevents resource exhaustion

### 5. Compilation Security

#### Security Flags
```cmake
-fstack-protector-strong  # Stack canaries
-D_FORTIFY_SOURCE=2       # Buffer overflow detection
-fPIE -pie                # Position-independent executable
-Wformat -Wformat-security # Format string protection
-Wall -Wextra -Werror     # All warnings as errors
```

#### Address Space Layout Randomization (ASLR)
- PIE compilation enables ASLR
- Makes exploitation more difficult

### 6. Dependency Security

#### Vetted Libraries Only
- **OpenSSL**: Industry-standard cryptography
- **libcurl**: Widely-used HTTP client
- **libxml2**: Secure XML/HTML parsing with options
- **nlohmann/json**: Header-only JSON library
- **pybind11**: C++/Python bindings

#### XML/HTML Parsing Security
```cpp
int options = XML_PARSE_NONET     // No network access
            | XML_PARSE_NOENT     // No entity expansion
            | XML_PARSE_NOCDATA;  // No CDATA sections
```

Prevents:
- XML External Entity (XXE) attacks
- Billion laughs attack
- Network-based attacks

### 7. Audit Logging

#### Query Logging
- All queries logged with timestamps
- User identification (if applicable)
- Query type and target
- Success/failure status

#### Access Logging
- All external API calls logged
- Source attribution for intelligence
- Enables forensic analysis

#### Tamper-Evident Logs
- Logs include cryptographic hashes
- Sequential integrity verification
- Detects log tampering

### 8. Ethical Boundary Enforcement

#### Prohibited Query Detection
```python
PROHIBITED_PATTERNS = [
    r'hack\s+into',
    r'unauthorized\s+access',
    r'steal\s+',
    # ... more patterns
]
```

- Regex-based detection of illegal queries
- Explicit refusal with clear messaging
- Logged for compliance audits

#### Data Minimization
- Only collect necessary intelligence
- No storage of sensitive personal data
- Respect GDPR/CCPA redactions

## Security Testing

### 1. Unit Tests
- All security-critical functions tested
- Edge cases and error conditions covered
- Regression tests for known vulnerabilities

### 2. Fuzzing
- libFuzzer integration for parsers
- Continuous fuzzing of input handlers
- Detects memory corruption bugs

```bash
./fuzz_parsers -max_total_time=300
```

### 3. Static Analysis
- Compiler warnings as errors
- Clang-tidy for code quality
- ASAN/UBSAN for runtime checks

### 4. Penetration Testing
- Regular security audits recommended
- Red team testing for production deployments
- Vulnerability disclosure program

## Incident Response

### Vulnerability Reporting

**If you discover a security vulnerability:**

1. **DO NOT** publicly disclose the vulnerability
2. Email security contact with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. Allow reasonable time for patching (90 days)

### Security Updates

- Security patches released as soon as possible
- Critical vulnerabilities: 24-48 hour response
- Users notified via security advisories

## Compliance

### Standards Alignment
- **NIST Cybersecurity Framework**: Aligned with core functions
- **OWASP Top 10**: Mitigations for common web vulnerabilities
- **CWE Top 25**: Protections against common weaknesses

### Data Protection
- **GDPR**: Respects privacy regulations
- **CCPA**: Complies with California privacy law
- **HIPAA**: Not applicable (no health data)

## Security Checklist for Deployment

- [ ] Use strong API keys (minimum 32 characters)
- [ ] Store API keys in environment variables, not code
- [ ] Enable audit logging
- [ ] Review and restrict file permissions
- [ ] Run with least privilege (non-root user)
- [ ] Keep dependencies updated
- [ ] Monitor for security advisories
- [ ] Implement rate limiting for public-facing deployments
- [ ] Use HTTPS for all external communications
- [ ] Regular security audits and penetration testing

## Known Security Limitations

1. **Python Components**: Less memory-safe than C++, but mitigated by input validation
2. **Third-Party APIs**: Trust in upstream providers required
3. **Timing Attacks**: Some operations may leak timing information
4. **Side Channels**: Cache timing not fully mitigated

## Future Security Enhancements

- [ ] Hardware security module (HSM) integration for key storage
- [ ] Secure enclave support (Intel SGX, ARM TrustZone)
- [ ] Formal verification of critical components
- [ ] Continuous fuzzing infrastructure
- [ ] Bug bounty program

---

**Security is a continuous process. Stay vigilant.**

**Last Updated**: 2025-12-13
