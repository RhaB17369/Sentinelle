# SENTINNELLE System Limitations

## Technical Limitations

### 1. Data Source Constraints

#### OSINT Only
- **Limitation**: System can ONLY access publicly available, lawful data sources
- **Impact**: Cannot access:
  - Non-public databases
  - Proprietary commercial data (without license)
  - Government-restricted information
  - Data requiring authentication/authorization
- **Mitigation**: None - this is a fundamental design constraint

#### API Dependencies
- **Limitation**: Relies on third-party APIs (WHOIS, DNS, geolocation, etc.)
- **Impact**: 
  - Subject to API rate limits
  - Service availability dependencies
  - Data quality varies by provider
  - Some APIs require paid subscriptions
- **Mitigation**: Implement caching, rate limiting, fallback providers

### 2. Accuracy and Precision

#### IP Geolocation
- **Limitation**: IP geolocation is probabilistic, not deterministic
- **Accuracy**: City-level at best, often only country/region level
- **Impact**: Cannot reliably determine exact physical location from IP
- **Confidence**: Marked as "probabilistic" in all reports
- **Mitigation**: Cross-reference with other data sources, clearly state uncertainty

#### WHOIS Data
- **Limitation**: WHOIS data may be:
  - Redacted due to GDPR/privacy regulations
  - Outdated or stale
  - Protected by privacy services
- **Impact**: Limited ownership information for many domains
- **Mitigation**: Use multiple data sources, note data freshness

#### Person Intelligence
- **Limitation**: Limited to public digital footprint only
- **Impact**: Cannot access:
  - Private social media profiles
  - Non-public records
  - Real-time location data
  - Financial information
- **Mitigation**: None - ethical and legal constraint

### 3. Real-Time Constraints

#### Data Freshness
- **Limitation**: Some data sources have update delays
- **Examples**:
  - WHOIS: Updated periodically, not real-time
  - DNS: TTL-dependent caching
  - Geolocation databases: Updated monthly/quarterly
- **Impact**: Intelligence may not reflect current state
- **Mitigation**: Timestamp all data, implement freshness decay in confidence scoring

#### Rate Limiting
- **Limitation**: External APIs enforce rate limits
- **Examples**:
  - Nominatim (OSM): 1 request/second
  - HaveIBeenPwned: Requires API key for automation
  - DNS: May be rate-limited by resolver
- **Impact**: Queries may take longer or fail under high load
- **Mitigation**: Implement request queuing, caching, backoff strategies

### 4. Coverage Limitations

#### Geographic Coverage
- **Limitation**: Data quality varies by region
- **Impact**: 
  - Better coverage for US/EU than other regions
  - Some countries have restricted WHOIS data
  - Geolocation accuracy varies by country
- **Mitigation**: Clearly indicate confidence levels, note regional limitations

#### Historical Data
- **Limitation**: Limited access to historical intelligence
- **Impact**: Cannot reliably track changes over time without continuous monitoring
- **Mitigation**: Implement local caching and historical tracking where permitted

### 5. Performance Constraints

#### Query Latency
- **Limitation**: Multi-source queries require multiple API calls
- **Typical Latency**: 5-30 seconds per query depending on sources
- **Impact**: Not suitable for real-time, high-throughput scenarios
- **Mitigation**: Implement async queries, caching, batch processing

#### Scalability
- **Limitation**: Single-instance deployment
- **Impact**: Limited concurrent query capacity
- **Mitigation**: Deploy multiple instances, implement load balancing

## Legal and Ethical Limitations

### 1. Prohibited Use Cases

**SENTINNELLE EXPLICITLY REFUSES:**

- ❌ Illegal surveillance or stalking
- ❌ Unauthorized access to systems or accounts
- ❌ Harassment, doxxing, or intimidation
- ❌ Circumventing access controls or security measures
- ❌ Collection of sensitive personal data (SSN, credit cards, medical records)
- ❌ Any use violating local, state, federal, or international law

### 2. Compliance Requirements

#### Data Protection
- **GDPR**: System respects GDPR-redacted WHOIS data
- **CCPA**: Complies with California privacy regulations
- **Impact**: Reduced data availability for EU/California entities

#### Terms of Service
- **Limitation**: Must comply with all third-party API terms of service
- **Impact**: Some use cases may be prohibited by upstream providers
- **Mitigation**: Review and comply with all API ToS

### 3. Ethical Constraints

#### Consent
- **Limitation**: No collection of data requiring individual consent
- **Impact**: Cannot access private social media, personal communications
- **Principle**: Respect for privacy and autonomy

#### Transparency
- **Requirement**: All intelligence must be explainable and auditable
- **Impact**: Cannot use "black box" data sources
- **Principle**: Accountability and transparency

## Known Bugs and Issues

### Current Issues
- None reported (initial release)

### Future Enhancements
- Historical intelligence tracking
- Additional OSINT sources (Shodan, VirusTotal, etc.)
- Machine learning for entity resolution
- Real-time monitoring capabilities

## Unsupported Features

The following features are **NOT** supported and **WILL NOT** be implemented:

1. **Active Reconnaissance**: No port scanning, vulnerability scanning, or active probing
2. **Credential Testing**: No password checking, credential stuffing, or authentication attempts
3. **Social Engineering**: No impersonation, phishing, or deceptive practices
4. **Data Exfiltration**: No unauthorized data extraction or scraping
5. **Malware Analysis**: No malware execution or dynamic analysis (use dedicated sandboxes)

## Disclaimer

**SENTINNELLE is provided "AS IS" without warranty of any kind.**

- **Accuracy**: Intelligence is provided on a best-effort basis. Accuracy is not guaranteed.
- **Completeness**: Data may be incomplete, outdated, or unavailable.
- **Liability**: Users are responsible for verifying intelligence before taking action.
- **Legal Compliance**: Users must ensure their use complies with all applicable laws.

**Use at your own risk. The developers assume no liability for misuse or damages.**

## Reporting Limitations

If you encounter a limitation not documented here, please report it to the development team with:

1. Description of the limitation
2. Expected vs. actual behavior
3. Impact on your use case
4. Suggested mitigation (if any)

---

**Last Updated**: 2025-12-13
