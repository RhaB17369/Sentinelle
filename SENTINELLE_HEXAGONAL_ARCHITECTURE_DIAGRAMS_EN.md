# SENTINELLE - HEXAGONAL ARCHITECTURE DIAGRAMS

**Classification:** CONFIDENTIAL  
**Project:** SENTINELLE OSINT/SIGINT Platform  
**Type:** Architectural Visual Diagrams  
**Date:** 2025-01-25  

---

## 1. GLOBAL HEXAGONAL ARCHITECTURE

```
                    ┌─────────────────────────────────────────┐
                    │              PRIMARY ACTORS             │
                    │                                         │
                    │  👤 OSINT Analyst     🖥️  CLI Interface │
                    │  🎯 SIGINT Operator   📊 TUI Dashboard  │
                    │  👨‍💼 SOC Commander     ⌨️  User Input     │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────┐
                    │           INTERFACE LAYER               │
                    │                                         │
                    │    ┌─────────────────────────────────┐  │
                    │    │   sentinelle-interface-cli     │  │
                    │    │                                 │  │
                    │    │  • Event Loop (Crossterm)      │  │
                    │    │  • UI Rendering (Ratatui)      │  │
                    │    │  • Input Validation            │  │
                    │    │  • Output Formatting           │  │
                    │    │  • Activity Logging            │  │
                    │    └─────────────────────────────────┘  │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────┐
                    │          APPLICATION LAYER              │
                    │                                         │
                    │    ┌─────────────────────────────────┐  │
                    │    │   sentinelle-application       │  │
                    │    │                                 │  │
                    │    │  📋 RunIpIntelligence          │  │
                    │    │  📧 RunMailScan                │  │
                    │    │  👥 RunSocialScan              │  │
                    │    │  🔍 RunDomainIntel             │  │
                    │    │  📞 RunPhoneIntel              │  │
                    │    │  🌐 RunEmailRecon              │  │
                    │    │  ⚡ RunSigintTcp/Icmp/Trace    │  │
                    │    │  📊 RunLatencyIntel            │  │
                    │    └─────────────────────────────────┘  │
                    └─────────────────┬───────────────────────┘
                                      │
        ┌─────────────────────────────▼─────────────────────────────┐
        │                    DOMAIN LAYER (HEXAGON)                 │
        │                                                           │
        │  ┌─────────────────────────────────────────────────────┐  │
        │  │              sentinelle-domain                      │  │
        │  │                                                     │  │
        │  │  🏛️ ENTITIES:                                        │  │
        │  │    • Entity (Intelligence Graph)                   │  │
        │  │    • Email (Value Object)                          │  │
        │  │    • PhoneNumber (Value Object)                    │  │
        │  │    • Confidence (Value Object)                     │  │
        │  │                                                     │  │
        │  │  🔌 PORTS (Interfaces):                            │  │
        │  │    • IpIntelligencePort                            │  │
        │  │    • MailIntelligencePort                          │  │
        │  │    • SocialIntelligencePort                        │  │
        │  │    • SigintTcp/Icmp/TraceroutePort                 │  │
        │  │    • DomainIntelligencePort                        │  │
        │  │    • EmailReconPort                                │  │
        │  │    • LatencyIntelligencePort                       │  │
        │  │    • PhoneIntelligencePort                         │  │
        │  │    • MetricsPort                                   │  │
        │  │                                                     │  │
        │  │  ⚖️ BUSINESS RULES:                                  │  │
        │  │    • Input validation                              │  │
        │  │    • Confidence logic                              │  │
        │  │    • Intelligence aggregation                      │  │
        │  └─────────────────────────────────────────────────────┘  │
        └─────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────▼─────────────────────────────┐
        │                INFRASTRUCTURE LAYER                       │
        │                                                           │
        │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
        │  │   OSINT     │  │   SIGINT    │  │    SUPPORT      │   │
        │  │  ADAPTERS   │  │  ADAPTERS   │  │   ADAPTERS      │   │
        │  │             │  │             │  │                 │   │
        │  │ 🌐 IP Intel │  │ ⚡ TCP Sig  │  │ 💾 SQLite Cache │   │
        │  │ 📧 Mail     │  │ 📡 ICMP Sig │  │ 📊 Metrics     │   │
        │  │ 👥 Social   │  │ 🛤️ Tracert  │  │ 🕸️ Graph       │   │
        │  │ 🔍 Domain   │  │ ⏱️ Latency  │  │                 │   │
        │  │ 📞 Phone    │  │             │  │                 │   │
        │  │ 🌐 EmailRec │  │             │  │                 │   │
        │  └─────────────┘  └─────────────┘  └─────────────────┘   │
        └─────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────┐
                    │           SECONDARY ACTORS              │
                    │                                         │
                    │  🌐 External APIs    📡 Raw Sockets     │
                    │  🗄️ Databases        🖥️ System Commands │
                    │  📁 Web Archives     🔍 DNS Resolvers    │
                    │  📊 Metrics Store    💾 File System     │
                    └─────────────────────────────────────────┘
```

---

## 2. HEXAGONAL DATA FLOW

```
┌─────────────────────────────────────────────────────────────────────┐
│                        OSINT/SIGINT FLOW                           │
└─────────────────────────────────────────────────────────────────────┘

INPUT (Primary Actor)
    │
    ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   VALIDATION    │───▶│   ORCHESTRATION  │───▶│   PORT SELECTION    │
│                 │    │                  │    │                     │
│ • Format Check  │    │ • Use Case Route │    │ • Interface Lookup │
│ • Security Val  │    │ • Dependency Inj │    │ • Contract Binding │
│ • Range Check   │    │ • Error Handling │    │ • Method Dispatch  │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
                                                          │
                                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    INFRASTRUCTURE EXECUTION                         │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │HTTP Clients │  │Raw Sockets  │  │System Cmds  │  │Local Storage│ │
│  │             │  │             │  │             │  │             │ │
│  │• IP-API     │  │• TCP SYN    │  │• Traceroute │  │• SQLite     │ │
│  │• GeoJS      │  │• ICMP Echo  │  │• Ping       │  │• Cache      │ │
│  │• CT Logs    │  │• Raw Probe  │  │• DNS Query  │  │• Activity   │ │
│  │• Archives   │  │• Packet Cap │  │• Whois      │  │• Metrics    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      RESULT PROCESSING                             │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   MERGE     │  │   ENRICH    │  │  VALIDATE   │  │   CACHE     │ │
│  │             │  │             │  │             │  │             │ │
│  │• Multi-Src  │  │• Metadata   │  │• Confidence │  │• Persist    │ │
│  │• Composite  │  │• Timestamp  │  │• Integrity  │  │• Key-Value  │ │
│  │• Fallback   │  │• Sources    │  │• Completeness│ │• Activity   │ │
│  │• Priority   │  │• Context    │  │• Consistency │  │• Metrics    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
OUTPUT (Primary Actor)
```

---

## 3. DETAILED LAYERED ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────┐
│                           LAYER 1: PRESENTATION                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                sentinelle-interface-cli                    │    │
│  │                                                             │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │    │
│  │  │    TUI      │  │   INPUT     │  │       OUTPUT        │ │    │
│  │  │             │  │             │  │                     │ │    │
│  │  │• Ratatui    │  │• Validation │  │• Table Rendering    │ │    │
│  │  │• Crossterm  │  │• Parsing    │  │• Scroll Support     │ │    │
│  │  │• Event Loop │  │• Sanitize   │  │• Filter/Search      │ │    │
│  │  │• Widgets    │  │• Transform  │  │• Export Formats     │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          LAYER 2: APPLICATION                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                sentinelle-application                       │    │
│  │                                                             │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │    │
│  │  │    OSINT    │  │   SIGINT    │  │      SUPPORT        │ │    │
│  │  │  USE CASES  │  │  USE CASES  │  │     USE CASES       │ │    │
│  │  │             │  │             │  │                     │ │    │
│  │  │• IP Intel   │  │• TCP Sigint │  │• Cache Management   │ │    │
│  │  │• Mail Scan  │  │• ICMP Sigint│  │• Metrics Collection │ │    │
│  │  │• Social Scan│  │• Traceroute │  │• Activity Logging   │ │    │
│  │  │• Domain Int │  │• Latency    │  │• Graph Building     │ │    │
│  │  │• Email Recon│  │             │  │                     │ │    │
│  │  │• Phone Intel│  │             │  │                     │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           LAYER 3: DOMAIN                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    sentinelle-domain                        │    │
│  │                                                             │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │    │
│  │  │  ENTITIES   │  │    PORTS    │  │    VALUE OBJECTS    │ │    │
│  │  │             │  │ (INTERFACES)│  │                     │ │    │
│  │  │• Entity     │  │• IpIntelPort│  │• Email              │ │    │
│  │  │• Relation   │  │• MailPort   │  │• PhoneNumber        │ │    │
│  │  │• Graph      │  │• SocialPort │  │• Confidence         │ │    │
│  │  │• Confidence │  │• SigintPorts│  │• AttributeValue     │ │    │
│  │  │             │  │• DomainPort │  │• EntityId           │ │    │
│  │  │             │  │• EmailPort  │  │• RelationType       │ │    │
│  │  │             │  │• PhonePort  │  │                     │ │    │
│  │  │             │  │• MetricPort │  │                     │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        LAYER 4: INFRASTRUCTURE                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                 sentinelle-infra-*                          │    │
│  │                                                             │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │    │
│  │  │    OSINT    │  │   SIGINT    │  │      SUPPORT        │ │    │
│  │  │  ADAPTERS   │  │  ADAPTERS   │  │     ADAPTERS        │ │    │
│  │  │             │  │             │  │                     │ │    │
│  │  │• osint-ip   │  │• latency-raw│  │• cache-sqlite       │ │    │
│  │  │• osint-mail │  │• latency-int│  │• metrics            │ │    │
│  │  │• osint-soc  │  │             │  │• graph              │ │    │
│  │  │• email-recon│  │             │  │                     │ │    │
│  │  │• domain-int │  │             │  │                     │ │    │
│  │  │• phone-int  │  │             │  │                     │ │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL SYSTEMS                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  WEB APIs   │  │   NETWORK   │  │   SYSTEM    │  │   STORAGE   │ │
│  │             │  │             │  │             │  │             │ │
│  │• IP-API     │  │• Raw Sockets│  │• Traceroute │  │• SQLite DB  │ │
│  │• GeoJS      │  │• TCP/ICMP   │  │• Ping Cmd   │  │• File System│ │
│  │• CT Logs    │  │• DNS Query  │  │• Whois Cmd  │  │• Memory     │ │
│  │• Archives   │  │• HTTP Req   │  │• System Info│  │• Cache      │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---
## 4. CLASSIC HEXAGONAL DIAGRAM

```
                                    👤 OSINT Analyst
                                           │
                                           ▼
                              ┌─────────────────────┐
                              │                     │
                              │    CLI Interface    │
                              │                     │
                              └─────────┬───────────┘
                                        │
                    🖥️ TUI Dashboard ────┤
                                        │
                              ┌─────────▼───────────┐
                              │                     │
                              │   APPLICATION       │
                              │    (Use Cases)      │
                              │                     │
                              └─────────┬───────────┘
                                        │
                                        ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                                                             │
        │                        DOMAIN                               │
        │                     (Hexagon)                               │
        │                                                             │
        │  ┌─────────────────────────────────────────────────────┐    │
        │  │                                                     │    │
        │  │  🏛️ Entities    🔌 Ports      ⚖️ Business Rules    │    │
        │  │                                                     │    │
        │  │  • Entity       • IpIntelPort   • Validation       │    │
        │  │  • Email        • MailPort      • Confidence       │    │
        │  │  • Phone        • SocialPort    • Aggregation      │    │
        │  │  • Graph        • SigintPorts   • Intelligence     │    │
        │  │                                                     │    │
        │  └─────────────────────────────────────────────────────┘    │
        │                                                             │
        └─────────────────────────────────────────────────────────────┘
                │                                           │
                ▼                                           ▼
    ┌─────────────────────┐                   ┌─────────────────────┐
    │                     │                   │                     │
    │   OSINT ADAPTERS    │                   │   SIGINT ADAPTERS   │
    │                     │                   │                     │
    │ • IP Intelligence   │                   │ • TCP Fingerprint   │
    │ • Mail OSINT        │                   │ • ICMP Probing      │
    │ • Social Scanning   │                   │ • Traceroute SIGINT │
    │ • Email Recon       │                   │ • Latency Analysis  │
    │ • Domain Intel      │                   │                     │
    │ • Phone Intel       │                   │                     │
    └─────────┬───────────┘                   └─────────┬───────────┘
              │                                         │
              ▼                                         ▼
    ┌─────────────────────┐                   ┌─────────────────────┐
    │                     │                   │                     │
    │   EXTERNAL APIs     │                   │   RAW SOCKETS       │
    │                     │                   │                     │
    │ 🌐 IP-API.com       │                   │ ⚡ TCP SYN Probe    │
    │ 🌐 GeoJS.io         │                   │ 📡 ICMP Echo        │
    │ 📜 CT Logs          │                   │ 🛤️ System Tracert   │
    │ 📁 Web Archives     │                   │ 🔍 DNS Queries      │
    └─────────────────────┘                   └─────────────────────┘
                │                                         │
                └─────────────────┬───────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │                             │
                    │      SUPPORT ADAPTERS       │
                    │                             │
                    │ 💾 SQLite Cache             │
                    │ 📊 Metrics Collection       │
                    │ 🕸️ Intelligence Graph       │
                    │ 📝 Activity Logging         │
                    └─────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │                             │
                    │      LOCAL STORAGE          │
                    │                             │
                    │ 🗄️ SQLite Database          │
                    │ 📁 File System              │
                    │ 🧠 Memory Cache             │
                    └─────────────────────────────┘
```

---

## 5. ARCHITECTURAL PATTERNS VISUALS

### 5.1 Composite Pattern (IP Intelligence)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    COMPOSITE IP INTELLIGENCE                        │
└─────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────┐
                    │                         │
                    │  CompositeIpIntelligence│
                    │                         │
                    │  + analyze_ip()         │
                    │  + merge_results()      │
                    │  + fallback_strategy()  │
                    └─────────┬───────────────┘
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
    ┌─────────────────────┐     ┌─────────────────────┐
    │                     │     │                     │
    │    IpApiClient      │     │     GeoJsClient     │
    │                     │     │                     │
    │ • Primary Provider  │     │ • Fallback Provider │
    │ • High Accuracy     │     │ • Backup Source     │
    │ • Rate Limited      │     │ • Alternative Data  │
    │ • JSON Response     │     │ • JSON Response     │
    └─────────┬───────────┘     └─────────┬───────────┘
              │                           │
              ▼                           ▼
    ┌─────────────────────┐     ┌─────────────────────┐
    │                     │     │                     │
    │   IP-API.com        │     │     GeoJS.io        │
    │                     │     │                     │
    │ GET /json/{ip}      │     │ GET /v1/ip/{ip}     │
    │ • Country, City     │     │ • Geolocation       │
    │ • ISP, ASN          │     │ • Timezone          │
    │ • Coordinates       │     │ • Organization      │
    └─────────────────────┘     └─────────────────────┘

FLOW:
1. Request → CompositeIpIntelligence
2. Try IpApiClient (Primary)
3. If success → Merge with GeoJsClient (Enhancement)
4. If failure → Fallback to GeoJsClient only
5. Return aggregated IpIntelligence
```

### 5.2 Probe Pattern (Mail OSINT)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PROBE PATTERN - MAIL OSINT                  │
└─────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────┐
                    │                         │
                    │    MailOsintEngine      │
                    │                         │
                    │  + scan_email()         │
                    │  + aggregate_results()  │
                    │  + parallel_probing()   │
                    └─────────┬───────────────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
                ▼             ▼             ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │                 │ │             │ │                 │
    │   Gmail Probe   │ │ Yahoo Probe │ │ Outlook Probe   │
    │                 │ │             │ │                 │
    │ • Check Exist   │ │ • Verify    │ │ • Account Test  │
    │ • Recovery Info │ │ • Profile   │ │ • Service Check │
    │ • Rate Limit    │ │ • Rate Limit│ │ • Rate Limit    │
    └─────────┬───────┘ └─────┬───────┘ └─────────┬───────┘
              │               │                   │
              ▼               ▼                   ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │                 │ │             │ │                 │
    │  Gmail Service  │ │Yahoo Service│ │ Outlook Service │
    │                 │ │             │ │                 │
    │ accounts.google │ │ login.yahoo │ │ login.live.com  │
    │ • Forgot Pass   │ │ • Forgot    │ │ • Account Check │
    │ • Account Rec   │ │ • Recovery  │ │ • Password Rec  │
    └─────────────────┘ └─────────────┘ └─────────────────┘

PARALLEL EXECUTION:
┌─────────────────────────────────────────────────────────────────────┐
│  Email Input: user@example.com                                     │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │   Probe 1   │  │   Probe 2   │  │   Probe 3   │                │
│  │             │  │             │  │             │                │
│  │ ⏱️ 2.3s      │  │ ⏱️ 1.8s      │  │ ⏱️ 3.1s      │                │
│  │ ✅ Found     │  │ ❌ Not Found │  │ ✅ Found     │                │
│  │ 📧 Recovery  │  │             │  │ 📞 Phone     │                │
│  └─────────────┘  └─────────────┘  └─────────────┘                │
│                                                                     │
│  Result: MailScanSummary {                                          │
│    email: user@example.com,                                        │
│    services: [                                                     │
│      { service: "Gmail", exists: true, recovery: "u***@***.com" }, │
│      { service: "Yahoo", exists: false },                          │
│      { service: "Outlook", exists: true, phone: "+1***-***-1234" } │
│    ]                                                               │
│  }                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 Strategy Pattern (Traceroute SIGINT)

```
┌─────────────────────────────────────────────────────────────────────┐
│                   STRATEGY PATTERN - TRACEROUTE SIGINT             │
└─────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────┐
                    │                         │
                    │ TracerouteSigintEngine  │
                    │                         │
                    │  + trace()              │
                    │  + select_strategy()    │
                    │  + enrich_hops()        │
                    └─────────┬───────────────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
                ▼             ▼             ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │                 │ │             │ │                 │
    │ System Strategy │ │ ASN Strategy│ │  IXP Strategy   │
    │                 │ │             │ │                 │
    │ • traceroute    │ │ • Team Cymru│ │ • Pattern Match │
    │ • tracert (Win) │ │ • DNS Lookup│ │ • Name Analysis │
    │ • Raw Output    │ │ • BGP Data  │ │ • IXP Detection │
    └─────────┬───────┘ └─────┬───────┘ └─────────┬───────┘
              │               │                   │
              ▼               ▼                   ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │                 │ │             │ │                 │
    │ System Command  │ │ DNS Resolver│ │ Pattern Engine  │
    │                 │ │             │ │                 │
    │ traceroute -n   │ │ *.origin.   │ │ "ixp", "ix",    │
    │ -m 30 target    │ │ asn.cymru   │ │ "exchange",     │
    │                 │ │ .com        │ │ "peering"       │
    └─────────────────┘ └─────────────┘ └─────────────────┘

EXECUTION FLOW:
┌─────────────────────────────────────────────────────────────────────┐
│  Target: 8.8.8.8                                                   │
│                                                                     │
│  Step 1: System Traceroute                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ 1  192.168.1.1     1.234 ms                                │   │
│  │ 2  10.0.0.1        5.678 ms                                │   │
│  │ 3  203.0.113.1    12.345 ms                                │   │
│  │ 4  8.8.8.8        15.678 ms                                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Step 2: ASN Enrichment (Team Cymru)                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ 192.168.1.1 → Private Network                              │   │
│  │ 10.0.0.1    → Private Network                              │   │
│  │ 203.0.113.1 → AS64512 | US | Example ISP                  │   │
│  │ 8.8.8.8     → AS15169 | US | Google LLC                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Step 3: IXP Detection                                              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ No IXP patterns detected in AS names                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Result: NetworkPathIntel {                                         │
│    target: 8.8.8.8,                                                │
│    hops: [TracerouteHopDetail...],                                  │
│    as_path: ["AS64512", "AS15169"],                                 │
│    ixps: []                                                         │
│  }                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. DEPLOYMENT DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DEPLOYMENT ENVIRONMENT                       │
└─────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────┐
                    │                         │
                    │    ANALYST WORKSTATION  │
                    │                         │
                    │ 🖥️ Linux Workstation    │
                    │ 🔐 Secure Access        │
                    │ 🛡️ Local Firewall       │
                    └─────────┬───────────────┘
                              │
                              ▼
                    ┌─────────────────────────┐
                    │                         │
                    │   SENTINELLE BINARY     │
                    │                         │
                    │ 📦 sentinelle-bin       │
                    │ ⚡ Rust Native           │
                    │ 🔧 Single Executable    │
                    │ 💾 ~50MB Size           │
                    └─────────┬───────────────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
                ▼             ▼             ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │                 │ │             │ │                 │
    │  LOCAL STORAGE  │ │  NETWORK    │ │  SYSTEM ACCESS  │
    │                 │ │   ACCESS    │ │                 │
    │ 💾 SQLite DB    │ │ 🌐 HTTPS    │ │ 🔧 Raw Sockets  │
    │ 📁 Cache Files  │ │ 🔍 DNS      │ │ ⚡ CAP_NET_RAW   │
    │ 📊 Metrics     │ │ 📡 TCP/ICMP │ │ 🖥️ System Cmds   │
    │ 📝 Activity Log │ │             │ │                 │
    └─────────┬───────┘ └─────┬───────┘ └─────────┬───────┘
              │               │                   │
              ▼               ▼                   ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │                 │ │             │ │                 │
    │ File System     │ │ Internet    │ │ Kernel Access   │
    │                 │ │             │ │                 │
    │ /var/sentinelle │ │ External    │ │ Privileged Ops  │
    │ ~/.cache/sent   │ │ APIs        │ │ Network Stack   │
    │ /tmp/sent_*     │ │ Public DNS  │ │ Process Control │
    └─────────────────┘ └─────────────┘ └─────────────────┘

SECURITY:
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  🔒 ACCESS CONTROLS:                                                │
│    • Strict input validation                                       │
│    • Private IP range filtering                                    │
│    • Allowed character limitation                                  │
│    • Timeout on all network operations                             │
│                                                                     │
│  🛡️ ISOLATION:                                                      │
│    • No credential storage                                         │
│    • Local cache only                                              │
│    • No sensitive data transmission                                │
│    • Activity logs for audit                                       │
│                                                                     │
│  ⚡ PRIVILEGES:                                                      │
│    • CAP_NET_RAW for SIGINT TCP/ICMP                              │
│    • Validation before access attempt                              │
│    • Graceful degradation if insufficient privileges               │
│    • No automatic escalation                                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. COMMUNICATION DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INTER-MODULE COMMUNICATION                       │
└─────────────────────────────────────────────────────────────────────┘

CLI Interface
    │
    │ 1. User Input
    ▼
┌─────────────────┐
│   Validation    │ ──── 2. Parse & Validate ────┐
└─────────────────┘                               │
    │                                             │
    │ 3. Valid Input                              │
    ▼                                             ▼
┌─────────────────┐                         ┌─────────────┐
│   Use Case      │ ──── 4. Port Lookup ───▶│   Domain    │
│  Orchestrator   │                         │   Registry  │
└─────────────────┘                         └─────────────┘
    │                                             │
    │ 5. Port Reference                           │
    ▼                                             │
┌─────────────────┐                              │
│ Infrastructure  │ ◀──── 6. Contract ───────────┘
│    Adapter      │
└─────────────────┘
    │
    │ 7. External Call
    ▼
┌─────────────────┐
│ External System │
│  (API/Socket)   │
└─────────────────┘
    │
    │ 8. Response
    ▼
┌─────────────────┐
│ Infrastructure  │
│    Adapter      │
└─────────────────┘
    │
    │ 9. Domain Object
    ▼
┌─────────────────┐
│   Use Case      │
│  Orchestrator   │
└─────────────────┘
    │
    │ 10. Result
    ▼
┌─────────────────┐
│      Cache      │ ──── 11. Persist ────┐
└─────────────────┘                       │
    │                                     │
    │ 12. Cached Result                   ▼
    ▼                               ┌─────────────┐
┌─────────────────┐                 │   SQLite    │
│ CLI Interface   │                 │  Database   │
└─────────────────┘                 └─────────────┘
    │                                     │
    │ 13. Render Output                   │
    ▼                                     │
┌─────────────────┐                      │
│   TUI Display   │                      │
└─────────────────┘                      │
    │                                     │
    │ 14. Log Activity                    │
    ▼                                     │
┌─────────────────┐                      │
│ Activity Logger │ ──── 15. Store ──────┘
└─────────────────┘

MESSAGE TYPES:
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  📨 COMMAND MESSAGES:                                               │
│    • ValidateInput(String)                                         │
│    • ExecuteUseCase(UseCaseType, Input)                            │
│    • CallPort(PortType, Method, Args)                              │
│    • StoreResult(Key, Value)                                       │
│                                                                     │
│  📬 EVENT MESSAGES:                                                 │
│    • InputValidated(ValidInput)                                    │
│    • UseCaseCompleted(Result)                                      │
│    • PortCallSucceeded(Output)                                     │
│    • PortCallFailed(Error)                                         │
│    • ResultCached(CacheKey)                                        │
│    • ActivityLogged(Event)                                         │
│                                                                     │
│  📋 QUERY MESSAGES:                                                 │
│    • GetCachedResult(Key)                                          │
│    • GetRecentActivity(Limit)                                      │
│    • GetMetrics(Provider)                                          │
│    • GetPortImplementation(PortType)                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

**END OF DIAGRAMS**

These visual diagrams illustrate the strict hexagonal architecture of the Sentinelle project with:

1. **Hexagonal overview** - Global architecture with primary/secondary actors
2. **Data flow** - Complete OSINT/SIGINT pipeline
3. **Layered architecture** - Strict responsibility separation
4. **Classic hexagon** - Traditional ports & adapters representation
5. **Architectural patterns** - Composite, Probe, Strategy in detail
6. **Deployment** - Execution environment and security
7. **Communication** - Messages and inter-module interactions

The architecture perfectly respects hexagonal principles with clear separation between business domain (central hexagon) and infrastructure adapters (hexagon sides).

---