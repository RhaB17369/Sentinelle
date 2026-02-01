# SENTINELLE - DIAGRAMMES ARCHITECTURE HEXAGONALE

**Classification:** CONFIDENTIEL DÉFENSE  
**Projet:** SENTINELLE OSINT/SIGINT Platform  
**Type:** Diagrammes Architecturaux Visuels  
**Date:** 2025-01-25  

---

## 1. ARCHITECTURE HEXAGONALE GLOBALE

```
                    ┌─────────────────────────────────────────┐
                    │              ACTEURS PRIMAIRES          │
                    │                                         │
                    │  👤 Analyste OSINT    🖥️  CLI Interface │
                    │  🎯 Opérateur SIGINT   📊 TUI Dashboard  │
                    │  👨‍💼 Commandant SOC    ⌨️  User Input     │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────┐
                    │           COUCHE INTERFACE              │
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
                    │          COUCHE APPLICATION             │
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
        │                    COUCHE DOMAINE (HEXAGONE)              │
        │                                                           │
        │  ┌─────────────────────────────────────────────────────┐  │
        │  │              sentinelle-domain                      │  │
        │  │                                                     │  │
        │  │  🏛️ ENTITÉS:                                        │  │
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
        │  │  ⚖️ RÈGLES MÉTIER:                                  │  │
        │  │    • Validation des entrées                        │  │
        │  │    • Logique de confiance                          │  │
        │  │    • Agrégation d'intelligence                     │  │
        │  └─────────────────────────────────────────────────────┘  │
        └─────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────▼─────────────────────────────┐
        │                COUCHE INFRASTRUCTURE                      │
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
                    │           ACTEURS SECONDAIRES           │
                    │                                         │
                    │  🌐 APIs Externes    📡 Raw Sockets     │
                    │  🗄️ Bases de Données 🖥️ System Commands │
                    │  📁 Archives Web     🔍 DNS Resolvers    │
                    │  📊 Metrics Store    💾 File System     │
                    └─────────────────────────────────────────┘
```

---

## 2. FLUX DE DONNÉES HEXAGONAL

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FLUX OSINT/SIGINT                           │
└─────────────────────────────────────────────────────────────────────┘

INPUT (Acteur Primaire)
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
OUTPUT (Acteur Primaire)
```

---

## 3. ARCHITECTURE EN COUCHES DÉTAILLÉE

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
## 4. DIAGRAMME HEXAGONAL CLASSIQUE

```
                                    👤 Analyste OSINT
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
        │                     (Hexagone)                              │
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

## 5. PATTERNS ARCHITECTURAUX VISUELS

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

## 6. DIAGRAMME DE DÉPLOIEMENT

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENVIRONNEMENT DE DÉPLOIEMENT                │
└─────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────┐
                    │                         │
                    │    POSTE ANALYSTE       │
                    │                         │
                    │ 🖥️ Linux Workstation    │
                    │ 🔐 Accès Sécurisé       │
                    │ 🛡️ Firewall Local       │
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

SÉCURITÉ:
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  🔒 CONTRÔLES D'ACCÈS:                                              │
│    • Validation stricte des entrées                                │
│    • Filtrage des plages IP privées                                │
│    • Limitation des caractères autorisés                           │
│    • Timeout sur toutes les opérations réseau                      │
│                                                                     │
│  🛡️ ISOLATION:                                                      │
│    • Pas de stockage de credentials                                │
│    • Cache local uniquement                                        │
│    • Pas de transmission de données sensibles                      │
│    • Logs d'activité pour audit                                    │
│                                                                     │
│  ⚡ PRIVILÈGES:                                                      │
│    • CAP_NET_RAW pour SIGINT TCP/ICMP                              │
│    • Validation avant tentative d'accès                            │
│    • Graceful degradation si privilèges insuffisants               │
│    • Pas d'escalation automatique                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 7. DIAGRAMME DE COMMUNICATION

```
┌─────────────────────────────────────────────────────────────────────┐
│                    COMMUNICATION INTER-MODULES                     │
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

**FIN DES DIAGRAMMES**

Ces diagrammes visuels illustrent l'architecture hexagonale stricte du projet Sentinelle avec :

1. **Vue d'ensemble hexagonale** - Architecture globale avec acteurs primaires/secondaires
2. **Flux de données** - Pipeline OSINT/SIGINT complet
3. **Architecture en couches** - Séparation stricte des responsabilités
4. **Hexagone classique** - Représentation traditionnelle ports & adapters
5. **Patterns architecturaux** - Composite, Probe, Strategy en détail
6. **Déploiement** - Environnement d'exécution et sécurité
7. **Communication** - Messages et interactions inter-modules

L'architecture respecte parfaitement les principes hexagonaux avec une séparation claire entre le domaine métier (hexagone central) et les adaptateurs d'infrastructure (côtés de l'hexagone).

---