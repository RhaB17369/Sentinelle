import asyncio
import platform
import logging
import re
import ipaddress
import time
import statistics
import aiodns
from typing import List, Dict, Any, Tuple, Optional
from scapy.all import IP, TCP, ICMP, sr1, conf, sr

from ...core.engine import BaseEngine, EventType

__version__ = "2.1.0"

class LatencyTracer(BaseEngine):
    """
    Military-grade network intelligence tool for SIGINT.
    Advanced Android/Mobile detection via Jitter & TCP signatures.
    """

    # Constants for physical limits and heuristics
    FIBER_SPEED_KM_MS = 200.0
    ROUTING_OVERHEAD_FACTOR = 1.05
    CACHE_TTL = 300

    # Mobile/Radio network jitter threshold (ms)
    MOBILE_JITTER_THRESHOLD = 15.0
    # Jitter variance threshold for Bufferbloat detection
    BUFFERBLOAT_THRESHOLD = 50.0
    # Satellite/Starlink thresholds
    SAT_RTT_THRESHOLD = 480.0
    STARLINK_RTT_MAX = 100.0
    STARLINK_JITTER_THRESHOLD = 20.0

    IXP_PATTERNS = [
        r"\.ix\.", r"\.exchange\.", r"decix", r"equinix", r"ams-ix",
        r"linx", r"mix-it", r"six-seattle", r"torix", r"hkix", r"any2ix"
    ]
    CDN_PATTERNS = [
        r"cloudflare", r"fastly", r"akamai", r"google", r"amazon",
        r"edgecast", r"limelight", r"level3", r"incapsula", r"sucuri"
    ]

    def __init__(self):
        super().__init__()
        self.system = platform.system().lower()
        self._cache = {}
        # Create resolver lazily to avoid requiring an event loop at import/test time
        self.resolver = None

    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        self.log(f"📡 Initializing SIGINT analysis for {target}...")
        self.progress(advance=0, total=6, description="Initializing")

        results = {"target": target, "timestamp": time.time()}

        # 1. Reverse DNS / Semantic Geo
        self.progress(advance=1, description="Semantic Geo (PTR)")
        geo = await self.get_semantic_geo(target)
        if geo:
            results["semantic_geo"] = geo
            self.emit(EventType.DATA, data={"Category": "DNS", "Property": "Hostname", "Value": geo.get("ptr", "Unknown")})
            if geo.get("detected_city_name"):
                self.emit(EventType.DATA, data={"Category": "Geo", "Property": "Clue", "Value": geo["detected_city_name"]})

        # 2. ASN Info
        self.progress(advance=1, description="ASN Intelligence")
        asn = await self.get_asn_info(target)
        if asn:
            results["asn"] = asn
            self.emit(EventType.DATA, data={"Category": "Network", "Property": "ASN", "Value": f"AS{asn.get('asn')} ({asn.get('owner')})"})
            if asn.get("is_known_vpn"):
                self.emit(EventType.DATA, data={"Category": "Security", "Property": "Type", "Value": "VPN/Hosting Detected"})

        # 3. Path MTU (Privileged)
        self.progress(advance=1, description="Path MTU Discovery")
        mtu_data = await self.discover_path_mtu(target)
        if mtu_data.get("status") != "permission_denied":
            results["mtu"] = mtu_data
            self.emit(EventType.DATA, data={"Category": "Network", "Property": "MTU", "Value": f"{mtu_data.get('mtu')} ({mtu_data.get('intelligence')})"})
        else:
            self.log("[yellow]⚠️ MTU discovery requires root/elevated privileges[/]")

        # 4. ICMP/TCP RTT & Jitter
        self.progress(advance=1, description="RTT & Jitter Analysis")
        ping_res = await self.ping(target, count=5)
        if ping_res.get("status") == "reachable":
            results["ping"] = ping_res
            rtt = ping_res.get("rtt_ms", {})
            self.emit(EventType.DATA, data={"Category": "Latency", "Property": "Avg RTT", "Value": f"{rtt.get('avg')}ms"})
            self.emit(EventType.DATA, data={"Category": "Latency", "Property": "Jitter", "Value": f"{rtt.get('mdev')}ms"})
            
            # Distance estimate
            dist = ping_res.get("distance_estimate", {}).get("km")
            if dist:
                self.emit(EventType.DATA, data={"Category": "Geo", "Property": "Est. Distance", "Value": f"~{int(dist)} km"})

        # 5. Clock Skew (Stealthy Fingerprinting)
        self.progress(advance=1, description="Clock Skew Fingerprinting")
        skew = await self.measure_clock_skew(target)
        if skew is None:
            skew = await self.measure_icmp_clock_skew(target)
        
        if skew is not None:
            results["clock_skew"] = skew
            self.emit(EventType.DATA, data={"Category": "Fingerprint", "Property": "Clock Skew", "Value": f"{skew} Hz"})

        # 6. Final Path Analysis
        self.progress(advance=1, description="Path Analysis (Traceroute)")
        path = await self.traceroute(target)
        if path:
            results["path"] = path
            self.emit(EventType.DATA, data={"Category": "Network", "Property": "Hops", "Value": str(len(path))})

        self.progress(advance=1, description="SIGINT complete")
        self.emit(EventType.COMPLETE, data=results)
        return results

    def _ensure_resolver(self):
        """Instantiate aiodns resolver if needed; fail gracefully if not possible."""
        if self.resolver is None:
            try:
                self.resolver = aiodns.DNSResolver()
            except Exception:
                logger.exception("failed to create aiodns DNSResolver")
                self.resolver = None

    def _is_elevated(self) -> bool:
        """Return True if running with administrative privileges (root on Unix, Admin on Windows)."""
        try:
            if self.system == "windows":
                try:
                    import ctypes
                    return ctypes.windll.shell32.IsUserAnAdmin() != 0
                except Exception:
                    return False
            else:
                import os
                return getattr(os, 'geteuid', lambda: -1)() == 0
        except Exception:
            logger.exception("failed to determine privilege level")
            return False

    def _elevation_check_response(self, action_name: str) -> Dict[str, Any]:
        """Return a standardized permission-denied response for privileged actions."""
        msg = (f"{action_name} requires administrative privileges (root/CAP_NET_RAW). "
               "Please run the program with elevated privileges.")
        logger.warning(msg)
        return {'status': 'permission_denied', 'message': msg}

    async def get_semantic_geo(self, ip: str) -> Dict[str, Any]:
        """Extract geographic clues from Reverse DNS hostnames."""
        try:
            addr = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            self._ensure_resolver()
            if not self.resolver:
                return {}
            response = await self.resolver.query(addr, 'PTR')
            if not response:
                return {}

            hostname_raw = self._decode_dns_text(response[0])
            if not hostname_raw:
                return {}
            hostname = hostname_raw.lower()

            # IATA codes (LHR, CDG, FRA, JFK, etc.)
            iata_patterns = (r"\b(lhr|cdg|fra|jfk|lax|hkg|sin|ams|sfo|sea|"
                             r"dfw)\b")
            iata_match = re.search(iata_patterns, hostname)

            # City name snippets
            city_patterns = (r"(paris|london|berlin|new-york|tokyo|madrid|"
                             r"milan)")
            city_match = re.search(city_patterns, hostname)

            return {
                'ptr': hostname,
                'detected_city_code': (iata_match.group(0).upper()
                                       if iata_match else None),
                'detected_city_name': (city_match.group(0).capitalize()
                                       if city_match else None)
            }
        except Exception:
            logger.exception("get_semantic_geo failed for %s", ip)
            return {}

    async def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Query Team Cymru ASN DNS API for network intelligence."""
        try:
            if self._is_ipv6(ip):
                return {'error': 'IPv6 ASN lookup not implemented'}

            rev_ip = ".".join(reversed(ip.split(".")))
            query = f"{rev_ip}.origin.asn.cymru.com"
            self._ensure_resolver()
            if not self.resolver:
                return {}
            response = await self.resolver.query(query, 'TXT')

            if response:
                first_txt = self._decode_dns_text(response[0])
                if not first_txt:
                    return {}
                parts = first_txt.split("|")
                asn = parts[0].strip()

                desc_query = f"AS{asn}.asn.cymru.com"
                desc_res = await self.resolver.query(desc_query, 'TXT')
                owner = "Unknown"
                if desc_res:
                    owner_txt = self._decode_dns_text(desc_res[0])
                    if owner_txt:
                        owner = owner_txt.split("|")[-1].strip()

                return {
                    'asn': asn,
                    'prefix': parts[1].strip() if len(parts) > 1 else None,
                    'country': parts[2].strip() if len(parts) > 2 else None,
                    'owner': owner,
                    'is_known_vpn': any(
                        x in (owner or '').lower()
                        for x in ['vpn', 'proxy', 'tor', 'hosting']
                    )
                }
        except Exception:
            logger.exception("get_asn_info failed for %s", ip)
        return {}

    def _get_from_cache(self, host: str) -> Optional[Dict[str, Any]]:
        """Retrieve data from cache if not expired."""
        if host in self._cache:
            ts, data = self._cache[host]
            if time.time() - ts < self.CACHE_TTL:
                return data
        return None

    def _save_to_cache(self, host: str, data: Dict[str, Any]):
        """Save data to cache with current timestamp."""
        self._cache[host] = (time.time(), data)

    async def tcp_ping(self, host: str, port: int = 443,
                       timeout: int = 2) -> Dict[str, Any]:
        """Deep Packet Inspection TCP handshake via Scapy."""
        # This probe uses raw sockets via Scapy; require elevation explicitly.
        if not self._is_elevated():
            return self._elevation_check_response('tcp_ping')

        old_verb = getattr(conf, 'verb', None)
        conf.verb = 0
        try:
            syn_packet = IP(dst=host) / TCP(dport=port, flags="S")
            start = time.perf_counter()

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: sr1(syn_packet, timeout=timeout, verbose=0)
            )
            latency = (time.perf_counter() - start) * 1000

            if response and response.haslayer(TCP):
                opts = response.getlayer(TCP).options
                intel = self._analyze_tcp_options(opts)
                return {
                    'latency': round(latency, 3),
                    'win_size': response.getlayer(TCP).window,
                    'tcp_options': intel,
                    'status': 'success'
                }

            return await self._tcp_ping_fallback(host, port, timeout)
        except Exception:
            logger.exception("tcp_ping failed for %s:%d", host, port)
            return await self._tcp_ping_fallback(host, port, timeout)
        finally:
            if old_verb is not None:
                conf.verb = old_verb

    async def _tcp_ping_fallback(self, host: str, port: int, timeout: int):
        """Standard TCP connect fallback."""
        try:
            start = time.perf_counter()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            latency = (time.perf_counter() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return {
                'latency': round(latency, 3),
                'status': 'success',
                'method': 'Standard_Connect'
            }
        except Exception:
            logger.exception("tcp_ping_fallback failed for %s:%d", host, port)
            return {'status': 'failed'}

    async def discover_path_mtu(self, host: str) -> Dict[str, Any]:
        """
        Binary search for Path MTU discovery via ICMP DF flag.
        Reveals tunneling protocols (VPN/IPsec/Wireguard).
        """
        # Requires raw sockets/ICMP privileges.
        if not self._is_elevated():
            return self._elevation_check_response('discover_path_mtu')

        try:
            if self._is_ipv6(host):
                return {'mtu': 1280, 'type': 'IPv6 Default'}

            mtu = 1500
            loop = asyncio.get_event_loop()

            for test_mtu in [1500, 1492, 1420, 1400, 1280]:
                payload = "X" * (test_mtu - 28)
                pkt = IP(dst=host, flags="DF")/ICMP()/payload
                ans = await loop.run_in_executor(
                    None, lambda p=pkt: sr1(p, timeout=1, verbose=0)
                )
                if ans:
                    mtu = test_mtu
                    break

            return {
                'mtu': mtu,
                'intelligence': self._fingerprint_mtu(mtu)
            }
        except Exception:
            logger.exception("discover_path_mtu failed for %s", host)
            return {'mtu': 1500, 'intelligence': 'Default/Unknown'}

    def _fingerprint_mtu(self, mtu: int) -> str:
        """Map MTU values to common network technologies."""
        if mtu == 1500:
            return "Standard Ethernet"
        if mtu == 1492:
            return "PPPoE (DSL)"
        if mtu == 1420:
            return "Wireguard VPN"
        if mtu == 1400:
            return "Generic Tunnel (IPsec/GRE)"
        if mtu < 1400:
            return "Encapsulated/VPN Tunnel"
        return "Unknown"

    async def _get_ip_id_intelligence(self, host: str,
                                      count: int = 5) -> Dict[str, Any]:
        """Analyze IP ID sequence to detect NAT or OS behavior."""
        # Requires raw socket privileges for ICMP capture.
        if not self._is_elevated():
            return self._elevation_check_response('_get_ip_id_intelligence')

        try:
            if self._is_ipv6(host):
                return {'type': 'IPv6 (No ID)'}

            packets = IP(dst=host)/ICMP()
            loop = asyncio.get_event_loop()

            ans, _ = await loop.run_in_executor(
                None, lambda: sr(packets * count, timeout=2, verbose=0)
            )

            ids = []
            for pair in ans:
                recv = None
                if isinstance(pair, tuple) and len(pair) >= 2:
                    recv = pair[1]
                elif hasattr(pair, 'id'):
                    recv = pair
                if recv and hasattr(recv, 'id'):
                    ids.append(int(getattr(recv, 'id')))

            if len(ids) < 2:
                return {'type': 'Insufficient Data'}

            def _id_diff(a, b):
                # handle 16-bit wrap-around
                d = (b - a) & 0xffff
                if d > 0x7fff:
                    d -= 0x10000
                return d

            diffs = [_id_diff(ids[i], ids[i+1]) for i in range(len(ids)-1)]

            if all(d == 0 for d in diffs):
                return {
                    'type': 'Constant (Likely Linux/Android)',
                    'values': ids
                }
            elif all(1 <= d <= 2 for d in diffs):
                return {
                    'type': 'Incremental (Likely Windows/Network Device)',
                    'values': ids
                }
            elif any(d < 0 for d in diffs) or \
                    statistics.stdev([float(d) for d in diffs]) > 1000:
                return {
                    'type': ('Random/High-Traffic (Potential NAT/'
                             'Load Balancer)'),
                    'values': ids
                }

            return {'type': 'Mixed', 'values': ids}
        except Exception:
            logger.exception("ip_id intelligence failed for %s", host)
            return {'type': 'Error during capture'}

    async def measure_clock_skew(self, host: str, port: int = 443,
                                 count: int = 3) -> Optional[float]:
        """
        Estimate target clock skew (Hz) via TCP Timestamps.
        Uses linear regression over multiple samples for high precision.
        """
        try:
            samples = []
            for _ in range(count):
                start_time = time.perf_counter()
                s = await self.tcp_ping(host, port)
                t_local = time.perf_counter()
                # Use the midpoint of the RTT for better local time estimation
                t_local_adjusted = (start_time + t_local) / 2.0
                t_remote = s.get('tcp_options', {}).get('ts_val')

                if t_remote is not None:
                    samples.append((t_local_adjusted, t_remote))

                if _ < count - 1:
                    await asyncio.sleep(1.0)

            if len(samples) < 2:
                return None

            # Simple linear regression (Local Time -> Remote TS)
            n = len(samples)
            sum_x = sum(s[0] for s in samples)
            sum_y = sum(s[1] for s in samples)
            sum_xy = sum(s[0] * s[1] for s in samples)
            sum_xx = sum(s[0]**2 for s in samples)

            denominator = (n * sum_xx - sum_x**2)
            if denominator == 0:
                return None

            slope = (n * sum_xy - sum_x * sum_y) / denominator
            return round(slope, 2)
        except Exception:
            logger.exception("measure_clock_skew failed for %s", host)
            return None

    async def measure_icmp_clock_skew(self, host: str, count: int = 3) -> Optional[float]:
        """
        Estimate target clock skew via ICMP Timestamp Request (Type 13).
        Stealthier alternative when TCP timestamps are blocked.
        """
        # ICMP timestamp probing requires elevated privileges.
        if not self._is_elevated():
            # Returning None is consistent with function signature while providing
            # a clear permission-denied message via a helper response if desired.
            logger.warning("measure_icmp_clock_skew requires administrative privileges")
            return None

        try:
            samples = []
            for _ in range(count):
                pkt = IP(dst=host)/ICMP(type=13)
                start_time = time.perf_counter()

                loop = asyncio.get_event_loop()
                ans = await loop.run_in_executor(
                    None, lambda: sr1(pkt, timeout=1, verbose=0)
                )

                t_local = time.perf_counter()
                t_local_adjusted = (start_time + t_local) / 2.0

                if ans and ans.haslayer(ICMP) and ans.getlayer(ICMP).type == 14:
                    t_remote = ans.getlayer(ICMP).ts_rx
                    if t_remote:
                        samples.append((t_local_adjusted, t_remote))

                if _ < count - 1:
                    await asyncio.sleep(1.0)

            if len(samples) < 2:
                return None

            n = len(samples)
            sum_x = sum(s[0] for s in samples)
            sum_y = sum(s[1] for s in samples)
            sum_xy = sum(s[0] * s[1] for s in samples)
            sum_xx = sum(s[0]**2 for s in samples)

            denom = (n * sum_xx - sum_x**2)
            if denom == 0:
                return None

            slope = (n * sum_xy - sum_x * sum_y) / denom
            return round(slope, 2)
        except Exception:
            logger.exception("measure_icmp_clock_skew failed for %s", host)
            return None

    def _analyze_tcp_options(self, options: List[Tuple[str, Any]]) -> Dict[str, Any]:
        """Analyze TCP Options for expert-level OS fingerprinting."""
        opt_dict = dict(options)
        opt_names = [opt[0] for opt in options]
        opt_sequence = ",".join(opt_names)

        fp = "Unknown"

        # Refined signatures based on common stack implementations
        if "MSS" in opt_names and "SAckOK" in opt_names and "Timestamp" in opt_names:
            if opt_sequence.startswith("MSS,SAckOK,Timestamp"):
                fp = "Linux Kernel 3.11+"
            elif "WScale" in opt_names:
                fp = "Linux-based (Generic)"
        elif "MSS" in opt_names and "NOP" in opt_names and "WScale" in opt_names:
            if "SAckOK" in opt_names:
                fp = "Windows 10/11"
            else:
                fp = "Windows (Older/Server)"
        elif "MSS" in opt_names and "WScale" in opt_names and "Timestamp" in opt_names:
            # macOS/iOS often uses MSS, NOP, WScale, NOP, NOP, TS, SACK
            if opt_sequence.count("NOP") >= 3:
                fp = "iOS/macOS"

        ts_val = None
        if "Timestamp" in opt_dict:
            ts_val = opt_dict["Timestamp"][0] if isinstance(opt_dict["Timestamp"], tuple) else opt_dict["Timestamp"]

        return {
            'fingerprint': fp,
            'options': opt_names,
            'ts_val': ts_val,
            'wscale': opt_dict.get("WScale")
        }

    async def ping(self, host: str, count: int = 10,
                   timeout: int = 5, use_cache: bool = True) -> Dict[str, Any]:
        """High-precision ping with Mobile/Android intelligence."""
        if use_cache:
            cached = self._get_from_cache(host)
            if cached:
                return cached

        is_v6 = self._is_ipv6(host)
        cmd = ["ping", "-6" if is_v6 else "-4", "-c", str(count),
               "-W", str(timeout), host]
        if self.system == "windows":
            cmd = ["ping", "-6" if is_v6 else "-4", "-n", str(count), host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 5
            )
            output = stdout.decode().strip()

            if proc.returncode == 0:
                stats = self._parse_ping_output(output)
                raw_rtts = self._extract_all_rtts(output)
                ttl = self._extract_ttl(output)

                jitter_profile = self._analyze_jitter_profile(raw_rtts)
                bufferbloat = self._detect_bufferbloat(raw_rtts)
                anycast = self._detect_anycast(host, stats.get('avg', 0))
                proxy_anomaly = self._detect_proxy_vpn_anomaly(
                    stats.get('avg', 0), ttl, jitter_profile['jitter']
                )

                # Parallel Intelligence Gathering (Deep SIGINT)
                tcp_task = asyncio.create_task(self.tcp_ping(host))
                asn_task = asyncio.create_task(self.get_asn_info(host))
                ipid_task = asyncio.create_task(self._get_ip_id_intelligence(host))
                mtu_task = asyncio.create_task(self.discover_path_mtu(host))
                geo_task = asyncio.create_task(self.get_semantic_geo(host))

                res_gather = await asyncio.gather(
                    tcp_task, asn_task, ipid_task, mtu_task, geo_task
                )
                tcp_intel, asn_intel, ipid_intel, mtu_intel, geo_intel = res_gather

                link_type = self._classify_link_type(
                    stats.get('avg', 0), jitter_profile['jitter']
                )

                os_fp = self._fingerprint_os(
                    ttl, jitter_profile,
                    tcp_intel.get('win_size'),
                    tcp_intel.get('tcp_options')
                )

                dist, margin = self.estimate_distance(
                    stats.get('avg', 0), stats.get('mdev', 0)
                )

                is_vpn = proxy_anomaly or asn_intel.get('is_known_vpn', False)
                link_integrity = self._calculate_link_integrity(
                    stats, jitter_profile['jitter']
                )

                result = {
                    'host': host,
                    'status': 'reachable',
                    'rtt_ms': stats,
                    'intelligence': {
                        'os': os_fp,
                        'link_medium': link_type,
                        'link_integrity': link_integrity,
                        'is_anycast': anycast,
                        'proxy_vpn_detected': is_vpn,
                        'bufferbloat_detected': bufferbloat,
                        'ttl': ttl,
                        'jitter_ms': jitter_profile['jitter'],
                        'tcp_fingerprint': tcp_intel.get('tcp_options'),
                        'asn_data': asn_intel,
                        'ip_id_analysis': ipid_intel,
                        'path_mtu': mtu_intel,
                        'semantic_location': geo_intel
                    },
                    'distance_estimate': {'km': dist, 'margin_km': margin},
                    'method': 'ICMP_Advanced_SIGINT'
                }
                self._save_to_cache(host, result)
                return result

            tcp_res = await self.tcp_ping(host)
            if tcp_res['status'] == 'success':
                dist, margin = self.estimate_distance(tcp_res['latency'], 0)
                return {
                    'host': host, 'status': 'reachable',
                    'rtt_ms': {'avg': tcp_res['latency']},
                    'intelligence': {
                        'os': 'Unknown (TCP Only)',
                        'win_size': tcp_res['win_size']
                    },
                    'distance_estimate': {'km': dist, 'margin_km': margin},
                    'method': 'TCP_Fallback'
                }

            return {'host': host, 'status': 'unreachable'}
        except Exception as e:
            logger.exception("ping failed for %s: %s", host, e)
            return {'host': host, 'status': 'error', 'message': str(e)}

    def _classify_link_type(self, avg_rtt: float, jitter: float) -> str:
        """Categorize physical medium based on statistical signatures."""
        if avg_rtt > self.SAT_RTT_THRESHOLD:
            return "Geostationary Satellite (High Latency)"

        # Starlink has unique signatures: ~30-80ms RTT with higher jitter
        if 25.0 < avg_rtt < self.STARLINK_RTT_MAX and \
           jitter > self.STARLINK_JITTER_THRESHOLD:
            return "LEO Satellite (Likely Starlink)"

        if jitter > self.MOBILE_JITTER_THRESHOLD:
            return "Mobile/Radio (4G/5G/LTE)"

        return "Terrestrial (Fiber/Copper)"

    def _analyze_jitter_profile(self, rtts: List[float]) -> Dict[str, Any]:
        """Distinguish Fixed vs Mobile (Android/iOS) via RTT variance."""
        if len(rtts) < 3:
            return {'type': 'Unknown', 'jitter': 0.0}

        jitter = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
        net_type = "Fixed/Fiber"
        if jitter > self.MOBILE_JITTER_THRESHOLD:
            net_type = "Mobile/Radio (Potential Android/iOS)"

        return {'type': net_type, 'jitter': round(jitter, 3)}

    def _detect_bufferbloat(self, rtts: List[float]) -> bool:
        """Detect domestic router congestion (Bufferbloat)."""
        if not rtts:
            return False
        return (max(rtts) - min(rtts)) > self.BUFFERBLOAT_THRESHOLD

    def _detect_proxy_vpn_anomaly(self, avg_rtt: float,
                                  ttl: Optional[int],
                                  jitter: float) -> bool:
        """Identify Proxy/VPN tunnels via latency/TTL anomalies."""
        if not ttl or avg_rtt == 0:
            return False

        if avg_rtt < 30.0 and jitter > 10.0:
            return True

        hops = 0
        if ttl <= 64:
            hops = 64 - ttl
        elif ttl <= 128:
            hops = 128 - ttl
        elif ttl <= 255:
            hops = 255 - ttl

        if hops > 0 and (avg_rtt / hops) > 50.0:
            return True

        return False

    def _fingerprint_os(self, ttl: Optional[int],
                        jitter_data: Dict[str, Any],
                        win_size: Optional[int] = None,
                        tcp_options: Optional[Dict[str, Any]] = None) -> str:
        """Advanced OS detection: TTL + Network Profile + TCP Options."""
        if tcp_options and tcp_options.get('fingerprint') != "Unknown":
            return tcp_options['fingerprint']

        # WScale and Window Size correlation
        wscale = tcp_options.get('wscale') if tcp_options else None

        if not ttl:
            if win_size:
                if win_size == 64240:
                    return "Windows (TCP-based)"
                if win_size in [29200, 5840, 14600]:
                    return "Linux (TCP-based)"
                if win_size == 65535:
                    return "FreeBSD/macOS (TCP-based)"
            return "Unknown"

        if ttl <= 64:
            # Linux/Android/iOS/macOS all use TTL 64
            if jitter_data.get('type', '').startswith("Mobile/Radio"):
                return "Android/Mobile Device"
            if win_size == 65535 or (wscale is not None and wscale in [6, 8]):
                return "macOS/iOS"
            if win_size in [29200, 5840, 14600, 64240]:
                return "Linux"
            return "Unix/Linux Derivative"

        if ttl <= 128:
            # Windows uses TTL 128
            if win_size == 64240 or (wscale is not None and wscale == 8):
                return "Windows 10/11"
            return "Windows"

        return "Network Device (Cisco/Juniper/F5)"

    def _calculate_link_integrity(self, rtt_ms: Dict[str, float],
                                  jitter: float) -> Dict[str, Any]:
        """Generate a quality score based on link stability and health."""
        score = 100.0
        loss = rtt_ms.get('loss_pct', 0.0)

        # Penalize packet loss (heavy weight)
        score -= (loss * 1.5)

        # Penalize jitter
        score -= min(25, jitter * 1.5)

        # Penalize bufferbloat (latency variance)
        avg = rtt_ms.get('avg', 0)
        if avg > 0:
            max_rtt = rtt_ms.get('max', 0)
            bloat_factor = max_rtt / avg
            if bloat_factor > 1.5:
                score -= min(20, (bloat_factor - 1.5) * 10)

        rating = "Elite"
        if score < 30:
            rating = "Critical"
        elif score < 50:
            rating = "Degraded"
        elif score < 75:
            rating = "Nominal"
        elif score < 90:
            rating = "High-Quality"

        return {
            'quality_score': round(max(0, score), 1),
            'rating': rating,
            'packet_loss_pct': loss
        }

    def _extract_all_rtts(self, output: str) -> List[float]:
        """Extract individual RTT values for statistical analysis.

        Accepts both dot and comma decimals produced by different locales.
        """
        matches = re.findall(r"time=([0-9]+(?:[.,][0-9]+)?)", output)
        return [float(m.replace(',', '.')) for m in matches]

    def _is_ipv6(self, host: str) -> bool:
        try:
            return ipaddress.ip_address(host).version == 6
        except ValueError:
            return False

    def _decode_dns_text(self, entry) -> Optional[str]:
        """Safely extract text/value bytes from aiodns response entry."""
        if entry is None:
            return None
        txt = getattr(entry, 'text', None) or getattr(entry, 'value', None)
        if txt is None:
            return None
        if isinstance(txt, (bytes, bytearray)):
            try:
                return txt.decode('utf-8', errors='ignore')
            except Exception:
                return txt.decode('latin-1', errors='ignore') if isinstance(txt, (bytes, bytearray)) else str(txt)
        return str(txt)

    def _extract_ttl(self, output: str) -> Optional[int]:
        match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        return int(match.group(1)) if match else None

    def _detect_anycast(self, host: str, rtt: float) -> bool:
        if rtt < 5.0 and not host.startswith(("127.", "192.168.", "10.")):
            return True
        cdn = self.CDN_PATTERNS
        return any(re.search(p, host, re.IGNORECASE) for p in cdn)

    def _parse_ping_output(self, output: str) -> Dict[str, float]:
        stats = {'loss_pct': 100.0}

        # Extract packet loss; handle different formats/locales
        loss_match = re.search(r"(\d+(?:[.,]\d+)?)% packet loss", output, re.IGNORECASE)
        if not loss_match:
            loss_match = re.search(r"Lost = \d+ \((\d+)%\s*loss\)", output, re.IGNORECASE)
        if loss_match:
            stats['loss_pct'] = float(loss_match.group(1).replace(',', '.'))

        if self.system == "windows":
            p = r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms"
            match = re.search(p, output)
            if match:
                stats.update({
                    'min': float(match.group(1)),
                    'max': float(match.group(2)),
                    'avg': float(match.group(3)),
                    'mdev': 0.0
                })
        else:
            p = r"([0-9]+(?:[.,][0-9]+)?)/([0-9]+(?:[.,][0-9]+)?)/([0-9]+(?:[.,][0-9]+)?)/([0-9]+(?:[.,][0-9]+)?) ms"
            match = re.search(p, output)
            if match:
                stats.update({
                    'min': float(match.group(1).replace(',', '.')),
                    'avg': float(match.group(2).replace(',', '.')),
                    'max': float(match.group(3).replace(',', '.')),
                    'mdev': float(match.group(4).replace(',', '.'))
                })
        return stats

    def estimate_distance(self,
                          rtt: float, mdev: float) -> Tuple[float, float]:
        if rtt <= 0:
            return 0.0, 0.0
        one_way = rtt / 2.0
        effective = max(0.1, one_way - 1.0)
        dist = (effective * self.FIBER_SPEED_KM_MS) * \
            self.ROUTING_OVERHEAD_FACTOR
        margin = (mdev * self.FIBER_SPEED_KM_MS) + (dist * 0.1)
        return round(dist, 2), round(margin, 2)

    async def traceroute(self, host: str,
                         max_hops: int = 20) -> Dict[str, Any]:
        """
        Refined traceroute with ASN path analysis and IXP detection.
        """
        if self.system == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), host]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
            output = stdout.decode().strip()

            # Extract unique IPs from the output
            hop_ips = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
            
            # Parallel ASN resolution for each unique hop
            unique_ips = list(dict.fromkeys(hop_ips))
            asn_tasks = [self.get_asn_info(ip) for ip in unique_ips]
            asn_results = await asyncio.gather(*asn_tasks)
            asn_map = dict(zip(unique_ips, asn_results))

            refined_hops = []
            for ip in hop_ips:
                intel = asn_map.get(ip, {})
                refined_hops.append({
                    'ip': ip,
                    'asn': intel.get('asn'),
                    'owner': intel.get('owner'),
                    'country': intel.get('country')
                })

            ixps = [ix for ix in self.IXP_PATTERNS
                    if re.search(ix, output, re.IGNORECASE)]
            
            # AS Path deduction
            as_path = [h['asn'] for h in refined_hops if h['asn']]
            # Remove consecutive duplicates in AS path
            dedup_as_path = [as_path[i] for i in range(len(as_path)) 
                            if i == 0 or as_path[i] != as_path[i-1]]

            return {
                'host': host,
                'hop_count': len(refined_hops),
                'hops': refined_hops,
                'ixps': list(set(ixps)),
                'as_path': dedup_as_path,
                'path_intel': {
                    'countries': list(set(h['country'] for h in refined_hops if h['country'])),
                    'unique_asns': len(set(dedup_as_path))
                }
            }
        except Exception as e:
            return {'host': host, 'error': str(e)}

    def validate_physical_constraints(self, dist_km: float, rtt_ms: float) -> bool:
        """
        Verify if the distance/latency pair respects physical laws.
        Fiber Speed of Light is ~200,000 km/s (200 km/ms).
        """
        if rtt_ms <= 0:
            return False
        min_rtt = (dist_km * 2.0) / self.FIBER_SPEED_KM_MS
        return rtt_ms >= min_rtt

    def triangulate(self,
                    vantage_points: List[Dict[str, Any]]) \
            -> Tuple[float, float, float]:
        """Weighted multilateration via distance and stability (mdev)."""
        if len(vantage_points) < 2:
            return 0.0, 0.0, 0.0

        total_w, w_lat, w_lon = 0.0, 0.0, 0.0
        total_mdev = sum(vp.get('mdev', 0) for vp in vantage_points)
        avg_mdev = total_mdev / len(vantage_points)

        for vp in vantage_points:
            is_possible = self.validate_physical_constraints(
                vp['dist_km'], vp.get('avg_rtt', 0)
            )
            phys_w = 1.0 if is_possible else 0.1

            dist_w = 1.0 / max(0.1, vp['dist_km'])
            jitter_w = 1.0 / max(0.1, vp.get('mdev', 0))
            w = dist_w * jitter_w * phys_w

            total_w += w
            w_lat += vp['lat'] * w
            w_lon += vp['lon'] * w

        # If no weight accumulated, avoid division by zero and return neutral values.
        if total_w == 0:
            return 0.0, 0.0, 0.0

        base_conf = min(0.9, len(vantage_points) / 5.0)
        jitter_penalty = min(0.4, avg_mdev / 100.0)
        confidence = round(base_conf - jitter_penalty, 2)

        return round(w_lat / total_w, 6), round(w_lon / total_w, 6), confidence

    async def run_triangulation(self, target_ip: str,
                                vp_data: List[Dict[str, Any]]) \
            -> Dict[str, Any]:
        # Allow vp_data to optionally include precomputed measurement results
        tasks = []
        for vp in vp_data:
            if 'precomputed' in vp and isinstance(vp['precomputed'], dict):
                # immediate successful placeholder
                tasks.append(asyncio.create_task(asyncio.sleep(0, result=vp['precomputed'])))
            else:
                tasks.append(asyncio.create_task(self.ping(target_ip)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        tri_data, final = [], {}
        for vp_info, res in zip(vp_data, results):
            if isinstance(res, Exception):
                logger.warning("ping for vp %s failed: %s", vp_info.get('id'), res)
                continue
            reachable = res.get('status') == 'reachable'
            if reachable:
                tri_data.append({
                    'lat': vp_info['lat'], 'lon': vp_info['lon'],
                    'dist_km': res['distance_estimate']['km'],
                    'mdev': res['rtt_ms'].get('mdev', 0),
                    'avg_rtt': res['rtt_ms'].get('avg', 0)
                })
                final[vp_info['id']] = res
            else:
                final[vp_info['id']] = res

        final['clock_skew_hz'] = await self.measure_clock_skew(target_ip)
        if final['clock_skew_hz'] is None:
            final['clock_skew_hz'] = await self.measure_icmp_clock_skew(target_ip)

        final['path_analysis'] = await self.traceroute(target_ip)

        if len(tri_data) >= 2:
            lat, lon, score = self.triangulate(tri_data)
            final['location_estimate'] = {
                'lat': lat, 'lon': lon, 'confidence': score
            }
        return final
