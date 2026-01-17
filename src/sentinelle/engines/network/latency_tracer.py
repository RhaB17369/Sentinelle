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


logger = logging.getLogger(__name__)


class LatencyTracer:
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
        self.system = platform.system().lower()
        self._cache = {}
        self.resolver = aiodns.DNSResolver()

    async def get_semantic_geo(self, ip: str) -> Dict[str, Any]:
        """Extract geographic clues from Reverse DNS hostnames."""
        try:
            addr = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            response = await self.resolver.query(addr, 'PTR')
            if not response:
                return {}

            hostname = response[0].value.decode().lower()

            # IATA codes (LHR, CDG, FRA, JFK, etc.)
            iata_patterns = r"\b(lhr|cdg|fra|jfk|lax|hkg|sin|ams|sfo|sea|dfw)\b"
            iata_match = re.search(iata_patterns, hostname)

            # City name snippets
            city_patterns = r"(paris|london|berlin|new-york|tokyo|madrid|milan)"
            city_match = re.search(city_patterns, hostname)

            return {
                'ptr': hostname,
                'detected_city_code': (iata_match.group(0).upper()
                                       if iata_match else None),
                'detected_city_name': (city_match.group(0).capitalize()
                                       if city_match else None)
            }
        except Exception:
            return {}

    async def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Query Team Cymru ASN DNS API for network intelligence."""
        try:
            if self._is_ipv6(ip):
                return {'error': 'IPv6 ASN lookup not implemented'}

            rev_ip = ".".join(reversed(ip.split(".")))
            query = f"{rev_ip}.origin.asn.cymru.com"
            response = await self.resolver.query(query, 'TXT')

            if response:
                parts = response[0].text.decode().split("|")
                asn = parts[0].strip()

                desc_query = f"AS{asn}.asn.cymru.com"
                desc_res = await self.resolver.query(desc_query, 'TXT')
                if desc_res:
                    owner = desc_res[0].text.decode().split("|")[-1].strip()
                else:
                    owner = "Unknown"

                return {
                    'asn': asn,
                    'prefix': parts[1].strip(),
                    'country': parts[2].strip(),
                    'owner': owner,
                    'is_known_vpn': any(x in owner.lower()
                                        for x in ['vpn', 'proxy', 'tor', 'hosting'])
                }
        except Exception:
            pass
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
        try:
            conf.verb = 0
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
            return await self._tcp_ping_fallback(host, port, timeout)

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
            return {'status': 'failed'}

    async def discover_path_mtu(self, host: str) -> Dict[str, Any]:
        """
        Binary search for Path MTU discovery via ICMP DF flag.
        Reveals tunneling protocols (VPN/IPsec/Wireguard).
        """
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

    async def _get_ip_id_intelligence(self, host: str, count: int = 5) -> Dict[str, Any]:
        """Analyze IP ID sequence to detect NAT or OS behavior."""
        try:
            if self._is_ipv6(host):
                return {'type': 'IPv6 (No ID)'}

            packets = IP(dst=host)/ICMP()
            loop = asyncio.get_event_loop()

            ans, _ = await loop.run_in_executor(
                None, lambda: sr(packets * count, timeout=2, verbose=0)
            )

            ids = [pkt[1].id for pkt in ans]
            if len(ids) < 2:
                return {'type': 'Insufficient Data'}

            diffs = [ids[i+1] - ids[i] for i in range(len(ids)-1)]

            if all(d == 0 for d in diffs):
                return {'type': 'Constant (Likely Linux/Android)', 'values': ids}
            elif all(1 <= d <= 2 for d in diffs):
                return {'type': 'Incremental (Likely Windows/Network Device)',
                        'values': ids}
            elif any(d < 0 for d in diffs) or \
                    statistics.stdev([float(d) for d in diffs]) > 1000:
                return {'type': 'Random/High-Traffic (Potential NAT/Load Balancer)',
                        'values': ids}

            return {'type': 'Mixed', 'values': ids}
        except Exception:
            return {'type': 'Error during capture'}

    async def measure_clock_skew(self, host: str, port: int = 443) -> Optional[float]:
        """Estimate target clock skew (Hz) via TCP Timestamps."""
        try:
            s1 = await self.tcp_ping(host, port)
            t1_local = time.perf_counter()
            t1_remote = s1.get('tcp_options', {}).get('ts_val')

            if t1_remote is None:
                return None

            await asyncio.sleep(1.0)

            s2 = await self.tcp_ping(host, port)
            t2_local = time.perf_counter()
            t2_remote = s2.get('tcp_options', {}).get('ts_val')

            if t2_remote is None:
                return None

            remote_delta = t2_remote - t1_remote
            local_delta = t2_local - t1_local
            return round(remote_delta / local_delta, 2)
        except Exception:
            return None

    def _analyze_tcp_options(self, options: List[Tuple[str, Any]]) -> Dict[str, Any]:
        """Analyze TCP Options for expert-level OS fingerprinting."""
        opt_names = [opt[0] for opt in options]

        fp = "Unknown"
        if "Timestamp" in opt_names and "WScale" in opt_names:
            if opt_names[1] == "SACK":
                fp = "Linux Kernel 3.x+"
            else:
                fp = "iOS/macOS"
        elif "WScale" in opt_names and "NOP" in opt_names:
            fp = "Windows"

        return {
            'fingerprint': fp,
            'options': opt_names,
            'ts_val': next((opt[1] for opt in options
                            if opt[0] == "Timestamp"), None)
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

                result = {
                    'host': host,
                    'status': 'reachable',
                    'rtt_ms': stats,
                    'intelligence': {
                        'os': os_fp,
                        'link_medium': link_type,
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

        if not ttl:
            if win_size:
                if win_size == 64240:
                    return "Windows (TCP-based)"
                if win_size == 65535:
                    return "FreeBSD/macOS (TCP-based)"
            return "Unknown"

        if ttl <= 64:
            if jitter_data.get('type', '').startswith("Mobile/Radio"):
                return "Android/Mobile Device"
            if win_size == 65535:
                return "macOS/iOS"
            return "Linux"
        if ttl <= 128:
            return "Windows"
        return "Network Device (Cisco/Juniper)"

    def _extract_all_rtts(self, output: str) -> List[float]:
        """Extract individual RTT values for statistical analysis."""
        return [float(m) for m in re.findall(r"time=(\d+\.?\d*)", output)]

    def _is_ipv6(self, host: str) -> bool:
        try:
            return ipaddress.ip_address(host).version == 6
        except ValueError:
            return False

    def _extract_ttl(self, output: str) -> Optional[int]:
        match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        return int(match.group(1)) if match else None

    def _detect_anycast(self, host: str, rtt: float) -> bool:
        if rtt < 5.0 and not host.startswith(("127.", "192.168.", "10.")):
            return True
        cdn = self.CDN_PATTERNS
        return any(re.search(p, host, re.IGNORECASE) for p in cdn)

    def _parse_ping_output(self, output: str) -> Dict[str, float]:
        stats = {}
        if self.system == "windows":
            p = r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms"
            match = re.search(p, output)
            if match:
                stats = {
                    'min': float(match.group(1)),
                    'max': float(match.group(2)),
                    'avg': float(match.group(3)),
                    'mdev': 0.0
                }
        else:
            p = r"(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+) ms"
            match = re.search(p, output)
            if match:
                stats = {
                    'min': float(match.group(1)),
                    'avg': float(match.group(2)),
                    'max': float(match.group(3)),
                    'mdev': float(match.group(4))
                }
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
        if self.system == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), host]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), host]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode().strip()
            hops = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
            ixps = [ix for ix in self.IXP_PATTERNS
                    if re.search(ix, output, re.IGNORECASE)]
            return {
                'host': host, 'hop_count': len(hops), 'hops': hops,
                'ixps': list(set(ixps))
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

        base_conf = min(0.9, len(vantage_points) / 5.0)
        jitter_penalty = min(0.4, avg_mdev / 100.0)
        confidence = round(base_conf - jitter_penalty, 2)

        return round(w_lat / total_w, 6), round(w_lon / total_w, 6), confidence

    async def run_triangulation(self, target_ip: str,
                                vp_data: List[Dict[str, Any]]) \
            -> Dict[str, Any]:
        results = await asyncio.gather(
            *[self.ping(target_ip) for _ in vp_data],
            return_exceptions=True
        )
        tri_data, final = [], {}
        for vp_info, res in zip(vp_data, results):
            reachable = (not isinstance(res, Exception) and
                         res.get('status') == 'reachable')
            if reachable:
                tri_data.append({
                    'lat': vp_info['lat'], 'lon': vp_info['lon'],
                    'dist_km': res['distance_estimate']['km'],
                    'mdev': res['rtt_ms'].get('mdev', 0),
                    'avg_rtt': res['rtt_ms'].get('avg', 0)
                })
                final[vp_info['id']] = res

        final['clock_skew_hz'] = await self.measure_clock_skew(target_ip)
        final['path_analysis'] = await self.traceroute(target_ip)

        if len(tri_data) >= 2:
            lat, lon, score = self.triangulate(tri_data)
            final['location_estimate'] = {
                'lat': lat, 'lon': lon, 'confidence': score
            }
        return final
