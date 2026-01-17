import asyncio
import platform
import logging
import re
import ipaddress
import time
import statistics
from typing import List, Dict, Any, Tuple, Optional


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
        """Enhanced TCP handshake for latency and header heuristics."""
        try:
            start = time.perf_counter()
            # In a real SIGINT scenario, we'd use raw sockets (scapy)
            # to capture Window Size and Timestamps.
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            latency = (time.perf_counter() - start) * 1000

            # Simulated header extraction (TCP Window/Options)
            # In production, this would come from a packet capture layer
            win_size = 65535  # Common for modern mobile/desktop

            writer.close()
            await writer.wait_closed()
            return {
                'latency': round(latency, 3),
                'win_size': win_size,
                'status': 'success'
            }
        except Exception:
            return {'status': 'failed'}

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

                # SIGINT Intelligence Layer
                jitter_profile = self._analyze_jitter_profile(raw_rtts)
                bufferbloat = self._detect_bufferbloat(raw_rtts)
                os_fp = self._fingerprint_os(ttl, jitter_profile)
                anycast = self._detect_anycast(host, stats.get('avg', 0))
                proxy_anomaly = self._detect_proxy_vpn_anomaly(
                    stats.get('avg', 0), ttl, jitter_profile['jitter']
                )

                dist, margin = self.estimate_distance(
                    stats.get('avg', 0), stats.get('mdev', 0)
                )

                result = {
                    'host': host,
                    'status': 'reachable',
                    'rtt_ms': stats,
                    'intelligence': {
                        'os': os_fp,
                        'network_type': jitter_profile['type'],
                        'is_anycast': anycast,
                        'proxy_vpn_detected': proxy_anomaly,
                        'bufferbloat_detected': bufferbloat,
                        'ttl': ttl,
                        'jitter_ms': jitter_profile['jitter']
                    },
                    'distance_estimate': {'km': dist, 'margin_km': margin},
                    'method': 'ICMP_Advanced'
                }
                self._save_to_cache(host, result)
                return result

            # TCP Fallback
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

    def _analyze_jitter_profile(self, rtts: List[float]) -> Dict[str, Any]:
        """Distinguish Fixed vs Mobile (Android/iOS) via RTT variance."""
        if len(rtts) < 3:
            return {'type': 'Unknown', 'jitter': 0.0}

        jitter = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
        # Mobile networks (4G/5G) have high jitter due to radio scheduling
        net_type = "Fixed/Fiber"
        if jitter > self.MOBILE_JITTER_THRESHOLD:
            net_type = "Mobile/Radio (Potential Android/iOS)"

        return {'type': net_type, 'jitter': round(jitter, 3)}

    def _detect_bufferbloat(self, rtts: List[float]) -> bool:
        """Detect domestic router congestion (Bufferbloat)."""
        if not rtts:
            return False
        # If max RTT is significantly higher than min RTT, buffers are filling
        return (max(rtts) - min(rtts)) > self.BUFFERBLOAT_THRESHOLD

    def _detect_proxy_vpn_anomaly(self, avg_rtt: float,
                                  ttl: Optional[int],
                                  jitter: float) -> bool:
        """
        Identify Proxy/VPN tunnels via latency/TTL anomalies.
        - High jitter on low-latency links.
        - Non-standard TTL values.
        - Latency inconsistent with fiber physical limits.
        """
        if not ttl or avg_rtt == 0:
            return False

        # VPNs often add 10-20ms overhead and high jitter
        if avg_rtt < 30.0 and jitter > 10.0:
            return True

        # Non-standard TTL after few hops (VPNs often use 64 or 128)
        # If TTL is e.g. 59, it means ~5 hops. If latency is 200ms,
        # but only 5 hops, it's likely a tunneled connection (Proxy).
        hops = 0
        if ttl <= 64:
            hops = 64 - ttl
        elif ttl <= 128:
            hops = 128 - ttl
        elif ttl <= 255:
            hops = 255 - ttl

        # Heuristic: suspicious if RTT/hops > 50ms per hop for fixed lines
        if hops > 0 and (avg_rtt / hops) > 50.0:
            return True

        return False

    def _fingerprint_os(self, ttl: Optional[int],
                        jitter_data: Dict[str, Any],
                        win_size: Optional[int] = None) -> str:
        """Advanced OS detection: TTL + Network Profile + TCP Window."""
        if not ttl:
            if win_size:
                if win_size == 64240:
                    return "Windows (TCP-based)"
                if win_size == 65535:
                    return "FreeBSD/macOS (TCP-based)"
            return "Unknown"

        # Base TTL logic
        if ttl <= 64:
            # Android, Linux, and macOS all use TTL 64
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
            # Weight is inversely proportional to distance and jitter
            dist_w = 1.0 / max(0.1, vp['dist_km'])
            jitter_w = 1.0 / max(0.1, vp.get('mdev', 0))
            w = dist_w * jitter_w

            total_w += w
            w_lat += vp['lat'] * w
            w_lon += vp['lon'] * w

        # Confidence based on number of VPs and overall jitter
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
                    'mdev': res['rtt_ms'].get('mdev', 0)
                })
                final[vp_info['id']] = res
        final['path_analysis'] = await self.traceroute(target_ip)
        if len(tri_data) >= 2:
            lat, lon, score = self.triangulate(tri_data)
            final['location_estimate'] = {
                'lat': lat, 'lon': lon, 'confidence': score
            }
        return final
