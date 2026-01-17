import asyncio
import platform
import logging
import re
import ipaddress
import time
from typing import List, Dict, Any, Tuple, Optional


logger = logging.getLogger(__name__)


class LatencyTracer:
    """
    Expert-level network intelligence tool for SIGINT and geolocation.
    Integrates ICMP/TCP pings, OS fingerprinting, and path correlation.
    """

    # Physical limits and delay factors
    FIBER_SPEED_KM_MS = 200.0
    ROUTING_OVERHEAD_FACTOR = 1.05
    CACHE_TTL = 300

    # Common IXP and CDN patterns for path analysis
    IXP_PATTERNS = [
        r"\.ix\.", r"\.exchange\.", r"decix", r"equinix", r"ams-ix"
    ]
    CDN_PATTERNS = [
        r"cloudflare", r"fastly", r"akamai", r"google", r"amazon"
    ]

    def __init__(self):
        self.system = platform.system().lower()
        self._cache = {}

    def _get_from_cache(self, host: str) -> Optional[Dict[str, Any]]:
        """Retrieve data from cache if not expired."""
        if host in self._cache:
            timestamp, data = self._cache[host]
            if time.time() - timestamp < self.CACHE_TTL:
                return data
        return None

    def _save_to_cache(self, host: str, data: Dict[str, Any]):
        """Save data to cache with current timestamp."""
        self._cache[host] = (time.time(), data)

    def _is_ipv6(self, host: str) -> bool:
        """Detect if host is an IPv6 address."""
        try:
            return ipaddress.ip_address(host).version == 6
        except ValueError:
            return False

    async def tcp_ping(self, host: str, port: int = 443,
                       timeout: int = 2) -> Optional[float]:
        """Measure latency via TCP handshake (fallback for ICMP block)."""
        try:
            start = time.perf_counter()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            latency = (time.perf_counter() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return round(latency, 3)
        except Exception:
            return None

    async def ping(self, host: str, count: int = 3,
                   timeout: int = 5, use_cache: bool = True) -> Dict[str, Any]:
        """High-precision ping with TCP fallback and OS fingerprinting."""
        if use_cache:
            cached = self._get_from_cache(host)
            if cached:
                return cached

        is_v6 = self._is_ipv6(host)
        if self.system == "windows":
            cmd = ["ping", "-6" if is_v6 else "-4", "-n", str(count), host]
        else:
            cmd = ["ping", "-6" if is_v6 else "-4", "-c", str(count),
                   "-W", str(timeout), host]

        try:
            start_time = time.perf_counter()
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 2
            )
            end_time = time.perf_counter()
            output = stdout.decode().strip()

            if proc.returncode == 0:
                stats = self._parse_ping_output(output)
                ttl = self._extract_ttl(output)

                os_info = self._fingerprint_os(ttl)
                anycast = self._detect_anycast(host, stats.get('avg', 0))
                dist, margin = self.estimate_distance(
                    stats.get('avg', 0), stats.get('mdev', 0)
                )

                result = {
                    'host': host,
                    'status': 'reachable',
                    'family': 'IPv6' if is_v6 else 'IPv4',
                    'rtt_ms': stats,
                    'ttl': ttl,
                    'os_fingerprint': os_info,
                    'is_anycast': anycast,
                    'distance_estimate': {'km': dist, 'margin_km': margin},
                    'execution_time': end_time - start_time,
                    'method': 'ICMP'
                }
                self._save_to_cache(host, result)
                return result

            tcp_lat = await self.tcp_ping(host)
            if tcp_lat:
                dist, margin = self.estimate_distance(tcp_lat, 0)
                return {
                    'host': host, 'status': 'reachable',
                    'rtt_ms': {'avg': tcp_lat},
                    'distance_estimate': {'km': dist, 'margin_km': margin},
                    'method': 'TCP_Handshake'
                }

            return {'host': host, 'status': 'unreachable',
                    'error': stderr.decode()}

        except Exception as e:
            return {'host': host, 'status': 'error', 'message': str(e)}

    def _extract_ttl(self, output: str) -> Optional[int]:
        """Extract TTL value from ping output."""
        match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        return int(match.group(1)) if match else None

    def _fingerprint_os(self, ttl: Optional[int]) -> str:
        """Estimate OS based on initial TTL values."""
        if not ttl:
            return "Unknown"
        if ttl <= 64:
            return "Linux/Unix/macOS"
        if ttl <= 128:
            return "Windows"
        if ttl <= 255:
            return "Network Device (Solaris/Cisco)"
        return "Unknown"

    def _detect_anycast(self, host: str, rtt: float) -> bool:
        """Detect Anycast/CDN distribution (unrealistically low RTT)."""
        if rtt < 5.0 and not host.startswith(("127.", "192.168.", "10.")):
            return True
        for pattern in self.CDN_PATTERNS:
            if re.search(pattern, host, re.IGNORECASE):
                return True
        return False

    def _parse_ping_output(self, output: str) -> Dict[str, float]:
        """Parse RTT statistics with mean deviation support."""
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
        """Return distance and statistical margin of error (km)."""
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
        """Traceroute with IXP and border crossing detection."""
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

            hops = []
            ixps_detected = []
            for line in output.split('\n'):
                p = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                match = re.search(p, line)
                if match:
                    hops.append(match.group(1))
                    for ixp in self.IXP_PATTERNS:
                        if re.search(ixp, line, re.IGNORECASE):
                            ixps_detected.append(ixp)

            return {
                'host': host, 'hop_count': len(hops), 'hops': hops,
                'ixps_detected': list(set(ixps_detected)),
                'path_complexity': 'High' if len(hops) > 12 else 'Standard'
            }
        except Exception as e:
            return {'host': host, 'error': str(e)}

    def triangulate(self,
                    vantage_points: List[Dict[str, Any]]) \
            -> Tuple[float, float, float]:
        """Weighted multilateration for target localization."""
        if len(vantage_points) < 2:
            return 0.0, 0.0, 0.0
        total_w, w_lat, w_lon = 0.0, 0.0, 0.0
        for vp in vantage_points:
            w = 1.0 / max(0.1, vp['dist_km'])
            total_w += w
            w_lat += vp['lat'] * w
            w_lon += vp['lon'] * w
        score = min(1.0, len(vantage_points) / 4.0)
        return round(w_lat / total_w, 6), round(w_lon / total_w, 6), score

    async def run_triangulation(self, target_ip: str,
                                vp_data: List[Dict[str, Any]]) \
            -> Dict[str, Any]:
        """Full SIGINT-lite triangulation suite."""
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
                    'dist_km': res['distance_estimate']['km']
                })
                final[vp_info['id']] = res

        final['path_analysis'] = await self.traceroute(target_ip)
        if len(tri_data) >= 2:
            lat, lon, score = self.triangulate(tri_data)
            final['location_estimate'] = {
                'lat': lat, 'lon': lon, 'confidence': score
            }
        return final
