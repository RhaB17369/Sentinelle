import asyncio
import logging
from src.sentinelle.engines.network.latency_tracer import LatencyTracer

async def main():
    logging.basicConfig(level=logging.INFO)
    tracer = LatencyTracer()
    
    # Test local reachability (simulated or real)
    # Note: Running real pings in this environment might fail depending on permissions
    # But we can at least test the parsing logic if we mock the output
    
    print("--- Testing Intelligence Logic ---")
    
    # Mocking jitter for mobile detection
    mobile_rtts = [50.0, 85.0, 45.0, 120.0, 60.0]
    jitter_data = tracer._analyze_jitter_profile(mobile_rtts)
    print(f"Mobile Detection: {jitter_data}")
    
    # Mocking OS fingerprinting
    os_android = tracer._fingerprint_os(64, jitter_data)
    print(f"OS Detection (Mobile + TTL 64): {os_android}")
    
    os_win = tracer._fingerprint_os(128, {'type': 'Fixed/Fiber'})
    print(f"OS Detection (Fixed + TTL 128): {os_win}")
    
    # Mocking Proxy Detection
    proxy = tracer._detect_proxy_vpn_anomaly(150.0, 62, 25.0)
    print(f"Proxy Detection (TTL 62, RTT 150ms, High Jitter): {proxy}")

    # Mocking Triangulation
    vps = [
        {'id': 'NYC', 'lat': 40.7128, 'lon': -74.0060, 'dist_km': 100.0, 'mdev': 2.0},
        {'id': 'LDN', 'lat': 51.5074, 'lon': -0.1278, 'dist_km': 5000.0, 'mdev': 5.0},
        {'id': 'PAR', 'lat': 48.8566, 'lon': 2.3522, 'dist_km': 4800.0, 'mdev': 4.0}
    ]
    lat, lon, conf = tracer.triangulate(vps)
    print(f"Triangulation: {lat}, {lon} (Confidence: {conf})")

if __name__ == "__main__":
    asyncio.run(main())
