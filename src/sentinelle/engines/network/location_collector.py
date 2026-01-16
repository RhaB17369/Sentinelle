"""
Location OSINT collector.
Gathers intelligence from geocoding and geospatial data.
"""

import requests
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import logging
import time


class LocationCollector:
    """Collect OSINT intelligence on locations"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.geocoding_cache = {}
    
    def collect(self, location: str) -> Dict[str, Any]:
        """
        Collect all available intelligence on a location.
        
        Args:
            location: Location query (address, coordinates, place name)
            
        Returns:
            Dictionary containing all collected intelligence
        """
        # Check if location is coordinates
        coords = self._parse_coordinates(location)
        
        if coords:
            intelligence = {
                'query': location,
                'timestamp': datetime.now().isoformat(),
                'type': 'coordinates',
                'coordinates': coords,
                'reverse_geocode': self._reverse_geocode(coords),
            }
        else:
            intelligence = {
                'query': location,
                'timestamp': datetime.now().isoformat(),
                'type': 'place_name',
                'geocode': self._geocode(location),
            }
        
        return intelligence
    
    def _parse_coordinates(self, location: str) -> Optional[Tuple[float, float]]:
        """Parse coordinates from string (lat,lon)"""
        try:
            parts = location.split(',')
            if len(parts) == 2:
                lat = float(parts[0].strip())
                lon = float(parts[1].strip())
                
                # Validate ranges
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    return (lat, lon)
            
            return None
        except Exception:
            return None
    
    def _geocode(self, location: str) -> Optional[Dict[str, Any]]:
        """
        Geocode location string to coordinates.
        Uses OpenStreetMap Nominatim (free, rate-limited).
        """
        try:
            # Check cache
            if location in self.geocoding_cache:
                return self.geocoding_cache[location]
            
            # Rate limiting (Nominatim requires 1 request/second)
            time.sleep(1)
            
            response = requests.get(
                'https://nominatim.openstreetmap.org/search',
                params={
                    'q': location,
                    'format': 'json',
                    'limit': 1,
                },
                headers={
                    'User-Agent': 'SENTINNELLE/1.0 (OSINT Intelligence Platform)'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                results = response.json()
                
                if results:
                    result = results[0]
                    geo_data = {
                        'latitude': float(result['lat']),
                        'longitude': float(result['lon']),
                        'display_name': result.get('display_name'),
                        'type': result.get('type'),
                        'importance': result.get('importance'),
                        'bounding_box': result.get('boundingbox'),
                    }
                    
                    # Cache result
                    self.geocoding_cache[location] = geo_data
                    
                    self.logger.info(f"Geocoded location: {location}")
                    return geo_data
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to geocode location {location}: {e}")
            return None
    
    def _reverse_geocode(self, coords: Tuple[float, float]) -> Optional[Dict[str, Any]]:
        """
        Reverse geocode coordinates to location information.
        Uses OpenStreetMap Nominatim (free, rate-limited).
        """
        try:
            lat, lon = coords
            
            # Rate limiting
            time.sleep(1)
            
            response = requests.get(
                'https://nominatim.openstreetmap.org/reverse',
                params={
                    'lat': lat,
                    'lon': lon,
                    'format': 'json',
                },
                headers={
                    'User-Agent': 'SENTINNELLE/1.0 (OSINT Intelligence Platform)'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                geo_data = {
                    'display_name': result.get('display_name'),
                    'address': result.get('address', {}),
                    'type': result.get('type'),
                    'importance': result.get('importance'),
                }
                
                self.logger.info(f"Reverse geocoded coordinates: {coords}")
                return geo_data
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to reverse geocode {coords}: {e}")
            return None
