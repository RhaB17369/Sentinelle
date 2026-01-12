"""
Telephone OSINT collector (lawful public data only).
Gathers intelligence from carrier identification, geolocation, and GPS coordinates.
DEPRECATED: Use intelligence.phone_intelligence.PhoneIntelligence instead.
This module is maintained for backward compatibility only.
"""

# Import from unified phone intelligence module
from intelligence.phone_intelligence import PhoneIntelligence as PhoneCollector

# Backward compatibility
__all__ = ['PhoneCollector']
                phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
                phonenumbers.PhoneNumberType.VOIP: "voip",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
                phonenumbers.PhoneNumberType.PAGER: "pager",
                phonenumbers.PhoneNumberType.UAN: "uan",
                phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
                phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
            }
            
            type_str = type_map.get(number_type, "unknown")
            self.logger.info(f"Number type identified for {phone}: {type_str}")
            return type_str
            
        except Exception as e:
            self.logger.warning(f"Failed to get number type for {phone}: {e}")
            return None
    
    def _get_gps_coordinates(self, location: str) -> Optional[Dict[str, float]]:
        """
        Get GPS coordinates from location description using OpenCage Geocoding API.
        Integrates PhoneTracer functionality.
        """
        if not self.opencage_api_key:
            return None
        
        try:
            from opencage.geocoder import OpenCageGeocode
            
            geocoder = OpenCageGeocode(self.opencage_api_key)
            results = geocoder.geocode(location)
            
            if results and len(results) > 0:
                lat = results[0]['geometry']['lat']
                lng = results[0]['geometry']['lng']
                
                self.logger.info(f"GPS coordinates obtained for {location}: {lat}, {lng}")
                
                return {
                    'latitude': lat,
                    'longitude': lng,
                    'formatted': f"{lat},{lng}"
                }
            
            return None
            
        except ImportError:
            self.logger.warning("opencage library not installed. Install with: pip install opencage")
            return None
        except Exception as e:
            self.logger.warning(f"Failed to get GPS coordinates for {location}: {e}")
            return None