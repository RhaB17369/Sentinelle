
"""
Phone Tracer Intelligence Module
Refactored from Tkinter GUI to CLI-compatible module
Provides comprehensive phone number geolocation and intelligence gathering

Security Note: API keys should be stored in environment variables:
    - OPENCAGE_API_KEY: OpenCage Geocoding API key
    
Example:
    export OPENCAGE_API_KEY="your_api_key_here"
"""

import os
import sys
import logging
import requests
from typing import Optional, Dict, Any
from dataclasses import dataclass

import phonenumbers
from phonenumbers import geocoder

try:
    from opencage.geocoder import OpenCageGeocode
    OPENCAGE_AVAILABLE = True
except ImportError:
    OPENCAGE_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class PhoneTracerResult:
    """Structure for phone tracer results"""
    phone_number: str
    is_valid: bool
    country: Optional[str] = None
    region: Optional[str] = None
    number_type: Optional[str] = None
    carrier: Optional[str] = None
    location: Optional[str] = None
    gps_coordinates: Optional[Dict[str, float]] = None
    geocoding_error: Optional[str] = None
    error: Optional[str] = None


class PhoneTracer:
    """
    Advanced Phone Tracer Intelligence Module
    Handles phone number parsing, geolocation, and GPS coordinate retrieval
    Compatible with SENTINELLE CLI infrastructure
    
    Environment Variables:
        OPENCAGE_API_KEY: Your OpenCage Geocoding API key (required for GPS coordinates)
    """
    
    def __init__(self, opencage_api_key: Optional[str] = None):
        """
        Initialize PhoneTracer with optional OpenCage API key
        
        Args:
            opencage_api_key: OpenCage Geocoding API key. If not provided,
                            will attempt to load from OPENCAGE_API_KEY environment variable.
                            
        Raises:
            Warning: If no API key is provided, GPS coordinates cannot be retrieved.
        """
        # Try to get API key from parameter, then environment variable
        self.opencage_api_key = opencage_api_key or os.getenv('OPENCAGE_API_KEY')
        
        if not self.opencage_api_key and OPENCAGE_AVAILABLE:
            logger.warning(
                "⚠️  OpenCage API key not found. "
                "Set OPENCAGE_API_KEY environment variable to enable GPS coordinate retrieval. "
                "Export it like: export OPENCAGE_API_KEY='your_key_here'"
            )
        
        self.logger = logger
        
    def trace_phone(self, phone_number: str) -> PhoneTracerResult:
        """
        Trace a phone number and gather intelligence
        
        Args:
            phone_number: Phone number to trace (with country code, e.g., +1 555 1234567)
            
        Returns:
            PhoneTracerResult object with complete intelligence
        """
        result = PhoneTracerResult(phone_number=phone_number, is_valid=False)
        
        try:
            # Parse phone number
            parsed_number = phonenumbers.parse(phone_number)
            
            # Validate phone number
            if not phonenumbers.is_valid_number(parsed_number):
                result.error = "Invalid phone number format"
                return result
            
            result.is_valid = True
            
            # Extract country and region information
            result.country = phonenumbers.region_code_for_number(parsed_number)
            result.region = geocoder.description_for_number(parsed_number, "en")
            
            # Get number type (mobile, fixed-line, etc.)
            number_type = phonenumbers.number_type(parsed_number)
            result.number_type = self._format_number_type(number_type)
            
            # Get carrier information if available
            try:
                from phonenumbers import carrier
                result.carrier = carrier.name_for_number(parsed_number, "en")
            except Exception as e:
                logger.debug(f"Could not retrieve carrier info: {e}")
            
            # Get location description
            result.location = geocoder.description_for_number(parsed_number, "en")
            country_full = geocoder.country_name_for_number(parsed_number, "en")
            
            # Get GPS coordinates if available
            # Try specific location with country name first
            if result.location and country_full:
                result.gps_coordinates, result.geocoding_error = self._get_gps_coordinates(f"{result.location}, {country_full}", result.country)
            
            # Fallback to full country name
            if not result.gps_coordinates and country_full:
                result.gps_coordinates, result.geocoding_error = self._get_gps_coordinates(country_full, result.country)
                
            # Final fallback to country code if everything else fails (best effort)
            if not result.gps_coordinates and result.country:
                result.gps_coordinates, result.geocoding_error = self._get_gps_coordinates(result.country, result.country)
            
            return result
            
        except phonenumbers.NumberParseException as e:
            result.error = f"Number parsing error: {str(e)}"
            return result
        except Exception as e:
            result.error = f"Unexpected error during phone tracing: {str(e)}"
            logger.exception("Error in trace_phone")
            return result
    
    def _format_number_type(self, number_type: int) -> str:
        """Convert phonenumbers number type to human-readable string"""
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
            phonenumbers.PhoneNumberType.VOIP: "voip",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
            phonenumbers.PhoneNumberType.PAGER: "pager",
            phonenumbers.PhoneNumberType.UAN: "uan",
            phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
            phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
        }
        return type_map.get(number_type, "unknown")
    
    def _get_gps_coordinates(self, location: str, country_code: Optional[str] = None) -> tuple:
        """
        Get GPS coordinates from location description using OpenCage API
        Uses direct API call as fallback if library is not installed
        
        Args:
            location: Location description (city, region, etc.)
            country_code: ISO 3166-1 alpha-2 country code for better accuracy
            
        Returns:
            Tuple of (coordinates_dict or None, error_message or None)
        """
        if not self.opencage_api_key:
            return None, "OPENCAGE_API_KEY not configured"
        
        # Try library first if available
        if OPENCAGE_AVAILABLE:
            try:
                geocoder_client = OpenCageGeocode(self.opencage_api_key)
                geocode_args = {}
                if country_code:
                    geocode_args['countrycode'] = country_code.lower()
                    
                results = geocoder_client.geocode(location, **geocode_args)
                
                if results and len(results) > 0:
                    coordinates = {
                        'lat': results[0]['geometry']['lat'],
                        'lng': results[0]['geometry']['lng']
                    }
                    logger.info(f"GPS coordinates (library) obtained for {location}: {coordinates}")
                    return coordinates, None
            except Exception as e:
                logger.debug(f"Library geocoding failed, trying API fallback: {e}")

        # Direct API Fallback (Standard requests)
        try:
            url = "https://api.opencagedata.com/geocode/v1/json"
            params = {
                'q': location,
                'key': self.opencage_api_key,
                'limit': 1
            }
            if country_code:
                params['countrycode'] = country_code.lower()
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                if results:
                    coordinates = {
                        'lat': results[0]['geometry']['lat'],
                        'lng': results[0]['geometry']['lng']
                    }
                    logger.info(f"GPS coordinates (API) obtained for {location}: {coordinates}")
                    return coordinates, None
                return None, "No results found for this location"
            else:
                return None, f"OpenCage API Error: {response.status_code}"
                
        except Exception as e:
            logger.warning(f"Failed to retrieve GPS coordinates via API: {e}")
            return None, str(e)
    
    def trace_phone_batch(self, phone_numbers: list) -> list:
        """
        Trace multiple phone numbers
        
        Args:
            phone_numbers: List of phone numbers to trace
            
        Returns:
            List of PhoneTracerResult objects
        """
        return [self.trace_phone(phone) for phone in phone_numbers]


def format_result_table(result: PhoneTracerResult) -> str:
    """
    Format PhoneTracerResult as a readable table
    
    Args:
        result: PhoneTracerResult object
        
    Returns:
        Formatted string representation
    """
    if result.error:
        return f"❌ Error: {result.error}"
    
    if not result.is_valid:
        return "❌ Invalid phone number"
    
    output = [
        "📱 Phone Tracer Report",
        "=" * 50,
        f"Phone Number: {result.phone_number}",
        f"Valid: ✓",
        f"Country Code: {result.country}",
        f"Region: {result.region}",
        f"Type: {result.number_type}",
    ]
    
    if result.carrier:
        output.append(f"Carrier: {result.carrier}")
    
    if result.location:
        output.append(f"Location: {result.location}")
    
    if result.gps_coordinates:
        lat = result.gps_coordinates.get('lat', 'N/A')
        lng = result.gps_coordinates.get('lng', 'N/A')
        if lat != 'N/A' and lng != 'N/A':
            output.append(f"📍 GPS Coordinates: {lat:.4f}, {lng:.4f}")
            output.append(f"   Latitude:  {lat:.6f}")
            output.append(f"   Longitude: {lng:.6f}")
    else:
        output.append(f"📍 GPS Coordinates: Not available (set OPENCAGE_API_KEY for GPS)")
    
    output.append("=" * 50)
    return "\n".join(output)


# CLI-compatible main function
def main():
    """
    Interactive CLI mode for PhoneTracer
    Allows user to input phone numbers and get intelligence
    """
    tracer = PhoneTracer()
    
    print("\n🌐 SENTINELLE Phone Tracer Intelligence Module")
    print("=" * 60)
    print("Enter phone numbers with international format (e.g., +1 555 1234567)")
    print("Type 'quit' to exit\n")
    
    while True:
        try:
            phone_input = input("📱 Enter phone number: ").strip()
            
            if phone_input.lower() == 'quit':
                print("\n✓ Exiting Phone Tracer...")
                break
            
            if not phone_input:
                continue
            
            result = tracer.trace_phone(phone_input)
            print("\n" + format_result_table(result) + "\n")
            
        except KeyboardInterrupt:
            print("\n\n✓ Phone Tracer interrupted by user")
            break
        except Exception as e:
            print(f"❌ Error: {e}\n")


if __name__ == "__main__":
    main()
