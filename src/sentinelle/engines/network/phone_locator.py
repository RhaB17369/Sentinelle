
"""
Phone Tracer Intelligence Module
Refactored from Tkinter GUI to CLI-compatible module
Provides comprehensive phone number geolocation and intelligence gathering (Async version)
"""

import os
import sys
import logging
import httpx
import asyncio
from typing import Optional, Dict, Any, Tuple
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


from ...core.engine import BaseEngine, EventType

__version__ = "1.2.0"

class PhoneTracer(BaseEngine):
    """
    Advanced Phone Tracer Intelligence Module (Async)
    Handles phone number parsing, geolocation, and GPS coordinate retrieval
    """
    
    def __init__(self, opencage_api_key: Optional[str] = None, client: Optional[httpx.AsyncClient] = None):
        super().__init__()
        self.opencage_api_key = opencage_api_key or os.getenv('OPENCAGE_API_KEY')
        self.client = client
        self.logger = logger
        
    async def _get_client(self) -> httpx.AsyncClient:
        if self.client is None or self.client.is_closed:
            self.client = httpx.AsyncClient(timeout=10, follow_redirects=True)
        return self.client

    async def run(self, phone_number: str) -> PhoneTracerResult:
        """Trace a phone number and gather intelligence (Async)"""
        result = PhoneTracerResult(phone_number=phone_number, is_valid=False)
        self.log(f"🔍 Starting phone analysis for {phone_number}...")
        
        try:
            # Parse phone number
            parsed_number = phonenumbers.parse(phone_number)
            self.progress(advance=1, description="Validating number")
            
            # Validate phone number
            if not phonenumbers.is_valid_number(parsed_number):
                result.error = "Invalid phone number format"
                self.error(result.error)
                return result
            
            result.is_valid = True
            
            # Extract country and region information
            result.country = phonenumbers.region_code_for_number(parsed_number)
            result.region = geocoder.description_for_number(parsed_number, "en")
            self.progress(advance=1, description="Extracting location")
            
            # Get number type
            number_type = phonenumbers.number_type(parsed_number)
            result.number_type = self._format_number_type(number_type)
            
            # Get carrier information
            try:
                from phonenumbers import carrier
                result.carrier = carrier.name_for_number(parsed_number, "en")
                self.log(f"📡 Carrier identified: {result.carrier}")
            except Exception as e:
                logger.debug(f"Could not retrieve carrier info: {e}")
            
            # Get location description
            result.location = geocoder.description_for_number(parsed_number, "en")
            country_full = geocoder.country_name_for_number(parsed_number, "en")
            
            self.progress(advance=1, description="Geocoding coordinates")
            # Get GPS coordinates (Async network calls)
            if result.location and country_full:
                res = await self._get_gps_coordinates(f"{result.location}, {country_full}", result.country)
                result.gps_coordinates, result.geocoding_error = res
            
            # Emit data for partial updates if needed
            self.emit(EventType.DATA, data=result)
            
            self.progress(advance=1, description="Analysis complete")
            self.emit(EventType.COMPLETE, data=result)
            return result
            
        except phonenumbers.NumberParseException as e:
            result.error = f"Number parsing error: {str(e)}"
            self.error(result.error)
            return result
        except Exception as e:
            result.error = f"Unexpected error during phone tracing: {str(e)}"
            self.error(result.error)
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
    
    async def _get_gps_coordinates(self, location: str, country_code: Optional[str] = None) -> Tuple[Optional[Dict[str, float]], Optional[str]]:
        """Get GPS coordinates from location description using OpenCage API (Async)"""
        if not self.opencage_api_key:
            return None, "OPENCAGE_API_KEY not configured"
        
        # OpenCage library is synchronous, so we'll prefer direct API call with httpx
        try:
            client = await self._get_client()
            url = "https://api.opencagedata.com/geocode/v1/json"
            params = {
                'q': location,
                'key': self.opencage_api_key,
                'limit': 1
            }
            if country_code:
                params['countrycode'] = country_code.lower()
            
            response = await client.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                if results:
                    coordinates = {
                        'lat': results[0]['geometry']['lat'],
                        'lng': results[0]['geometry']['lng']
                    }
                    logger.info(f"GPS coordinates obtained for {location}: {coordinates}")
                    return coordinates, None
                return None, "No results found for this location"
            else:
                return None, f"OpenCage API Error: {response.status_code}"
                
        except Exception as e:
            logger.warning(f"Failed to retrieve GPS coordinates via API: {e}")
            return None, str(e)
    
    async def trace_phone_batch(self, phone_numbers: list) -> list:
        """Trace multiple phone numbers in parallel (Async)"""
        tasks = [self.run(phone) for phone in phone_numbers]
        return await asyncio.gather(*tasks)


def format_result_table(result: PhoneTracerResult) -> str:
    """Format PhoneTracerResult as a readable table"""
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
        lat = result.gps_coordinates.get('lat', 0)
        lng = result.gps_coordinates.get('lng', 0)
        output.append(f"📍 GPS Coordinates: {lat:.4f}, {lng:.4f}")
    else:
        output.append(f"📍 GPS Coordinates: Not available")
    
    output.append("=" * 50)
    return "\n".join(output)


async def main_async():
    """Interactive CLI mode for PhoneTracer (Async)"""
    tracer = PhoneTracer()
    
    print("\n🌐 SENTINELLE Phone Tracer Intelligence (Async)")
    print("=" * 60)
    print("Enter phone numbers with international format (e.g., +1 555 1234567)")
    print("Type 'quit' to exit\n")
    
    while True:
        try:
            phone_input = await asyncio.get_event_loop().run_in_executor(None, input, "📱 Enter phone number: ")
            phone_input = phone_input.strip()
            
            if phone_input.lower() == 'quit':
                print("\n✓ Exiting Phone Tracer...")
                break
            
            if not phone_input:
                continue
            
            result = await tracer.run(phone_input)
            print("\n" + format_result_table(result) + "\n")
            
        except KeyboardInterrupt:
            print("\n\n✓ Phone Tracer interrupted by user")
            break
        except Exception as e:
            print(f"❌ Error: {e}\n")


if __name__ == "__main__":
    asyncio.run(main_async())
