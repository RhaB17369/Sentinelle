"""
Telephone OSINT collector (lawful public data only).
Gathers intelligence from carrier identification and public exposure.
"""

import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging


class PhoneCollector:
    """Collect lawful OSINT intelligence on telephone numbers"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def collect(self, phone: str) -> Dict[str, Any]:
        """
        Collect all available lawful intelligence on a phone number.
        
        Args:
            phone: Phone number to investigate (international format preferred)
            
        Returns:
            Dictionary containing all collected intelligence
        """
        intelligence = {
            'phone': phone,
            'timestamp': datetime.now().isoformat(),
            'parsed': self._parse_phone(phone),
            'carrier': self._get_carrier(phone),
            'location': self._get_location(phone),
            'timezone': self._get_timezone(phone),
            'type': self._get_number_type(phone),
            'note': 'All data derived from public numbering plan information',
        }
        
        return intelligence
    
    def _parse_phone(self, phone: str) -> Optional[Dict[str, Any]]:
        """Parse and validate phone number"""
        try:
            # Try to parse without region first
            try:
                parsed = phonenumbers.parse(phone, None)
            except phonenumbers.NumberParseException:
                # Try with US as default region
                parsed = phonenumbers.parse(phone, "US")
            
            # Validate
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)
            
            parse_data = {
                'country_code': parsed.country_code,
                'national_number': parsed.national_number,
                'is_valid': is_valid,
                'is_possible': is_possible,
                'international_format': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
                ),
                'e164_format': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                ),
                'national_format': phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.NATIONAL
                ),
            }
            
            self.logger.info(f"Phone number parsed: {phone}")
            return parse_data
            
        except Exception as e:
            self.logger.warning(f"Failed to parse phone number {phone}: {e}")
            return None
    
    def _get_carrier(self, phone: str) -> Optional[str]:
        """Get carrier/operator information"""
        try:
            parsed = phonenumbers.parse(phone, None)
            carrier_name = carrier.name_for_number(parsed, "en")
            
            if carrier_name:
                self.logger.info(f"Carrier identified for {phone}: {carrier_name}")
                return carrier_name
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to get carrier for {phone}: {e}")
            return None
    
    def _get_location(self, phone: str) -> Optional[str]:
        """Get geographic location (country/region)"""
        try:
            parsed = phonenumbers.parse(phone, None)
            location = geocoder.description_for_number(parsed, "en")
            
            if location:
                self.logger.info(f"Location identified for {phone}: {location}")
                return location
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to get location for {phone}: {e}")
            return None
    
    def _get_timezone(self, phone: str) -> Optional[List[str]]:
        """Get timezone(s) for phone number"""
        try:
            parsed = phonenumbers.parse(phone, None)
            timezones = timezone.time_zones_for_number(parsed)
            
            if timezones:
                self.logger.info(f"Timezones identified for {phone}: {timezones}")
                return list(timezones)
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to get timezone for {phone}: {e}")
            return None
    
    def _get_number_type(self, phone: str) -> Optional[str]:
        """Get number type (mobile, fixed line, VoIP, etc.)"""
        try:
            parsed = phonenumbers.parse(phone, None)
            number_type = phonenumbers.number_type(parsed)
            
            type_map = {
                phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
                phonenumbers.PhoneNumberType.MOBILE: "mobile",
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
            
            type_str = type_map.get(number_type, "unknown")
            self.logger.info(f"Number type identified for {phone}: {type_str}")
            return type_str
            
        except Exception as e:
            self.logger.warning(f"Failed to get number type for {phone}: {e}")
            return None
