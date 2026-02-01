#![deny(warnings)]

use sentinelle_domain::{
    PhoneIntelligencePort, PhoneIntel, PhoneIntelError, PhoneNumber,
};

#[derive(Debug)]
pub struct PhoneIntelEngine;

impl PhoneIntelEngine {
    pub fn new(_opencage_key: Option<String>) -> Self {
        Self
    }
}

impl PhoneIntelligencePort for PhoneIntelEngine {
    fn analyze(&self, phone: PhoneNumber) -> Result<PhoneIntel, PhoneIntelError> {
        // Implémentation basique pour le moment
        Ok(PhoneIntel {
            phone_number: phone.clone(),
            is_valid: true,
            country: None,
            region: None,
            number_type: None,
            carrier: None,
            location: None,
            gps_coordinates: None,
            geocoding_error: None,
            error: None,
        })
    }
}