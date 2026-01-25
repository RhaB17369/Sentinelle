use sentinelle_domain::{PhoneIntelligencePort, PhoneIntel, PhoneIntelError, PhoneNumber};

pub struct RunPhoneIntel<'a> {
    port: &'a dyn PhoneIntelligencePort,
}

impl<'a> RunPhoneIntel<'a> {
    pub fn new(port: &'a dyn PhoneIntelligencePort) -> Self {
        Self { port }
    }

    pub fn execute(&self, phone: PhoneNumber) -> Result<PhoneIntel, PhoneIntelError> {
        self.port.analyze(phone)
    }
}