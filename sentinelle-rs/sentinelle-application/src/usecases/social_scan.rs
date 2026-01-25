use sentinelle_domain::{
    SocialIntelligencePort, SocialScanResult, SocialScanError, SocialTarget,
};

pub struct RunSocialScan<'a> {
    social_port: &'a dyn SocialIntelligencePort,
}

impl<'a> RunSocialScan<'a> {
    pub fn new(social_port: &'a dyn SocialIntelligencePort) -> Self {
        Self { social_port }
    }

    pub fn execute(&self, target: SocialTarget) -> Result<SocialScanResult, SocialScanError> {
        self.social_port.scan(target)
    }
}