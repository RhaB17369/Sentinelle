#![deny(warnings)]

use sentinelle_application::usecases::RunIpIntelligence;
use sentinelle_infra_metrics::InMemoryMetrics;
use sentinelle_infra_osint_ip::CompositeIpIntelligence;
use std::env;
use std::net::IpAddr;

fn main() {
    // Exemple minimal : IP intelligence en ligne de commande
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: sentinelle-bin &lt;IP_ADDRESS&gt;");
        std::process::exit(1);
    }

    let ip: IpAddr = match args[1].parse() {
        Ok(ip) =&gt; ip,
        Err(_) =&gt; {
            eprintln!("Invalid IP address: {}", args[1]);
            std::process::exit(1);
        }
    };

    let http = reqwest::Client::new();
    let metrics = InMemoryMetrics::default();
    let ip_engine = CompositeIpIntelligence::new(http, metrics);

    let usecase = RunIpIntelligence::new(&ip_engine);

    match usecase.execute(ip) {
        Ok(intel) =&gt; {
            println!("IP Intelligence for {}", intel.ip);
            if let Some(country) = intel.country {
                println!("  Country      : {}", country);
            }
            if let Some(cc) = intel.country_code {
                println!("  Country Code : {}", cc);
            }
            if let Some(city) = intel.city {
                println!("  City         : {}", city);
            }
            if let Some(isp) = intel.isp {
                println!("  ISP          : {}", isp);
            }
            if let Some(asn) = intel.asn {
                println!("  ASN          : {}", asn);
            }
            if let (Some(lat), Some(lon)) = (intel.latitude, intel.longitude) {
                println!("  Location     : {}, {}", lat, lon);
            }
        }
        Err(e) =&gt; {
            eprintln!("IP intelligence error: {}", e);
            std::process::exit(1);
        }
    }
}