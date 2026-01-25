#![deny(warnings)]

use sentinelle_application::usecases::{RunIpIntelligence, RunMailScan, RunSocialScan};
use sentinelle_domain::{Email, SocialTarget};
use sentinelle_infra_metrics::InMemoryMetrics;
use sentinelle_infra_osint_ip::CompositeIpIntelligence;
use sentinelle_infra_osint_mail::MailOsintEngine;
use sentinelle_infra_osint_social::SocialOsintEngine;
use std::io::{self, Write};
use std::net::IpAddr;

/// CLI minimaliste, remplacera progressivement app.py (Rich-based).
/// Ici, on teste simplement l'intégration des use cases et des adapters.
pub fn run_cli() {
    loop {
        println!("SENTINELLE CLI (Rust) - sélectionnez un module :");
        println!("1) IP Intelligence");
        println!("2) Mail OSINT");
        println!("3) Social OSINT");
        println!("q) Quitter");
        print!("> ");
        let _ = io::stdout().flush();

        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            eprintln!("Lecture entrée échouée");
            continue;
        }

        let choice = line.trim();
        match choice {
            "1" => run_ip(),
            "2" => run_mail(),
            "3" => run_social(),
            "q" | "Q" => break,
            _ => println!("Choix invalide"),
        }
    }
}

fn run_ip() {
    print!("IP cible: ");
    let _ = io::stdout().flush();
    let mut ip_s = String::new();
    if io::stdin().read_line(&mut ip_s).is_err() {
        eprintln!("Erreur de lecture");
        return;
    }

    let ip_s = ip_s.trim();
    let ip: IpAddr = match ip_s.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Adresse IP invalide: {}", ip_s);
            return;
        }
    };

    let http = reqwest::Client::new();
    let metrics = InMemoryMetrics::default();
    let ip_engine = CompositeIpIntelligence::new(http, metrics);
    let usecase = RunIpIntelligence::new(&ip_engine);

    match usecase.execute(ip) {
        Ok(intel) => {
            println!("Résultats IP pour {}", intel.ip);
            if let Some(country) = intel.country {
                println!("  Pays        : {}", country);
            }
            if let Some(city) = intel.city {
                println!("  Ville       : {}", city);
            }
            if let Some(isp) = intel.isp {
                println!("  ISP         : {}", isp);
            }
        }
        Err(e) => eprintln!("Erreur IP: {}", e),
    }
}

fn run_mail() {
    print!("Email cible: ");
    let _ = io::stdout().flush();
    let mut email_s = String::new();
    if io::stdin().read_line(&mut email_s).is_err() {
        eprintln!("Erreur de lecture");
        return;
    }

    let email_s = email_s.trim();
    let email = match Email::parse(email_s) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Email invalide: {}", e);
            return;
        }
    };

    let engine = MailOsintEngine::new_with_default_probes();
    let usecase = RunMailScan::new(&engine);

    match usecase.execute(email) {
        Ok(summary) => {
            println!("Résultats Mail pour {}", summary.email.as_str());
            for svc in summary.services {
                println!(
                    "  {:20} exists={} error={}",
                    svc.service_name, svc.exists, svc.error
                );
            }
        }
        Err(e) => eprintln!("Erreur Mail: {}", e),
    }
}

fn run_social() {
    print!("Username cible: ");
    let _ = io::stdout().flush();
    let mut u = String::new();
    if io::stdin().read_line(&mut u).is_err() {
        eprintln!("Erreur de lecture");
        return;
    }

    let username = u.trim().to_string();
    if username.is_empty() {
        eprintln!("Username vide");
        return;
    }

    let engine = SocialOsintEngine::new_with_default_probes();
    let usecase = RunSocialScan::new(&engine);

    let target = SocialTarget::Username(username);
    match usecase.execute(target) {
        Ok(result) => {
            println!("Résultats Social pour cible");
            for acc in result.accounts {
                println!(
                    "  {:20} status={:?} url={:?}",
                    acc.site_name, acc.status, acc.profile_url
                );
            }
        }
        Err(e) => eprintln!("Erreur Social: {}", e),
    }
}