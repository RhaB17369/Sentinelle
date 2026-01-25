#![deny(warnings)]

use sentinelle_application::usecases::{
    RunIpIntelligence,
    RunMailScan,
    RunSocialScan,
    RunSigintTcp,
    RunSigintIcmp,
    RunSigintTraceroute,
};
use sentinelle_domain::{Email, SocialTarget};
use sentinelle_infra_metrics::InMemoryMetrics;
use sentinelle_infra_osint_ip::CompositeIpIntelligence;
use sentinelle_infra_osint_mail::MailOsintEngine;
use sentinelle_infra_osint_social::SocialOsintEngine;
use sentinelle_infra_latency_raw::{TcpSigintEngine, IcmpSigintEngine, TracerouteSigintEngine};
use std::io::{self, Write};
use std::net::IpAddr;

/// CLI minimaliste, remplacera progressivement app.py (Rich-based).
/// Ici, on teste l'intégration des use cases et des adapters, y compris SIGINT.
pub fn run_cli() {
    loop {
        println!("SENTINELLE CLI (Rust) - sélectionnez un module :");
        println!("1) IP Intelligence");
        println!("2) Mail OSINT");
        println!("3) Social OSINT");
        println!("4) SIGINT TCP");
        println!("5) SIGINT ICMP");
        println!("6) SIGINT Traceroute");
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
            "4" => run_sigint_tcp(),
            "5" => run_sigint_icmp(),
            "6" => run_sigint_traceroute(),
            "q" | "Q" => break,
            _ => println!("Choix invalide"),
        }
    }
}

fn read_ip(prompt: &str) -> Option<IpAddr> {
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut ip_s = String::new();
    if io::stdin().read_line(&mut ip_s).is_err() {
        eprintln!("Erreur de lecture");
        return None;
    }
    let ip_s = ip_s.trim();
    match ip_s.parse() {
        Ok(ip) => Some(ip),
        Err(_) => {
            eprintln!("Adresse IP invalide: {}", ip_s);
            None
        }
    }
}

fn run_ip() {
    let Some(ip) = read_ip("IP cible: ") else {
        return;
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

fn run_sigint_tcp() {
    let Some(ip) = read_ip("IP cible (SIGINT TCP): ") else {
        return;
    };

    print!("Port cible (par défaut 443): ");
    let _ = io::stdout().flush();
    let mut p = String::new();
    if io::stdin().read_line(&mut p).is_err() {
        eprintln!("Erreur de lecture");
        return;
    }
    let port: u16 = p.trim().parse().unwrap_or(443);

    let engine = TcpSigintEngine::new();
    let usecase = RunSigintTcp::new(&engine);

    match usecase.execute(ip, port) {
        Ok(res) => {
            println!("SIGINT TCP pour {}:{}", res.target, res.port);
            if let Some(fp) = res.fingerprint {
                println!("  Window size : {}", fp.window_size);
                println!("  Options     : {:?}", fp.options);
                println!("  WScale      : {:?}", fp.wscale);
                println!("  SACK        : {}", fp.sack_permitted);
                println!("  TS val/Ecr  : {:?} / {:?}", fp.ts_val, fp.ts_ecr);
                println!("  TTL         : {:?}", fp.ttl);
                println!("  IP ID       : {:?}", fp.ip_id);
            } else {
                println!("  Aucun fingerprint TCP obtenu");
            }
            if let Some(skew) = res.clock_skew {
                println!("  Clock skew  : {} ({} samples)", skew.hz, skew.sample_count);
            }
            if let Some(os) = res.os_guess {
                println!("  OS guess    : {}", os);
            }
        }
        Err(e) => eprintln!("Erreur SIGINT TCP: {}", e),
    }
}

fn run_sigint_icmp() {
    let Some(ip) = read_ip("IP cible (SIGINT ICMP): ") else {
        return;
    };

    let engine = IcmpSigintEngine::new();
    let usecase = RunSigintIcmp::new(&engine);

    match usecase.execute(ip) {
        Ok(res) => {
            println!("SIGINT ICMP pour {}", res.target);
            if let Some(series) = res.ip_id_series {
                println!("  IP IDs      : {:?}", series.ids);
                println!("  Classification : {}", series.classification);
            } else {
                println!("  Aucune IP ID series disponible");
            }
            if let Some(skew) = res.clock_skew {
                println!("  Clock skew  : {} ({} samples)", skew.hz, skew.sample_count);
            }
        }
        Err(e) => eprintln!("Erreur SIGINT ICMP: {}", e),
    }
}

fn run_sigint_traceroute() {
    let Some(ip) = read_ip("IP cible (SIGINT Traceroute): ") else {
        return;
    };

    print!("Max hops (par défaut 20): ");
    let _ = io::stdout().flush();
    let mut h = String::new();
    if io::stdin().read_line(&mut h).is_err() {
        eprintln!("Erreur de lecture");
        return;
    }
    let max_hops: u8 = h.trim().parse().unwrap_or(20);

    let engine = TracerouteSigintEngine::new();
    let usecase = RunSigintTraceroute::new(&engine);

    match usecase.execute(ip, max_hops) {
        Ok(res) => {
            println!("SIGINT Traceroute pour {}", res.target);
            for hop in res.hops {
                println!(
                    "  {:2} {}  rtt={:?}  ASN={:?}  CC={:?}  Owner={:?}",
                    hop.hop_index, hop.ip, hop.rtt_ms, hop.asn, hop.country, hop.owner
                );
            }
            println!("AS path : {:?}", res.as_path);
            println!("IXPs    : {:?}", res.ixps);
        }
        Err(e) => eprintln!("Erreur SIGINT Traceroute: {}", e),
    }
}