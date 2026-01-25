#![deny(warnings)]

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use sentinelle_application::usecases::{
    RunIpIntelligence,
    RunMailScan,
    RunSocialScan,
    RunSigintTcp,
    RunSigintIcmp,
    RunSigintTraceroute,
    RunDomainIntel,
    RunEmailRecon,
};
use sentinelle_domain::{Email, SocialTarget};
use sentinelle_infra_latency_raw::{TcpSigintEngine, IcmpSigintEngine, TracerouteSigintEngine};
use sentinelle_infra_metrics::InMemoryMetrics;
use sentinelle_infra_osint_ip::CompositeIpIntelligence;
use sentinelle_infra_osint_mail::MailOsintEngine;
use sentinelle_infra_osint_social::SocialOsintEngine;
use sentinelle_infra_email_recon::EmailReconEngine;
use sentinelle_infra_domain_intel::DomainIntelEngine;
use sentinelle_infra_cache_sqlite::SqliteCache;
use std::io;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};

const BANNER: &[&str] = &[
    "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗██╗     ███████╗",
    "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██║     ██╔════╝",
    "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║██║     █████╗  ",
    "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██║     ██╔══╝  ",
    "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗",
    "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝",
];

enum View {
    MainMenu,
    IpInput,
    MailInput,
    SocialInput,
    SigintTcpInput,
    SigintIcmpInput,
    SigintTracerouteInput,
    ProfileIpInput,
    ProfileEmailInput,
}

#[derive(Serialize, Deserialize)]
struct CachedLog {
    lines: Vec<String>,
}

struct App {
    view: View,
    input: String,
    log: Vec<String>,
    selected_menu: usize,
    cache: SqliteCache,
}

impl App {
    fn new() -> Self {
        let cache = SqliteCache::new("sentinelle_cache.db").unwrap_or_else(|_| {
            // En dernier recours, un cache en mémoire temp (fichier éphémère)
            SqliteCache::new(":memory:").expect("cache sqlite")
        });
        Self {
            view: View::MainMenu,
            input: String::new(),
            log: Vec::new(),
            selected_menu: 0,
            cache,
        }
    }

    fn log_line(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 200 {
            self.log.drain(0..self.log.len() - 200);
        }
    }

    fn cache_load(&mut self, key: &str) -> bool {
        if let Ok(Some(cached)) = self.cache.get_json::<CachedLog>(key) {
            self.log = cached.lines;
            true
        } else {
            false
        }
    }

    fn cache_save(&self, key: &str) {
        let cached = CachedLog {
            lines: self.log.clone(),
        };
        let _ = self.cache.set_json(key, &cached);
    }
}

pub fn run_cli() -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();

    let res = main_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(e) = res {
        eprintln!("Erreur TUI: {}", e);
    }

    Ok(())
}

fn main_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), io::Error> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if crossterm::event::poll(std::time::Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(key) => {
                    if !handle_key(app, key)? {
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn ui&lt;B: ratatui::backend::Backend&gt;(f: &amp;mut ratatui::Frame&lt;B&gt;, app: &amp;App) {
    // Layout global: header, zone principale, barre de statut
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(BANNER.len() as u16 + 1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(f.size());

    // Header ASCII
    let banner_lines: Vec&lt;Spans&gt; = BANNER
        .iter()
        .map(|line| Spans::from(Span::styled(
            *line,
            Style::default().add_modifier(Modifier::BOLD),
        )))
        .collect();
    let header = Paragraph::new(banner_lines)
        .block(Block::default().borders(Borders::ALL).title("SENTINELLE OSINT / SIGINT"));
    f.render_widget(header, outer[0]);

    // Zone principale: à la bpytop, panneau gauche (menu) + panneau droit (input + output)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(outer[1]);

    // Panneau gauche: menu
    {
        let items = vec![
            "IP Intelligence",
            "Mail OSINT",
            "Social OSINT",
            "SIGINT TCP",
            "SIGINT ICMP",
            "SIGINT Traceroute",
            "Profil complet IP",
            "Profil complet Email",
            "Quitter",
        ];
        let list_items: Vec&lt;ListItem&gt; = items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                if i == app.selected_menu {
                    ListItem::new(Spans::from(Span::styled(
                        *item,
                        Style::default().add_modifier(Modifier::REVERSED),
                    )))
                } else {
                    ListItem::new(Spans::from(Span::raw(*item)))
                }
            })
            .collect();
        let menu = List::new(list_items)
            .block(Block::default().borders(Borders::ALL).title("Modules"));
        f.render_widget(menu, main_chunks[0]);
    }

    // Panneau droit: input en haut, output en bas
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(main_chunks[1]);

    // Input / cible courante
    let prompt = match app.view {
        View::IpInput =&gt; "IP cible (IP Intel): ",
        View::MailInput =&gt; "Email cible: ",
        View::SocialInput =&gt; "Username cible: ",
        View::SigintTcpInput =&gt; "IP:port pour SIGINT TCP (ex: 1.2.3.4:443): ",
        View::SigintIcmpInput =&gt; "IP cible (SIGINT ICMP): ",
        View::SigintTracerouteInput =&gt; "IP cible (SIGINT Traceroute): ",
        View::ProfileIpInput =&gt; "IP cible (Profil complet IP): ",
        View::ProfileEmailInput =&gt; "Email cible (Profil complet Email): ",
        View::MainMenu =&gt; "Sélectionnez un module et appuyez sur Entrée",
    };
    let input = Paragraph::new(app.input.as_str())
        .block(Block::default().borders(Borders::ALL).title(prompt));
    f.render_widget(input, right_chunks[0]);

    // Log / output pane (tableau dynamique de lignes)
    let log_lines: Vec&lt;Spans&gt; = app
        .log
        .iter()
        .rev()
        .take((right_chunks[1].height as usize).saturating_sub(2))
        .rev()
        .map(|l| Spans::from(Span::raw(l.as_str())))
        .collect();

    let log_widget = Paragraph::new(log_lines)
        .block(Block::default().borders(Borders::ALL).title("Output"));
    f.render_widget(log_widget, right_chunks[1]);

    // Status bar
    let status = Paragraph::new("Esc: retour / q: quitter")
        .style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(status, outer[2]);
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<bool, io::Error> {
    match app.view {
        View::MainMenu => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(false),
            KeyCode::Up => {
                if app.selected_menu > 0 {
                    app.selected_menu -= 1;
                }
            }
            KeyCode::Down => {
                if app.selected_menu < 8 {
                    app.selected_menu += 1;
                }
            }
            KeyCode::Enter => {
                app.input.clear();
                app.log.clear();
                match app.selected_menu {
                    0 => app.view = View::IpInput,
                    1 => app.view = View::MailInput,
                    2 => app.view = View::SocialInput,
                    3 => app.view = View::SigintTcpInput,
                    4 => app.view = View::SigintIcmpInput,
                    5 => app.view = View::SigintTracerouteInput,
                    6 => app.view = View::ProfileIpInput,
                    7 => app.view = View::ProfileEmailInput,
                    8 => return Ok(false),
                    _ => {}
                }
            }
            _ => {}
        },
        _ => match key.code {
            KeyCode::Esc => {
                app.view = View::MainMenu;
                app.input.clear();
            }
            KeyCode::Enter => {
                // Valider l'input et lancer le module correspondant
                let input = app.input.trim().to_string();
                match app.view {
                    View::IpInput => run_ip(app, &input),
                    View::MailInput => run_mail(app, &input),
                    View::SocialInput => run_social(app, &input),
                    View::SigintTcpInput => run_sigint_tcp(app, &input),
                    View::SigintIcmpInput => run_sigint_icmp(app, &input),
                    View::SigintTracerouteInput => run_sigint_traceroute(app, &input),
                    View::ProfileIpInput => run_profile_ip(app, &input),
                    View::ProfileEmailInput => run_profile_email(app, &input),
                    View::MainMenu => {}
                }
                app.view = View::MainMenu;
                app.input.clear();
            }
            KeyCode::Char(c) => {
                app.input.push(c);
            }
            KeyCode::Backspace => {
                app.input.pop();
            }
            _ => {}
        },
    }
    Ok(true)
}

// ---------- Handlers ----------

fn run_ip(app: &mut App, input: &str) {
    let ip: IpAddr = match input.parse() {
        Ok(ip) => ip,
        Err(_) => {
            app.log_line(format!("Adresse IP invalide: {}", input));
            return;
        }
    };

    let http = reqwest::Client::new();
    let metrics = InMemoryMetrics::default();
    let ip_engine = CompositeIpIntelligence::new(http, metrics);
    let usecase = RunIpIntelligence::new(&ip_engine);

    match usecase.execute(ip) {
        Ok(intel) => {
            app.log_line(format!("IP Intelligence pour {}", intel.ip));
            if let Some(country) = intel.country {
                app.log_line(format!("  Pays        : {}", country));
            }
            if let Some(city) = intel.city {
                app.log_line(format!("  Ville       : {}", city));
            }
            if let Some(isp) = intel.isp {
                app.log_line(format!("  ISP         : {}", isp));
            }
        }
        Err(e) => app.log_line(format!("Erreur IP: {}", e)),
    }
}

fn run_mail(app: &mut App, input: &str) {
    let email = match Email::parse(input) {
        Ok(e) => e,
        Err(e) => {
            app.log_line(format!("Email invalide: {}", e));
            return;
        }
    };

    let engine = MailOsintEngine::new_with_default_probes();
    let usecase = RunMailScan::new(&engine);

    match usecase.execute(email) {
        Ok(summary) => {
            app.log_line(format!("Mail OSINT pour {}", summary.email.as_str()));
            for svc in summary.services {
                app.log_line(format!(
                    "  {:20} exists={} error={}",
                    svc.service_name, svc.exists, svc.error
                ));
            }
        }
        Err(e) => app.log_line(format!("Erreur Mail: {}", e)),
    }
}

fn run_social(app: &mut App, input: &str) {
    let username = input.trim();
    if username.is_empty() {
        app.log_line("Username vide");
        return;
    }

    let engine = SocialOsintEngine::new_with_default_probes();
    let usecase = RunSocialScan::new(&engine);
    let target = SocialTarget::Username(username.to_string());

    match usecase.execute(target) {
        Ok(result) => {
            app.log_line("Social OSINT:");
            for acc in result.accounts {
                app.log_line(format!(
                    "  {:20} status={:?} url={:?}",
                    acc.site_name, acc.status, acc.profile_url
                ));
            }
        }
        Err(e) => app.log_line(format!("Erreur Social: {}", e)),
    }
}

fn run_sigint_tcp(app: &mut App, input: &str) {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() != 2 {
        app.log_line("Format attendu: IP:PORT, ex: 1.2.3.4:443");
        return;
    }

    let ip: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => {
            app.log_line(format!("Adresse IP invalide: {}", parts[0]));
            return;
        }
    };

    let port: u16 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => {
            app.log_line(format!("Port invalide: {}", parts[1]));
            return;
        }
    };

    let engine = TcpSigintEngine::new();
    let usecase = RunSigintTcp::new(&engine);

    match usecase.execute(ip, port) {
        Ok(res) => {
            app.log_line(format!("SIGINT TCP pour {}:{}", res.target, res.port));
            if let Some(fp) = res.fingerprint {
                app.log_line(format!("  Window size : {}", fp.window_size));
                app.log_line(format!("  Options     : {:?}", fp.options));
                app.log_line(format!("  WScale      : {:?}", fp.wscale));
                app.log_line(format!("  SACK        : {}", fp.sack_permitted));
                app.log_line(format!("  TS val/Ecr  : {:?} / {:?}", fp.ts_val, fp.ts_ecr));
                app.log_line(format!("  TTL         : {:?}", fp.ttl));
                app.log_line(format!("  IP ID       : {:?}", fp.ip_id));
            } else {
                app.log_line("  Aucun fingerprint TCP obtenu");
            }
            if let Some(skew) = res.clock_skew {
                app.log_line(format!(
                    "  Clock skew  : {} ({} samples)",
                    skew.hz, skew.sample_count
                ));
            }
            if let Some(os) = res.os_guess {
                app.log_line(format!("  OS guess    : {}", os));
            }
        }
        Err(e) => app.log_line(format!("Erreur SIGINT TCP: {}", e)),
    }
}

fn run_sigint_icmp(app: &mut App, input: &str) {
    let ip: IpAddr = match input.parse() {
        Ok(ip) => ip,
        Err(_) => {
            app.log_line(format!("Adresse IP invalide: {}", input));
            return;
        }
    };

    let engine = IcmpSigintEngine::new();
    let usecase = RunSigintIcmp::new(&engine);

    match usecase.execute(ip) {
        Ok(res) => {
            app.log_line(format!("SIGINT ICMP pour {}", res.target));
            if let Some(series) = res.ip_id_series {
                app.log_line(format!("  IP IDs      : {:?}", series.ids));
                app.log_line(format!("  Classification : {}", series.classification));
            } else {
                app.log_line("  Aucune IP ID series disponible");
            }
            if let Some(skew) = res.clock_skew {
                app.log_line(format!(
                    "  Clock skew  : {} ({} samples)",
                    skew.hz, skew.sample_count
                ));
            }
        }
        Err(e) => app.log_line(format!("Erreur SIGINT ICMP: {}", e)),
    }
}

fn run_sigint_traceroute(app: &mut App, input: &str) {
    let ip: IpAddr = match input.parse() {
        Ok(ip) => ip,
        Err(_) => {
            app.log_line(format!("Adresse IP invalide: {}", input));
            return;
        }
    };

    let max_hops: u8 = 20;

    let engine = TracerouteSigintEngine::new();
    let usecase = RunSigintTraceroute::new(&engine);

    match usecase.execute(ip, max_hops) {
        Ok(res) => {
            app.log_line(format!("SIGINT Traceroute pour {}", res.target));
            for hop in res.hops {
                app.log_line(format!(
                    "  {:2} {}  rtt={:?}  ASN={:?}  CC={:?}  Owner={:?}",
                    hop.hop_index, hop.ip, hop.rtt_ms, hop.asn, hop.country, hop.owner
                ));
            }
            app.log_line(format!("AS path : {:?}", res.as_path));
            app.log_line(format!("IXPs    : {:?}", res.ixps));
        }
        Err(e) => app.log_line(format!("Erreur SIGINT Traceroute: {}", e)),
    }
}

fn run_profile_ip(app: &mut App, input: &str) {
    let ip: IpAddr = match input.parse() {
        Ok(ip) => ip,
        Err(_) => {
            app.log_line(format!("Adresse IP invalide: {}", input));
            return;
        }
    };

    let cache_key = format!("profile_ip:{}", ip);
    if app.cache_load(&cache_key) {
        app.log_line(format!("(cache) Profil déjà calculé pour {}", ip));
        return;
    }

    app.log.clear();
    app.log_line(format!("=== Profil complet pour {} ===", ip));

    // IP Intelligence
    let http = reqwest::Client::new();
    let metrics = InMemoryMetrics::default();
    let ip_engine = CompositeIpIntelligence::new(http, metrics);
    let ip_usecase = RunIpIntelligence::new(&ip_engine);
    match ip_usecase.execute(ip) {
        Ok(intel) => {
            app.log_line(format!("IP Intel: {:?}", intel));
        }
        Err(e) => app.log_line(format!("IP Intel erreur: {}", e)),
    }

    // Domain Intelligence via reverse DNS si possible
    if let Ok(host) = dns_lookup::lookup_addr(&ip) {
        let domain_engine = DomainIntelEngine::new();
        let domain_usecase = RunDomainIntel::new(&domain_engine);
        match domain_usecase.execute(&host) {
            Ok(dintel) => {
                app.log_line(format!("DomainIntel pour {}: {:?}", host, dintel));
            }
            Err(e) => app.log_line(format!("DomainIntel erreur pour {}: {}", host, e)),
        }
    }

    // SIGINT TCP (port 443)
    let tcp_engine = TcpSigintEngine::new();
    let tcp_usecase = RunSigintTcp::new(&tcp_engine);
    match tcp_usecase.execute(ip, 443) {
        Ok(res) => {
            app.log_line(format!("SIGINT TCP 443: {:?}", res));
        }
        Err(e) => app.log_line(format!("SIGINT TCP erreur: {}", e)),
    }

    // SIGINT ICMP
    let icmp_engine = IcmpSigintEngine::new();
    let icmp_usecase = RunSigintIcmp::new(&icmp_engine);
    match icmp_usecase.execute(ip) {
        Ok(res) => {
            app.log_line(format!("SIGINT ICMP: {:?}", res));
        }
        Err(e) => app.log_line(format!("SIGINT ICMP erreur: {}", e)),
    }

    // Traceroute
    run_sigint_traceroute(app, input);

    app.log_line(format!("=== Fin du profil pour {} ===", ip));

    app.cache_save(&cache_key);
}

fn run_profile_email(app: &mut App, input: &str) {
    let email = match Email::parse(input) {
        Ok(e) => e,
        Err(e) => {
            app.log_line(format!("Email invalide: {}", e));
            return;
        }
    };

    let cache_key = format!("profile_email:{}", email.as_str());
    if app.cache_load(&cache_key) {
        app.log_line(format!("(cache) Profil email déjà calculé pour {}", email.as_str()));
        return;
    }

    app.log.clear();
    app.log_line(format!("=== Profil complet Email pour {} ===", email.as_str()));

    // Mail OSINT (présence sur services)
    let mail_engine = MailOsintEngine::new_with_default_probes();
    let mail_usecase = RunMailScan::new(&mail_engine);
    match mail_usecase.execute(email.clone()) {
        Ok(summary) => {
            app.log_line("Mail OSINT:");
            for svc in summary.services {
                app.log_line(format!(
                    "  {:20} exists={} error={}",
                    svc.service_name, svc.exists, svc.error
                ));
            }
        }
        Err(e) => app.log_line(format!("Mail OSINT erreur: {}", e)),
    }

    // EmailRecon (DNS, CT logs, archives)
    let recon_engine = EmailReconEngine::new();
    let recon_usecase = RunEmailRecon::new(&recon_engine);
    match recon_usecase.execute(email.clone()) {
        Ok(res) => {
            app.log_line(format!("EmailRecon domaine {}:", res.domain));
            if let Some(dns) = res.dns {
                app.log_line(format!("  MX hosts      : {:?}", dns.mx_hosts));
                app.log_line(format!("  Providers     : {:?}", dns.inferred_providers));
            }
            app.log_line(format!("  CT domains    : {} entrées", res.ct_domains.len()));
            app.log_line(format!("  Wayback hits  : {}", res.archive_hits));
            app.log_line(format!("  CCrawl hits   : {}", res.common_crawl_hits));
        }
        Err(e) => app.log_line(format!("EmailRecon erreur: {}", e)),
    }

    // Social OSINT (username/email sur les sites sociaux)
    let social_engine = SocialOsintEngine::new_with_default_probes();
    let social_usecase = RunSocialScan::new(&social_engine);
    let target = SocialTarget::Email(email);
    match social_usecase.execute(target) {
        Ok(result) => {
            app.log_line("Social OSINT (Email):");
            for acc in result.accounts {
                app.log_line(format!(
                    "  {:20} status={:?} url={:?}",
                    acc.site_name, acc.status, acc.profile_url
                ));
            }
        }
        Err(e) => app.log_line(format!("Social OSINT erreur: {}", e)),
    }

    app.log_line("=== Fin du profil Email ===");

    app.cache_save(&cache_key);
}