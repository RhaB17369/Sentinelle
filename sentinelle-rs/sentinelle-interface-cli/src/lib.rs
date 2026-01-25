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
    RunIpIntelligence, RunMailScan, RunSocialScan, RunSigintTcp, RunSigintIcmp, RunSigintTraceroute,
};
use sentinelle_domain::{Email, SocialTarget};
use sentinelle_infra_latency_raw::{TcpSigintEngine, IcmpSigintEngine, TracerouteSigintEngine};
use sentinelle_infra_metrics::InMemoryMetrics;
use sentinelle_infra_osint_ip::CompositeIpIntelligence;
use sentinelle_infra_osint_mail::MailOsintEngine;
use sentinelle_infra_osint_social::SocialOsintEngine;
use std::io;
use std::net::IpAddr;

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
    ProfileInput,
}

struct App {
    view: View,
    input: String,
    log: Vec<String>,
    selected_menu: usize,
}

impl App {
    fn new() -> Self {
        Self {
            view: View::MainMenu,
            input: String::new(),
            log: Vec::new(),
            selected_menu: 0,
        }
    }

    fn log_line(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 200 {
            self.log.drain(0..self.log.len() - 200);
        }
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

fn ui<B: ratatui::backend::Backend>(f: &mut ratatui::Frame<B>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(BANNER.len() as u16 + 1),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(f.size());

    // Header ASCII
    let banner_lines: Vec<Spans> = BANNER
        .iter()
        .map(|line| Spans::from(Span::styled(
            *line,
            Style::default().add_modifier(Modifier::BOLD),
        )))
        .collect();
    let header = Paragraph::new(banner_lines)
        .block(Block::default().borders(Borders::ALL).title("SENTINELLE OSINT / SIGINT"));
    f.render_widget(header, chunks[0]);

    // Menu or input prompt
    match app.view {
        View::MainMenu => {
            let items = vec![
                "IP Intelligence",
                "Mail OSINT",
                "Social OSINT",
                "SIGINT TCP",
                "SIGINT ICMP",
                "SIGINT Traceroute",
                "Profil complet IP",
                "Quitter",
            ];
            let list_items: Vec<ListItem> = items
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
                .block(Block::default().borders(Borders::ALL).title("Menu"));
            f.render_widget(menu, chunks[1]);
        }
        _ => {
            let prompt = match app.view {
                View::IpInput => "IP cible (IP Intel): ",
                View::MailInput => "Email cible: ",
                View::SocialInput => "Username cible: ",
                View::SigintTcpInput => "IP:port pour SIGINT TCP (ex: 1.2.3.4:443): ",
                View::SigintIcmpInput => "IP cible (SIGINT ICMP): ",
                View::SigintTracerouteInput => "IP cible (SIGINT Traceroute): ",
                View::ProfileInput => "IP cible (Profil complet): ",
                View::MainMenu => "",
            };
            let input = Paragraph::new(app.input.as_str())
                .block(Block::default().borders(Borders::ALL).title(prompt));
            f.render_widget(input, chunks[1]);
        }
    }

    // Log / output pane
    let log_lines: Vec<Spans> = app
        .log
        .iter()
        .rev()
        .take((chunks[2].height as usize).saturating_sub(2))
        .rev()
        .map(|l| Spans::from(Span::raw(l.as_str())))
        .collect();

    let log_widget = Paragraph::new(log_lines)
        .block(Block::default().borders(Borders::ALL).title("Output"));
    f.render_widget(log_widget, chunks[2]);

    // Status bar
    let status = Paragraph::new("Esc: retour / q: quitter")
        .style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(status, chunks[3]);
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
                if app.selected_menu < 7 {
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
                    6 => app.view = View::ProfileInput,
                    7 => return Ok(false),
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
                    View::ProfileInput => run_profile(app, &input),
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

fn run_profile(app: &mut App, input: &str) {
    let ip: IpAddr = match input.parse() {
        Ok(ip) => ip,
        Err(_) => {
            app.log_line(format!("Adresse IP invalide: {}", input));
            return;
        }
    };

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
}