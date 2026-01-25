#![deny(warnings)]

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
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
use sentinelle_domain::{Email, SocialTarget, TracerouteHopDetail};
use sentinelle_infra_latency_raw::{TcpSigintEngine, IcmpSigintEngine, TracerouteSigintEngine};
use sentinelle_infra_metrics::InMemoryMetrics;
use sentinelle_infra_osint_ip::CompositeIpIntelligence;
use sentinelle_infra_osint_mail::MailOsintEngine;
use sentinelle_infra_osint_social::SocialOsintEngine;
use sentinelle_infra_email_recon::EmailReconEngine;
use sentinelle_infra_domain_intel::DomainIntelEngine;
use sentinelle_infra_cache_sqlite::{SqliteCache, ActivityEvent};
use std::io;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use serde::{Serialize, Deserialize};
use chrono::{NaiveDateTime, Utc};

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
    lines: Vec&lt;String&gt;,
}

struct ReportIp {
    headers: Vec&lt;String&gt;,
    rows: Vec&lt;Vec&lt;String&gt;&gt;,
}

struct ReportEmail {
    headers: Vec&lt;String&gt;,
    rows: Vec&lt;Vec&lt;String&gt;&gt;,
}

enum ReportKind {
    None,
    Ip(ReportIp),
    Email(ReportEmail),
}

enum ReportMode {
    Full,
    Summary,
}

enum ActivityFilterMode {
    Both,
    Module,
    Target,
}

struct App {
    view: View,
    input: String,
    log: Vec&lt;String&gt;,
    selected_menu: usize,
    cache: SqliteCache,
    activity: Vec&lt;ActivityEvent&gt;,
    output_scroll: usize,
    activity_scroll: usize,
    report: ReportKind,
    activity_filter: String,
    activity_filter_mode: ActivityFilterMode,
    active_section: Option&lt;String&gt;,
    report_mode: ReportMode,
    traceroute_hops: Vec&lt;TracerouteHopDetail&gt;,
    show_traceroute_detail: bool,
}

impl App {
    fn new() -> Self {
        let cache = SqliteCache::new("sentinelle_cache.db").unwrap_or_else(|| {
            SqliteCache::new(":memory:").expect("cache sqlite")
        });

        let activity = cache.recent_activity(200).unwrap_or_default();

        Self {
            view: View::MainMenu,
            input: String::new(),
            log: Vec::new(),
            selected_menu: 0,
            cache,
            activity,
            output_scroll: 0,
            activity_scroll: 0,
            report: ReportKind::None,
            activity_filter: String::new(),
            activity_filter_mode: ActivityFilterMode::Both,
            active_section: None,
            report_mode: ReportMode::Full,
            traceroute_hops: Vec::new(),
            show_traceroute_detail: false,
        }
    }

    fn log_line(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 200 {
            self.log.drain(0..self.log.len() - 200);
        }
    }

    fn cache_load(&mut self, key: &str) -> bool {
        if let Ok(Some(cached)) = self.cache.get_json::&lt;CachedLog&gt;(key) {
            self.log = cached.lines;
            // Les rapports structurés et hops ne sont pas reconstruits depuis le cache,
            // on désactive donc les vues avancées.
            self.report = ReportKind::None;
            self.traceroute_hops.clear();
            self.show_traceroute_detail = false;
            self.active_section = None;
            self.report_mode = ReportMode::Full;
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

    fn push_activity(&mut self, ev: ActivityEvent) {
        let _ = self.cache.log_activity(&ev);
        self.activity.push(ev);
        if self.activity.len() > 500 {
            self.activity.drain(0..self.activity.len() - 500);
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
                Event::Mouse(me) => {
                    use crossterm::event::{MouseEventKind};
                    match me.kind {
                        MouseEventKind::ScrollUp => {
                            app.output_scroll = app.output_scroll.saturating_add(1);
                        }
                        MouseEventKind::ScrollDown => {
                            app.output_scroll = app.output_scroll.saturating_sub(1);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn ui<B: ratatui::backend::Backend>(f: &mut ratatui::Frame<B>, app: &App) {
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
    let banner_lines: Vec<Spans> = BANNER
        .iter()
        .map(|line| Spans::from(Span::styled(
            *line,
            Style::default().add_modifier(Modifier::BOLD),
        )))
        .collect();
    let header = Paragraph::new(banner_lines)
        .block(Block::default().borders(Borders::ALL).title("SENTINELLE OSINT / SIGINT"));
    f.render_widget(header, outer[0]);

    // Zone principale: panneau gauche (menu) + panneau droit (input + output + activity)
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
            .block(Block::default().borders(Borders::ALL).title("Modules"));
        f.render_widget(menu, main_chunks[0]);
    }

    // Panneau droit: input en haut, output au milieu, activity en bas
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(7),
        ])
        .split(main_chunks[1]);

    // Input / cible courante
    let prompt = match app.view {
        View::IpInput => "IP cible (IP Intel): ",
        View::MailInput => "Email cible: ",
        View::SocialInput => "Username cible: ",
        View::SigintTcpInput => "IP:port pour SIGINT TCP (ex: 1.2.3.4:443): ",
        View::SigintIcmpInput => "IP cible (SIGINT ICMP): ",
        View::SigintTracerouteInput => "IP cible (SIGINT Traceroute): ",
        View::ProfileIpInput => "IP cible (Profil complet IP): ",
        View::ProfileEmailInput => "Email cible (Profil complet Email): ",
        View::MainMenu => "Sélectionnez un module et appuyez sur Entrée",
    };
    let input = Paragraph::new(app.input.as_str())
        .block(Block::default().borders(Borders::ALL).title(prompt));
    f.render_widget(input, right_chunks[0]);

    // Output pane: table pour rapports structurés, sinon lignes texte avec scroll
    match &app.report {
        ReportKind::Ip(report) => {
            if app.show_traceroute_detail && !app.traceroute_hops.is_empty() {
                // Vue détaillée par hop
                let visible_rows = (right_chunks[1].height as usize).saturating_sub(3);
                let total_rows = app.traceroute_hops.len();
                let max_scroll = total_rows.saturating_sub(visible_rows);
                let scroll = app.output_scroll.min(max_scroll);
                let start = total_rows.saturating_sub(visible_rows + scroll);
                let end = total_rows.saturating_sub(scroll);

                let header = Row::new(vec![
                    Span::styled("Hop", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("IP", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("RTT", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("ASN", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("CC", Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled("Owner", Style::default().add_modifier(Modifier::BOLD)),
                ]);

                let rows: Vec<Row> = app
                    .traceroute_hops
                    .iter()
                    .skip(start)
                    .take(end.saturating_sub(start))
                    .map(|hop| {
                        Row::new(vec![
                            Span::raw(hop.hop_index.to_string()),
                            Span::raw(hop.ip.clone()),
                            Span::raw(
                                hop.rtt_ms
                                    .map(|r| format!("{:.2} ms", r))
                                    .unwrap_or_else(|| "-".to_string()),
                            ),
                            Span::raw(hop.asn.clone().unwrap_or_default()),
                            Span::raw(hop.country.clone().unwrap_or_default()),
                            Span::raw(hop.owner.clone().unwrap_or_default()),
                        ])
                    })
                    .collect();

                let table = Table::new(rows)
                    .header(header)
                    .block(Block::default().borders(Borders::ALL).title("Traceroute detail"))
                    .widths(&[
                        Constraint::Length(4),
                        Constraint::Length(16),
                        Constraint::Length(12),
                        Constraint::Length(10),
                        Constraint::Length(4),
                        Constraint::Min(10),
                    ]);
                f.render_widget(table, right_chunks[1]);
            } else {
                let visible_rows = (right_chunks[1].height as usize).saturating_sub(3);

                // Appliquer éventuel zoom de section et mode résumé
                let filtered_rows: Vec<&Vec<String>> = report
                    .rows
                    .iter()
                    .filter(|row| {
                        let section = row.get(0).map(|s| s.as_str()).unwrap_or("");
                        let section_ok = match &app.active_section {
                            None => true,
                            Some(active) => section == active,
                        };
                        let summary_ok = match app.report_mode {
                            ReportMode::Full => true,
                            ReportMode::Summary => match section {
                                "IP" => matches!(
                                    row.get(1).map(String::as_str),
                                    Some("Adresse") | Some("Pays") | Some("ISP")
                                ),
                                "Domain" => matches!(
                                    row.get(1).map(String::as_str),
                                    Some("Host") | Some("Registrar")
                                ),
                                "SIGINT TCP" => matches!(row.get(1).map(String::as_str), Some("OS")),
                                "Traceroute" => matches!(
                                    row.get(1).map(String::as_str),
                                    Some("Hops")
                                ),
                                _ => false,
                            },
                        };
                        section_ok && summary_ok
                    })
                    .collect();

                let total_rows = filtered_rows.len();
                let max_scroll = total_rows.saturating_sub(visible_rows);
                let scroll = app.output_scroll.min(max_scroll);
                let start = total_rows.saturating_sub(visible_rows + scroll);
                let end = total_rows.saturating_sub(scroll);

                let header = Row::new(
                    report
                        .headers
                        .iter()
                        .map(|h| Span::styled(h.clone(), Style::default().add_modifier(Modifier::BOLD)))
                        .collect::<Vec<_>>(),
                );

                let rows: Vec<Row> = filtered_rows
                    .iter()
                    .skip(start)
                    .take(end.saturating_sub(start))
                    .map(|cols| {
                        let section = cols.get(0).map(|s| s.as_str()).unwrap_or("");
                        let section_style = match section {
                            "IP" => Style::default().fg(Color::Cyan),
                            "Domain" => Style::default().fg(Color::Yellow),
                            s if s.starts_with("SIGINT") => Style::default().fg(Color::Magenta),
                            "Traceroute" => Style::default().fg(Color::LightGreen),
                            _ => Style::default(),
                        };

                        let mut spans = Vec::new();
                        if let Some(sec) = cols.get(0) {
                            spans.push(Span::styled(sec.clone(), section_style));
                        }
                        for c in cols.iter().skip(1) {
                            spans.push(Span::raw(c.clone()));
                        }
                        Row::new(spans)
                    })
                    .collect();

                let table = Table::new(rows)
                    .header(header)
                    .block(Block::default().borders(Borders::ALL).title("Output"))
                    .widths(&[
                        Constraint::Length(14),
                        Constraint::Length(16),
                        Constraint::Min(10),
                        Constraint::Min(10),
                    ]);
                f.render_widget(table, right_chunks[1]);
            }
        })
                .collect();

            let table = Table::new(rows)
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Output"))
                .widths(&[
                    Constraint::Length(14),
                    Constraint::Length(16),
                    Constraint::Min(10),
                    Constraint::Min(10),
                ]);
            f.render_widget(table, right_chunks[1]);
        }
        ReportKind::Email(report) => {
            let visible_rows = (right_chunks[1].height as usize).saturating_sub(3);

            let filtered_rows: Vec<&Vec<String>> = report
                .rows
                .iter()
                .filter(|row| {
                    let section = row.get(0).map(|s| s.as_str()).unwrap_or("");
                    let section_ok = match &app.active_section {
                        None => true,
                        Some(active) => section == active,
                    };
                    let summary_ok = match app.report_mode {
                        ReportMode::Full => true,
                        ReportMode::Summary => match section {
                            "Mail OSINT" => {
                                // lignes où exists=true
                                row.get(2).map(String::as_str) == Some("true")
                            }
                            "EmailRecon" => matches!(
                                row.get(1).map(String::as_str),
                                Some("Domaine")
                                    | Some("MX")
                                    | Some("CT domains")
                                    | Some("Wayback hits")
                                    | Some("CCrawl hits")
                            ),
                            "Social" => row.get(2).map(String::as_str) != Some("NotFound"),
                            _ => false,
                        },
                    };
                    section_ok && summary_ok
                })
                .collect();

            let total_rows = filtered_rows.len();
            let max_scroll = total_rows.saturating_sub(visible_rows);
            let scroll = app.output_scroll.min(max_scroll);
            let start = total_rows.saturating_sub(visible_rows + scroll);
            let end = total_rows.saturating_sub(scroll);

            let header = Row::new(
                report
                    .headers
                    .iter()
                    .map(|h| Span::styled(h.clone(), Style::default().add_modifier(Modifier::BOLD)))
                    .collect::<Vec<_>>(),
            );

            let rows: Vec<Row> = filtered_rows
                .iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .map(|cols| {
                    let section = cols.get(0).map(|s| s.as_str()).unwrap_or("");
                    let section_style = match section {
                        "Mail OSINT" => Style::default().fg(Color::Cyan),
                        "EmailRecon" => Style::default().fg(Color::Yellow),
                        "Social" => Style::default().fg(Color::Magenta),
                        _ => Style::default(),
                    };

                    let mut spans = Vec::new();
                    if let Some(sec) = cols.get(0) {
                        spans.push(Span::styled(sec.clone(), section_style));
                    }
                    for c in cols.iter().skip(1) {
                        spans.push(Span::raw(c.clone()));
                    }
                    Row::new(spans)
                })
                .collect();

            let table = Table::new(rows)
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("Output"))
                .widths(&[
                    Constraint::Length(14),
                    Constraint::Length(16),
                    Constraint::Min(10),
                    Constraint::Min(10),
                ]);
            f.render_widget(table, right_chunks[1]);
        }
        ReportKind::None => {
            let visible_output_lines = (right_chunks[1].height as usize).saturating_sub(2);
            let total_output_lines = app.log.len();
            let max_output_scroll = total_output_lines.saturating_sub(visible_output_lines);
            let output_scroll = app.output_scroll.min(max_output_scroll);
            let start = total_output_lines.saturating_sub(visible_output_lines + output_scroll);
            let end = total_output_lines.saturating_sub(output_scroll);
            let log_lines: Vec<Spans> = app
                .log
                .iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .map(|l| Spans::from(Span::raw(l.as_str())))
                .collect();

            let log_widget = Paragraph::new(log_lines)
                .block(Block::default().borders(Borders::ALL).title("Output"));
            f.render_widget(log_widget, right_chunks[1]);
        }
    }

    // Activity pane avec filtre, stats, scroll et rendu tabulaire
    let filtered_activity: Vec<&ActivityEvent> = if app.activity_filter.is_empty() {
        app.activity.iter().collect()
    } else {
        app.activity
            .iter()
            .filter(|ev| match app.activity_filter_mode {
                ActivityFilterMode::Both => {
                    ev.module.contains(&app.activity_filter)
                        || ev.target.contains(&app.activity_filter)
                }
                ActivityFilterMode::Module => ev.module.contains(&app.activity_filter),
                ActivityFilterMode::Target => ev.target.contains(&app.activity_filter),
            })
            .collect()
    };

    let total_events = app.activity.len();
    let filtered_events = filtered_activity.len();
    let done_count = filtered_activity
        .iter()
        .filter(|ev| ev.status == "done")
        .count();
    let error_count = filtered_activity
        .iter()
        .filter(|ev| ev.status == "error")
        .count();

    let stats_row = Row::new(vec![Span::styled(
        format!(
            "Total: {} | done: {} | error: {} | filtered: {}",
            total_events, done_count, error_count, filtered_events
        ),
        Style::default().add_modifier(Modifier::DIM),
    )]);

    let visible_activity_lines = (right_chunks[2].height as usize).saturating_sub(4); // header + stats + bordures
    let total_activity_lines = filtered_activity.len();
    let max_activity_scroll = total_activity_lines.saturating_sub(visible_activity_lines);
    let activity_scroll = app.activity_scroll.min(max_activity_scroll);
    let a_start = total_activity_lines.saturating_sub(visible_activity_lines + activity_scroll);
    let a_end = total_activity_lines.saturating_sub(activity_scroll);

    let header = Row::new(vec![
        Span::styled("Time", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("Module", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("Target", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("Dur(ms)", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("Status", Style::default().add_modifier(Modifier::BOLD)),
    ]);

    let mut rows: Vec<Row> = Vec::new();
    rows.push(stats_row);

    rows.extend(
        filtered_activity
            .iter()
            .skip(a_start)
            .take(a_end.saturating_sub(a_start))
            .map(|ev| {
                let ev = *ev;
                let dt = NaiveDateTime::from_timestamp_opt(ev.ts as i64, 0)
                    .unwrap_or_else(|| NaiveDateTime::from_timestamp_opt(0, 0).unwrap());
                let ts_str = dt.format("%Y-%m-%d %H:%M:%S").to_string();
                let status_style = match ev.status.as_str() {
                    "done" => Style::default().fg(Color::Green),
                    "error" => Style::default().fg(Color::Red),
                    _ => Style::default().fg(Color::Yellow),
                };
                Row::new(vec![
                    Span::raw(ts_str),
                    Span::raw(ev.module.clone()),
                    Span::raw(ev.target.clone()),
                    Span::raw(ev.duration_ms.to_string()),
                    Span::styled(ev.status.clone(), status_style),
                ])
            }),
    );

    let activity_widget = Table::new(rows)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Activity"))
        .widths(&[
            Constraint::Length(19),
            Constraint::Length(16),
            Constraint::Min(10),
            Constraint::Length(8),
            Constraint::Length(8),
        ]);
    f.render_widget(activity_widget, right_chunks[2]);

    // Status bar
    let section_label = app.active_section.clone().unwrap_or_else(|| "Toutes".to_string());
    let mode_label = match app.report_mode {
        ReportMode::Full => "complet",
        ReportMode::Summary => "résumé",
    };
    let status_text = format!(
        "Esc: retour / q: quitter  |  PgUp/PgDn/Scroll: output  |  a/z: activity  |  f: filtre activité='{}' (m:/t:/both) |  c: clear filtre  |  Tab: section={}  |  r: mode={}",
        app.activity_filter,
        section_label,
        mode_label,
    );
    let status = Paragraph::new(status_text)
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
            KeyCode::PageUp => {
                app.output_scroll = app.output_scroll.saturating_add(1);
            }
            KeyCode::PageDown => {
                app.output_scroll = app.output_scroll.saturating_sub(1);
            }
            KeyCode::Char('a') => {
                app.activity_scroll = app.activity_scroll.saturating_add(1);
            }
            KeyCode::Char('z') => {
                app.activity_scroll = app.activity_scroll.saturating_sub(1);
            }
            KeyCode::Char('f') => {
                let raw = app.input.trim();
                if let Some(rest) = raw.strip_prefix("m:") {
                    app.activity_filter_mode = ActivityFilterMode::Module;
                    app.activity_filter = rest.to_string();
                } else if let Some(rest) = raw.strip_prefix("t:") {
                    app.activity_filter_mode = ActivityFilterMode::Target;
                    app.activity_filter = rest.to_string();
                } else {
                    app.activity_filter_mode = ActivityFilterMode::Both;
                    app.activity_filter = raw.to_string();
                }
                app.activity_scroll = 0;
            }
            KeyCode::Char('c') => {
                app.activity_filter.clear();
                app.activity_filter_mode = ActivityFilterMode::Both;
                app.activity_scroll = 0;
            }
            KeyCode::Tab => {
                // Zoom section suivante sur rapport courant
                let sections: Vec<String> = match &app.report {
                    ReportKind::Ip(r) => r
                        .rows
                        .iter()
                        .map(|row| row[0].clone())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    ReportKind::Email(r) => r
                        .rows
                        .iter()
                        .map(|row| row[0].clone())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    ReportKind::None => Vec::new(),
                };
                if sections.is_empty() {
                    app.active_section = None;
                } else {
                    let next = match &app.active_section {
                        None => sections.first().cloned(),
                        Some(current) => {
                            let mut iter = sections.iter();
                            let mut found = None;
                            while let Some(s) = iter.next() {
                                if s == current {
                                    found = iter.next().cloned();
                                    break;
                                }
                            }
                            found.or_else(|| sections.first().cloned())
                        }
                    };
                    app.active_section = next;
                    app.output_scroll = 0;
                }
            }
            KeyCode::Char('r') => {
                app.report_mode = match app.report_mode {
                    ReportMode::Full => ReportMode::Summary,
                    ReportMode::Summary => ReportMode::Full,
                };
                app.output_scroll = 0;
            }
            KeyCode::Char('t') => {
                // Toggle vue traceroute détaillée si des hops sont disponibles
                if !app.traceroute_hops.is_empty() {
                    app.show_traceroute_detail = !app.show_traceroute_detail;
                    app.output_scroll = 0;
                }
            }
            KeyCode::Enter => {
                app.input.clear();
                app.log.clear();
                app.output_scroll = 0;
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
                let started = Instant::now();
                let res = match app.view {
                    View::IpInput => { run_ip(app, &input); ("ip_intel", input.clone(), "single") }
                    View::MailInput => { run_mail(app, &input); ("mail_osint", input.clone(), "single") }
                    View::SocialInput => { run_social(app, &input); ("social_osint", input.clone(), "single") }
                    View::SigintTcpInput => { run_sigint_tcp(app, &input); ("sigint_tcp", input.clone(), "single") }
                    View::SigintIcmpInput => { run_sigint_icmp(app, &input); ("sigint_icmp", input.clone(), "single") }
                    View::SigintTracerouteInput => { run_sigint_traceroute(app, &input); ("sigint_traceroute", input.clone(), "single") }
                    View::ProfileIpInput => { run_profile_ip(app, &input); ("profile_ip", input.clone(), "full") }
                    View::ProfileEmailInput => { run_profile_email(app, &input); ("profile_email", input.clone(), "full") }
                    View::MainMenu => ("noop", String::new(), "noop"),
                };
                if res.0 != "noop" {
                    let duration = started.elapsed().as_millis() as u64;
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let ev = ActivityEvent {
                        ts,
                        module: res.0.to_string(),
                        target: res.1,
                        kind: res.2.to_string(),
                        duration_ms: duration,
                        status: "done".to_string(),
                    };
                    app.push_activity(ev);
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
        app.report = ReportKind::None;
        return;
    }

    app.log.clear();
    app.report = ReportKind::None;
    app.traceroute_hops.clear();
    app.show_traceroute_detail = false;
    app.active_section = None;
    app.report_mode = ReportMode::Full;
    app.log_line(format!("=== Profil complet pour {} ===", ip));

    let mut rows = Vec::new();

    // IP Intelligence
    let http = reqwest::Client::new();
    let metrics = InMemoryMetrics::default();
    let ip_engine = CompositeIpIntelligence::new(http, metrics);
    let ip_usecase = RunIpIntelligence::new(&ip_engine);
    match ip_usecase.execute(ip) {
        Ok(intel) => {
            app.log_line(format!("IP Intel: {:?}", intel));
            rows.push(vec![
                "IP".to_string(),
                "Adresse".to_string(),
                intel.ip.to_string(),
                "".to_string(),
            ]);
            if let Some(country) = intel.country {
                rows.push(vec![
                    "IP".to_string(),
                    "Pays".to_string(),
                    country,
                    "".to_string(),
                ]);
            }
            if let Some(city) = intel.city {
                rows.push(vec![
                    "IP".to_string(),
                    "Ville".to_string(),
                    city,
                    "".to_string(),
                ]);
            }
            if let Some(isp) = intel.isp {
                rows.push(vec![
                    "IP".to_string(),
                    "ISP".to_string(),
                    isp,
                    "".to_string(),
                ]);
            }
        }
        Err(e) => {
            app.log_line(format!("IP Intel erreur: {}", e));
            rows.push(vec![
                "IP".to_string(),
                "Erreur".to_string(),
                e.to_string(),
                "".to_string(),
            ]);
        }
    }

    // Domain Intelligence via reverse DNS si possible
    if let Ok(host) = dns_lookup::lookup_addr(&ip) {
        let domain_engine = DomainIntelEngine::new();
        let domain_usecase = RunDomainIntel::new(&domain_engine);
        match domain_usecase.execute(&host) {
            Ok(dintel) => {
                app.log_line(format!("DomainIntel pour {}: {:?}", host, dintel));
                rows.push(vec![
                    "Domain".to_string(),
                    "Host".to_string(),
                    host.clone(),
                    "".to_string(),
                ]);
                if let Some(whois) = dintel.whois {
                    if let Some(reg) = whois.registrar {
                        rows.push(vec![
                            "Domain".to_string(),
                            "Registrar".to_string(),
                            reg,
                            "".to_string(),
                        ]);
                    }
                    if let Some(c) = whois.country {
                        rows.push(vec![
                            "Domain".to_string(),
                            "Pays".to_string(),
                            c,
                            "".to_string(),
                        ]);
                    }
                }
            }
            Err(e) => {
                app.log_line(format!("DomainIntel erreur pour {}: {}", host, e));
                rows.push(vec![
                    "Domain".to_string(),
                    "Erreur".to_string(),
                    e.to_string(),
                    host,
                ]);
            }
        }
    }

    // SIGINT TCP (port 443)
    let tcp_engine = TcpSigintEngine::new();
    let tcp_usecase = RunSigintTcp::new(&tcp_engine);
    match tcp_usecase.execute(ip, 443) {
        Ok(res) => {
            app.log_line(format!("SIGINT TCP 443: {:?}", res));
            if let Some(fp) = res.fingerprint {
                rows.push(vec![
                    "SIGINT TCP".to_string(),
                    "Window".to_string(),
                    fp.window_size.to_string(),
                    format!("{:?}", fp.options),
                ]);
                if let Some(os) = res.os_guess {
                    rows.push(vec![
                        "SIGINT TCP".to_string(),
                        "OS".to_string(),
                        os,
                        "".to_string(),
                    ]);
                }
            }
        }
        Err(e) => {
            app.log_line(format!("SIGINT TCP erreur: {}", e));
            rows.push(vec![
                "SIGINT TCP".to_string(),
                "Erreur".to_string(),
                e.to_string(),
                "".to_string(),
            ]);
        }
    }

    // SIGINT ICMP
    let icmp_engine = IcmpSigintEngine::new();
    let icmp_usecase = RunSigintIcmp::new(&icmp_engine);
    match icmp_usecase.execute(ip) {
        Ok(res) => {
            app.log_line(format!("SIGINT ICMP: {:?}", res));
            if let Some(series) = res.ip_id_series {
                rows.push(vec![
                    "SIGINT ICMP".to_string(),
                    "IP ID".to_string(),
                    format!("{:?}", series.ids),
                    series.classification,
                ]);
            }
        }
        Err(e) => {
            app.log_line(format!("SIGINT ICMP erreur: {}", e));
            rows.push(vec![
                "SIGINT ICMP".to_string(),
                "Erreur".to_string(),
                e.to_string(),
                "".to_string(),
            ]);
        }
    }

    // Traceroute (résumé + détail)
    let ip_str = ip.to_string();
    let max_hops: u8 = 20;
    let tr_engine = TracerouteSigintEngine::new();
    let tr_usecase = RunSigintTraceroute::new(&tr_engine);
    match tr_usecase.execute(ip, max_hops) {
        Ok(res) => {
            app.log_line(format!("SIGINT Traceroute pour {}: {:?}", res.target, res));
            rows.push(vec![
                "Traceroute".to_string(),
                "Hops".to_string(),
                res.hops.len().to_string(),
                format!("AS path: {:?}", res.as_path),
            ]);
            app.traceroute_hops = res.hops;
        }
        Err(e) => {
            app.log_line(format!("SIGINT Traceroute erreur: {}", e));
            rows.push(vec![
                "Traceroute".to_string(),
                "Erreur".to_string(),
                e.to_string(),
                ip_str,
            ]);
            app.traceroute_hops.clear();
        }
    }

    app.log_line(format!("=== Fin du profil pour {} ===", ip));

    // Tri des lignes par section pour regrouper IP / Domain / SIGINT / Traceroute
    rows.sort_by(|a, b| a[0].cmp(&b[0]));

    let headers = vec![
        "Section".to_string(),
        "Clé".to_string(),
        "Valeur".to_string(),
        "Détail".to_string(),
    ];

    app.report = ReportKind::Ip(ReportIp { headers, rows });
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
        app.report = ReportKind::None;
        return;
    }

    app.log.clear();
    app.report = ReportKind::None;
    app.log_line(format!("=== Profil complet Email pour {} ===", email.as_str()));

    let mut headers = vec![
        "Section".to_string(),
        "Clé".to_string(),
        "Valeur".to_string(),
        "Détail".to_string(),
    ];
    let mut rows = Vec::new();

    // Mail OSINT (présence sur services)
    let mail_engine = MailOsintEngine::new_with_default_probes();
    let mail_usecase = RunMailScan::new(&mail_engine);
    match mail_usecase.execute(email.clone()) {
        Ok(summary) => {
            app.log_line("Mail OSINT:");
            for svc in &summary.services {
                app.log_line(format!(
                    "  {:20} exists={} error={}",
                    svc.service_name, svc.exists, svc.error
                ));
                rows.push(vec![
                    "Mail OSINT".to_string(),
                    svc.service_name.clone(),
                    svc.exists.to_string(),
                    svc.error.clone(),
                ]);
            }
        }
        Err(e) => {
            app.log_line(format!("Mail OSINT erreur: {}", e));
            rows.push(vec![
                "Mail OSINT".to_string(),
                "Erreur".to_string(),
                e.to_string(),
                "".to_string(),
            ]);
        }
    }

    // EmailRecon (DNS, CT logs, archives)
    let recon_engine = EmailReconEngine::new();
    let recon_usecase = RunEmailRecon::new(&recon_engine);
    match recon_usecase.execute(email.clone()) {
        Ok(res) => {
            app.log_line(format!("EmailRecon domaine {}:", res.domain));
            rows.push(vec![
                "EmailRecon".to_string(),
                "Domaine".to_string(),
                res.domain.clone(),
                "".to_string(),
            ]);
            if let Some(dns) = res.dns {
                rows.push(vec![
                    "EmailRecon".to_string(),
                    "MX".to_string(),
                    format!("{:?}", dns.mx_hosts),
                    format!("{:?}", dns.inferred_providers),
                ]);
            }
            rows.push(vec![
                "EmailRecon".to_string(),
                "CT domains".to_string(),
                res.ct_domains.len().to_string(),
                "".to_string(),
            ]);
            rows.push(vec![
                "EmailRecon".to_string(),
                "Wayback hits".to_string(),
                res.archive_hits.to_string(),
                "".to_string(),
            ]);
            rows.push(vec![
                "EmailRecon".to_string(),
                "CCrawl hits".to_string(),
                res.common_crawl_hits.to_string(),
                "".to_string(),
            ]);
        }
        Err(e) => {
            app.log_line(format!("EmailRecon erreur: {}", e));
            rows.push(vec![
                "EmailRecon".to_string(),
                "Erreur".to_string(),
                e.to_string(),
                "".to_string(),
            ]);
        }
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
                rows.push(vec![
                    "Social".to_string(),
                    acc.site_name,
                    format!("{:?}", acc.status),
                    acc.profile_url.unwrap_or_default(),
                ]);
            }
        }
        Err(e) => {
            app.log_line(format!("Social OSINT erreur: {}", e));
            rows.push(vec![
                "Social".to_string(),
                "Erreur".to_string(),
                e.to_string(),
                "".to_string(),
            ]);
        }
    }

    app.log_line("=== Fin du profil Email ===");

    app.report = ReportKind::Email(ReportEmail { headers, rows });
    app.cache_save(&cache_key);
}