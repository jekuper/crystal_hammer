//! Alert browser. `alerts dump [since] [limit]` pages stored alerts out of the evidence
//! log as NDJSON (also the scripting/test path); `alerts` with no args opens an interactive
//! TUI over that history - scroll, filter by severity/kind, free-text search, sort, and
//! open a detail view. Read-only: it only reads the evidence log.

use std::io;

use async_trait::async_trait;
use ch_common::proto::Alert;
use ch_common::{Error, Result};
use ch_transport::ClientCommandExecutor;
use rustyline::completion::{FilenameCompleter, Pair};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{Frame, Terminal};

use crate::model::{AgentCommand, AgentCommandContext, ClientCommand, ClientCommandContext};
use crate::response_command::run_remote;

#[derive(Clone, Deserialize)]
struct DumpRow {
    cursor: u64,
    alert: Alert,
}

// =============================================================================
// Agent: dump stored alerts as NDJSON
// =============================================================================

pub struct AlertsAgentCommand {}
impl AlertsAgentCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AgentCommand for AlertsAgentCommand {
    fn name(&self) -> &'static str {
        "alerts"
    }
    async fn execute(&self, args: Vec<String>, mut ctx: AgentCommandContext) -> Result<()> {
        // Only "dump" is defined agent-side; the bare `alerts` command is client-only (TUI).
        if args.first().map(String::as_str) != Some("dump") {
            ctx.stdout.write_all(b"usage: alerts dump [since_cursor] [limit]\n").await?;
            return Ok(());
        }
        let Some(store) = ctx.store.clone() else {
            ctx.stdout.write_all(b"state store unavailable; no alert history\n").await?;
            return Ok(());
        };
        let since = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let limit = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100_000);
        for rec in store.since(since, limit).unwrap_or_default() {
            if rec.kind != "alert" {
                continue;
            }
            let line = serde_json::json!({ "cursor": rec.cursor, "alert": rec.body }).to_string();
            if ctx.stdout.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = ctx.stdout.write_all(b"\n").await;
        }
        Ok(())
    }
}

// =============================================================================
// Client: fetch + interactive browser
// =============================================================================

pub struct AlertsClientCommand {}
impl AlertsClientCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ClientCommand for AlertsClientCommand {
    fn name(&self) -> &'static str {
        "alerts"
    }
    fn short_description(&self) -> &'static str {
        "Browse past alerts (interactive)"
    }
    fn help(&self) -> &'static str {
        "Usage: alerts [dump [since] [limit]]\n\n\
        With no args: opens an interactive browser over the alert history.\n\
          up/down pgup/pgdn home/end  move     s severity   f kind   t sort   / search\n\
          Enter  details                       p pin to console   a attribute pid   w watch path\n\
          q  quit\n\
        'p' prints the selected alert into the console and closes, so you keep it without\n\
        reopening. 'a'/'w' close and act on it (dossier / add to watchlist).\n\
        'alerts dump' prints the history as NDJSON (for scripting)."
    }
    fn complete_arg(&self, _p: &[&str], _w: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        if args.first().map(String::as_str) == Some("dump") {
            return run_remote(ctx, "alerts", args).await; // non-interactive passthrough
        }

        let rows = fetch_alerts(ctx.session).await?;
        if rows.is_empty() {
            println!("No alerts recorded yet.");
            return Ok(());
        }
        // The TUI is synchronous (raw mode); run it off the async runtime. It returns an
        // optional outcome chosen by the operator before closing.
        let outcome = tokio::task::spawn_blocking(move || run_tui(rows))
            .await
            .map_err(|e| Error::Other(e.to_string()))?
            .map_err(|e| Error::Other(e.to_string()))?;
        match outcome {
            // Pin the alert into the console scroll so the operator keeps it after closing.
            Some(Outcome::Print(block)) => {
                println!("{block}");
            }
            // Act on the alert: run a follow-up command against the agent, output to console.
            Some(Outcome::Exec(cmd, cargs)) => {
                println!("\u{25c8} running: {cmd} {}", cargs.join(" "));
                run_remote(ctx, &cmd, &cargs).await?;
            }
            None => {}
        }
        Ok(())
    }
}

/// What the TUI asks the client to do after it closes.
enum Outcome {
    /// Print this text block into the console flow.
    Print(String),
    /// Run this agent command (name + args) and show its output in the console.
    Exec(String, Vec<String>),
}

async fn fetch_alerts(session: &mut russh::client::Handle<ch_transport::client::ClientHandler>) -> Result<Vec<DumpRow>> {
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| Error::Other(e.to_string()))?;
    channel
        .exec(true, b"alerts dump 0 100000")
        .await
        .map_err(|e| Error::Other(e.to_string()))?;

    let mut buf: Vec<u8> = Vec::new();
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { ref data } => buf.extend_from_slice(data),
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    let text = String::from_utf8_lossy(&buf);
    Ok(text.lines().filter_map(|l| serde_json::from_str::<DumpRow>(l).ok()).collect())
}

// ---- TUI ---------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Sev {
    All,
    Info,
    Warn,
    Crit,
}

impl Sev {
    fn label(self) -> &'static str {
        match self {
            Sev::All => "all",
            Sev::Info => "info",
            Sev::Warn => "warn",
            Sev::Crit => "critical",
        }
    }
    fn next(self) -> Sev {
        match self {
            Sev::All => Sev::Info,
            Sev::Info => Sev::Warn,
            Sev::Warn => Sev::Crit,
            Sev::Crit => Sev::All,
        }
    }
}

#[derive(Clone, Copy)]
enum Sort {
    TimeDesc,
    Severity,
    Kind,
}

impl Sort {
    fn label(self) -> &'static str {
        match self {
            Sort::TimeDesc => "time",
            Sort::Severity => "severity",
            Sort::Kind => "kind",
        }
    }
    fn next(self) -> Sort {
        match self {
            Sort::TimeDesc => Sort::Severity,
            Sort::Severity => Sort::Kind,
            Sort::Kind => Sort::TimeDesc,
        }
    }
}

struct App {
    rows: Vec<DumpRow>,
    kinds: Vec<String>,
    view: Vec<usize>,
    state: TableState,
    sev: Sev,
    kind_idx: usize, // 0 = all, else kinds[kind_idx-1]
    search: String,
    searching: bool,
    detail: bool,
    sort: Sort,
}

fn sev_rank(a: &Alert) -> u8 {
    use ch_common::proto::AlertSeverity::*;
    match a.severity {
        Critical => 2,
        Warn => 1,
        Info => 0,
    }
}

fn sev_matches(a: &Alert, sev: Sev) -> bool {
    use ch_common::proto::AlertSeverity::*;
    matches!(
        (sev, a.severity),
        (Sev::All, _) | (Sev::Info, Info) | (Sev::Warn, Warn) | (Sev::Crit, Critical)
    )
}

fn who(a: &Alert) -> String {
    let act = &a.actor;
    if !act.uname.is_empty() {
        format!("{}({})", act.uname, act.uid)
    } else if !act.uid.is_empty() {
        format!("uid={}", act.uid)
    } else {
        "-".to_string()
    }
}

fn sev_label(a: &Alert) -> &'static str {
    use ch_common::proto::AlertSeverity::*;
    match a.severity {
        Critical => "critical",
        Warn => "warn",
        Info => "info",
    }
}

fn hms(unix: u64) -> String {
    let s = unix % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

impl App {
    fn new(rows: Vec<DumpRow>) -> Self {
        let mut kinds: Vec<String> = rows.iter().map(|r| r.alert.kind.clone()).collect();
        kinds.sort();
        kinds.dedup();
        let mut app = App {
            rows,
            kinds,
            view: Vec::new(),
            state: TableState::default(),
            sev: Sev::All,
            kind_idx: 0,
            search: String::new(),
            searching: false,
            detail: false,
            sort: Sort::TimeDesc,
        };
        app.recompute();
        app
    }

    fn kind_filter(&self) -> Option<&str> {
        if self.kind_idx == 0 {
            None
        } else {
            self.kinds.get(self.kind_idx - 1).map(String::as_str)
        }
    }

    fn recompute(&mut self) {
        let needle = self.search.to_lowercase();
        let kind_f = self.kind_filter().map(str::to_owned);
        let mut view: Vec<usize> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| sev_matches(&r.alert, self.sev))
            .filter(|(_, r)| kind_f.as_deref().map_or(true, |k| r.alert.kind == k))
            .filter(|(_, r)| {
                if needle.is_empty() {
                    return true;
                }
                let a = &r.alert;
                format!("{} {} {} {}", a.kind, a.path, a.detail, who(a)).to_lowercase().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect();

        match self.sort {
            Sort::TimeDesc => view.sort_by(|&a, &b| self.rows[b].alert.unix_time.cmp(&self.rows[a].alert.unix_time)),
            Sort::Severity => view.sort_by(|&a, &b| {
                sev_rank(&self.rows[b].alert)
                    .cmp(&sev_rank(&self.rows[a].alert))
                    .then(self.rows[b].alert.unix_time.cmp(&self.rows[a].alert.unix_time))
            }),
            Sort::Kind => view.sort_by(|&a, &b| self.rows[a].alert.kind.cmp(&self.rows[b].alert.kind)),
        }

        self.view = view;
        let sel = self.state.selected().unwrap_or(0).min(self.view.len().saturating_sub(1));
        self.state.select(if self.view.is_empty() { None } else { Some(sel) });
    }

    fn move_sel(&mut self, delta: isize) {
        if self.view.is_empty() {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, self.view.len() as isize - 1);
        self.state.select(Some(next as usize));
    }

    fn selected_alert(&self) -> Option<&Alert> {
        let i = *self.view.get(self.state.selected()?)?;
        Some(&self.rows[i].alert)
    }
}

/// Build the console block printed when an alert is pinned, including suggested follow-ups.
fn console_block(a: &Alert) -> String {
    let mut s = String::from("\n\u{25c8} pinned alert ---------------------------------------\n");
    s += &format!("  time:   {} (unix {})\n", hms(a.unix_time), a.unix_time);
    s += &format!("  sev:    {}\n", sev_label(a));
    s += &format!("  kind:   {}\n", a.kind);
    s += &format!("  path:   {}\n", if a.path.is_empty() { "-" } else { &a.path });
    s += &format!("  detail: {}\n", a.detail);
    s += &format!("  who:    {}\n", who(a));
    let mut acts = Vec::new();
    if a.actor.pid != 0 {
        acts.push(format!("attribute {}", a.actor.pid));
        acts.push(format!("kill {}", a.actor.pid));
    }
    if !a.actor.login.is_empty() {
        acts.push(format!("kick {}", a.actor.login));
    }
    if !a.path.is_empty() {
        acts.push(format!("watch add {}", a.path));
    }
    if !acts.is_empty() {
        s += &format!("  next:   {}\n", acts.join("   |   "));
    }
    s += "------------------------------------------------------\n";
    s
}

fn run_tui(rows: Vec<DumpRow>) -> io::Result<Option<Outcome>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = App::new(rows);
    let result = event_loop(&mut term, &mut app);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    result
}

fn event_loop<B: ratatui::backend::Backend>(term: &mut Terminal<B>, app: &mut App) -> io::Result<Option<Outcome>> {
    loop {
        term.draw(|f| draw(f, app))?;
        if !event::poll(std::time::Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else { continue };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if app.searching {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => app.searching = false,
                KeyCode::Backspace => {
                    app.search.pop();
                    app.recompute();
                }
                KeyCode::Char(c) => {
                    app.search.push(c);
                    app.recompute();
                }
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Char('q') => return Ok(None),
            KeyCode::Esc => {
                if app.detail {
                    app.detail = false;
                } else {
                    return Ok(None);
                }
            }
            KeyCode::Up => app.move_sel(-1),
            KeyCode::Down => app.move_sel(1),
            KeyCode::PageUp => app.move_sel(-10),
            KeyCode::PageDown => app.move_sel(10),
            KeyCode::Home => app.state.select((!app.view.is_empty()).then_some(0)),
            KeyCode::End => app.move_sel(app.view.len() as isize),
            KeyCode::Enter => app.detail = !app.detail,
            // p: pin the selected alert to the console and close.
            KeyCode::Char('p') => {
                if let Some(a) = app.selected_alert().cloned() {
                    return Ok(Some(Outcome::Print(console_block(&a))));
                }
            }
            // a: close and run the dossier (attribute) on the alert's pid.
            KeyCode::Char('a') => {
                if let Some(a) = app.selected_alert() {
                    if a.actor.pid != 0 {
                        return Ok(Some(Outcome::Exec("attribute".to_string(), vec![a.actor.pid.to_string()])));
                    }
                }
            }
            // w: close and add the alert's path to the watchlist.
            KeyCode::Char('w') => {
                if let Some(a) = app.selected_alert() {
                    if !a.path.is_empty() {
                        return Ok(Some(Outcome::Exec("watch".to_string(), vec!["add".to_string(), a.path.clone()])));
                    }
                }
            }
            KeyCode::Char('s') => {
                app.sev = app.sev.next();
                app.recompute();
            }
            KeyCode::Char('f') => {
                app.kind_idx = (app.kind_idx + 1) % (app.kinds.len() + 1);
                app.recompute();
            }
            KeyCode::Char('t') => {
                app.sort = app.sort.next();
                app.recompute();
            }
            KeyCode::Char('/') => {
                app.searching = true;
                app.search.clear();
                app.recompute();
            }
            _ => {}
        }
    }
}

fn sev_style(a: &Alert) -> Style {
    use ch_common::proto::AlertSeverity::*;
    match a.severity {
        Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Warn => Style::default().fg(Color::Yellow),
        Info => Style::default().fg(Color::Gray),
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.detail {
            vec![Constraint::Min(5), Constraint::Length(10), Constraint::Length(1)]
        } else {
            vec![Constraint::Min(5), Constraint::Length(1)]
        })
        .split(f.size());

    let header = Row::new(["TIME", "SEV", "KIND", "PATH", "WHO"]).style(Style::default().add_modifier(Modifier::BOLD));
    let rows = app.view.iter().map(|&i| {
        let a = &app.rows[i].alert;
        Row::new([
            hms(a.unix_time),
            sev_label(a).to_string(),
            a.kind.clone(),
            a.path.clone(),
            who(a),
        ])
        .style(sev_style(a))
    });
    let widths = [
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(16),
        Constraint::Min(20),
        Constraint::Length(22),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(" Alerts ({}/{}) ", app.view.len(), app.rows.len())))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, chunks[0], &mut app.state);

    if app.detail {
        let text = match app.selected_alert() {
            Some(a) => {
                let act = &a.actor;
                vec![
                    Line::from(format!("kind:     {}", a.kind)),
                    Line::from(format!("severity: {}", sev_label(a))),
                    Line::from(format!("time:     {} (unix {})", hms(a.unix_time), a.unix_time)),
                    Line::from(format!("path:     {}", a.path)),
                    Line::from(format!("detail:   {}", a.detail)),
                    Line::from(format!(
                        "who:      uid={} user={} login(auid)={}/{} pid={} ppid={}",
                        act.uid, act.uname, act.auid, act.login, act.pid, act.ppid
                    )),
                    Line::from(format!("exe:      {}", act.exe)),
                    Line::from(format!("cmd:      {}", act.cmdline)),
                ]
            }
            None => vec![Line::from("(no selection)")],
        };
        let detail = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title(" Detail (Enter/Esc to close) "))
            .wrap(Wrap { trim: false });
        f.render_widget(detail, chunks[1]);
    }

    let footer_idx = chunks.len() - 1;
    let footer = if app.searching {
        Line::from(vec![
            Span::styled("search: ", Style::default().fg(Color::Cyan)),
            Span::raw(&app.search),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ])
    } else {
        Line::from(format!(
            "sev:{}  kind:{}  sort:{}  search:{}  | s/f/t cycle  / search  Enter detail  p pin  a attribute  w watch  q quit",
            app.sev.label(),
            app.kind_filter().unwrap_or("all"),
            app.sort.label(),
            if app.search.is_empty() { "-" } else { &app.search },
        ))
    };
    f.render_widget(Paragraph::new(footer), chunks[footer_idx]);
}
