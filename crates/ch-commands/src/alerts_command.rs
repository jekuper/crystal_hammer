//! Alert browser. `alerts dump [since] [limit]` pages stored alerts out of the evidence
//! log as NDJSON (also the scripting/test path); `alerts` with no args opens an interactive
//! TUI over that history - scroll, filter by severity/kind, free-text search, sort, and
//! open a detail view. Read-only: it only reads the evidence log.

use std::collections::HashSet;
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
    #[serde(default)]
    acked: bool,
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
        let sub = args.first().map(String::as_str);
        let Some(store) = ctx.store.clone() else {
            ctx.stdout.write_all(b"state store unavailable; no alert history\n").await?;
            return Ok(());
        };
        match sub {
            Some("dump") => {
                // Args in any order: a time window (45s/30m/2h/1d or "all") and/or a bare
                // count limit. Default: everything.
                let mut window_secs: Option<u64> = None; // None = all time
                let mut limit = usize::MAX;
                for a in &args[1..] {
                    if a == "all" {
                        window_secs = None;
                    } else if let Some(secs) = parse_window(a) {
                        window_secs = Some(secs);
                    } else if let Ok(n) = a.parse::<usize>() {
                        limit = n;
                    }
                }
                let cutoff = window_secs.map(|w| unix_now().saturating_sub(w));
                let acked = store.acked_cursors().unwrap_or_default();
                // Collect matches in chronological order, then keep only the newest `limit`.
                let mut matched: Vec<_> = store
                    .since(0, usize::MAX)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|rec| rec.kind == "alert")
                    .filter(|rec| match cutoff {
                        None => true,
                        Some(c) => rec.body.get("unix_time").and_then(|v| v.as_u64()).unwrap_or(0) >= c,
                    })
                    .collect();
                if matched.len() > limit {
                    matched.drain(0..matched.len() - limit);
                }
                for rec in matched {
                    let line = serde_json::json!({
                        "cursor": rec.cursor,
                        "alert": rec.body,
                        "acked": acked.contains(&rec.cursor),
                    })
                    .to_string();
                    if ctx.stdout.write_all(line.as_bytes()).await.is_err() {
                        break;
                    }
                    let _ = ctx.stdout.write_all(b"\n").await;
                }
            }
            // ack/unack take one or more evidence cursors (as printed by dump / the TUI).
            Some("ack") | Some("unack") => {
                let on = sub == Some("ack");
                let cursors: Vec<u64> = args[1..].iter().filter_map(|s| s.parse().ok()).collect();
                if cursors.is_empty() {
                    ctx.stdout.write_all(b"usage: alerts ack|unack <cursor> [cursor...]\n").await?;
                    return Ok(());
                }
                let mut n = 0usize;
                for c in &cursors {
                    let r = if on { store.ack_alert(*c, "") } else { store.unack_alert(*c) };
                    if r.is_ok() {
                        n += 1;
                    }
                }
                let verb = if on { "acknowledged" } else { "unacknowledged" };
                ctx.stdout.write_all(format!("{verb} {n} alert(s)\n").as_bytes()).await?;
            }
            _ => {
                ctx.stdout
                    .write_all(b"usage: alerts dump [window] [limit] | alerts ack|unack <cursor>...\n")
                    .await?;
            }
        }
        Ok(())
    }
}

/// Seconds since the Unix epoch, now.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a relative time window like "45s", "30m", "2h", "1d" into seconds.
/// Returns None when the string is not a `<number><unit>` window (e.g. a bare count).
fn parse_window(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    Some(n.saturating_mul(secs))
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
        "Usage: alerts [dump [window] [limit] | ack|unack <cursor>...]\n\n\
        With no args: opens an interactive browser over the alert history.\n\
        Press '?' inside it for the full key list. Short version:\n\
          move    up/down pgup/pgdn home/end       filter  s sev  f kind  / search  h hide-acked\n\
          sort    t                                view    Enter details   ? keys\n\
          act     p pin to console   a attribute   w watch   x ack   k kill   e evict(kick)\n\
          quit    q  (pending ack marks are saved on quit)\n\
        'p' prints the full alert into the console and closes, so you keep it without reopening.\n\
        'k'/'e' ask for confirmation (default no) before closing and acting.\n\n\
        alerts dump [window] [limit]   print the history as NDJSON (for scripting / piping).\n\
          window: <n><unit> where unit is s/m/h/d (e.g. 45s, 30m, 2h, 1d), or 'all'.\n\
                  a bare number with no unit is a count, not a window.\n\
          examples:  alerts dump          all stored alerts\n\
                     alerts dump 30m       the past 30 minutes\n\
                     alerts dump 2h 50     the past 2 hours, newest 50\n\
                     alerts dump 100       the newest 100, any time\n\
        alerts ack|unack <cursor>...   mark alerts handled (cursor is the 'cursor' field in dump)."
    }
    fn complete_arg(&self, _p: &[&str], _w: &str, _c: &rustyline::Context<'_>, _f: &FilenameCompleter) -> Vec<Pair> {
        Vec::new()
    }
    async fn execute(&self, _e: &dyn ClientCommandExecutor, args: &[String], ctx: ClientCommandContext<'_>) -> Result<()> {
        if matches!(args.first().map(String::as_str), Some("dump") | Some("ack") | Some("unack")) {
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
        .exec(true, b"alerts dump")
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

/// A destructive action staged behind a y/N confirmation.
struct Confirm {
    prompt: String,
    outcome: Outcome,
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
    help: bool,
    sort: Sort,
    hide_acked: bool,
    // Cursors marked for acknowledgement this session; flushed to the agent on quit.
    pending_ack: HashSet<u64>,
    confirm: Option<Confirm>,
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
            help: false,
            sort: Sort::TimeDesc,
            hide_acked: false,
            pending_ack: HashSet::new(),
            confirm: None,
        };
        app.recompute();
        app
    }

    /// True if the row is acknowledged, either already on the agent or staged this session.
    fn is_acked(&self, r: &DumpRow) -> bool {
        r.acked || self.pending_ack.contains(&r.cursor)
    }

    fn selected_row(&self) -> Option<&DumpRow> {
        let i = *self.view.get(self.state.selected()?)?;
        Some(&self.rows[i])
    }

    /// Toggle the staged acknowledgement for the selected alert. Already-acked alerts are
    /// left alone (unack is a prompt command, not a TUI gesture).
    fn toggle_ack(&mut self) {
        if let Some(r) = self.selected_row() {
            if r.acked {
                return;
            }
            let c = r.cursor;
            if !self.pending_ack.remove(&c) {
                self.pending_ack.insert(c);
            }
            if self.hide_acked {
                self.recompute();
            }
        }
    }

    /// The outcome to return when the browser closes: flush any staged acks, else nothing.
    fn on_close(&self) -> Option<Outcome> {
        if self.pending_ack.is_empty() {
            return None;
        }
        let mut cursors: Vec<u64> = self.pending_ack.iter().copied().collect();
        cursors.sort_unstable();
        let mut args = vec!["ack".to_string()];
        args.extend(cursors.into_iter().map(|c| c.to_string()));
        Some(Outcome::Exec("alerts".to_string(), args))
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
        let hide_acked = self.hide_acked;
        let pending = self.pending_ack.clone();
        let mut view: Vec<usize> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| !(hide_acked && (r.acked || pending.contains(&r.cursor))))
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

fn dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

/// Build the console block printed when an alert is pinned. Prints every field (like `dump`,
/// but formatted) plus the acknowledgement state and suggested follow-up commands.
fn console_block(row: &DumpRow, acked: bool) -> String {
    let a = &row.alert;
    let act = &a.actor;
    let mut s = String::from("\n\u{25c8} pinned alert ---------------------------------------\n");
    s += &format!("  cursor:   {}\n", row.cursor);
    s += &format!("  acked:    {}\n", if acked { "yes" } else { "no" });
    s += &format!("  time:     {} (unix {})\n", hms(a.unix_time), a.unix_time);
    s += &format!("  severity: {}\n", sev_label(a));
    s += &format!("  kind:     {}\n", a.kind);
    s += &format!("  path:     {}\n", dash(&a.path));
    s += &format!("  detail:   {}\n", dash(&a.detail));
    s += &format!("  uid:      {}\n", dash(&act.uid));
    s += &format!("  uname:    {}\n", dash(&act.uname));
    s += &format!("  auid:     {}\n", dash(&act.auid));
    s += &format!("  login:    {}\n", dash(&act.login));
    s += &format!("  pid:      {}\n", act.pid);
    s += &format!("  ppid:     {}\n", dash(&act.ppid));
    s += &format!("  exe:      {}\n", dash(&act.exe));
    s += &format!("  comm:     {}\n", dash(&act.comm));
    s += &format!("  cmdline:  {}\n", dash(&act.cmdline));
    let mut acts = Vec::new();
    if act.pid != 0 {
        acts.push(format!("attribute {}", act.pid));
        acts.push(format!("kill {}", act.pid));
    }
    if !act.login.is_empty() {
        acts.push(format!("kick {}", act.login));
    }
    if !a.path.is_empty() {
        acts.push(format!("watch add {}", a.path));
    }
    acts.push(format!("alerts ack {}", row.cursor));
    s += &format!("  next:     {}\n", acts.join("  |  "));
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

        // A staged destructive action: only 'y' proceeds, anything else cancels.
        if let Some(c) = app.confirm.take() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => return Ok(Some(c.outcome)),
                _ => {}
            }
            continue;
        }

        // Help overlay: any key closes it.
        if app.help {
            app.help = false;
            continue;
        }

        match key.code {
            KeyCode::Char('q') => return Ok(app.on_close()),
            KeyCode::Esc => {
                if app.detail {
                    app.detail = false;
                } else {
                    return Ok(app.on_close());
                }
            }
            KeyCode::Char('?') => app.help = true,
            KeyCode::Up => app.move_sel(-1),
            KeyCode::Down => app.move_sel(1),
            KeyCode::PageUp => app.move_sel(-10),
            KeyCode::PageDown => app.move_sel(10),
            KeyCode::Home => app.state.select((!app.view.is_empty()).then_some(0)),
            KeyCode::End => app.move_sel(app.view.len() as isize),
            KeyCode::Enter => app.detail = !app.detail,
            // p: pin the full alert to the console and close.
            KeyCode::Char('p') => {
                if let Some(r) = app.selected_row() {
                    let block = console_block(r, app.is_acked(r));
                    return Ok(Some(Outcome::Print(block)));
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
            // x: toggle acknowledgement on the selected alert (saved on quit).
            KeyCode::Char('x') => app.toggle_ack(),
            // k: kill the alert's pid, behind a confirmation.
            KeyCode::Char('k') => {
                if let Some(a) = app.selected_alert() {
                    if a.actor.pid != 0 {
                        let pid = a.actor.pid;
                        app.confirm = Some(Confirm {
                            prompt: format!("kill pid {pid}?"),
                            outcome: Outcome::Exec("kill".to_string(), vec![pid.to_string()]),
                        });
                    }
                }
            }
            // e: evict (kick) the alert's login user, behind a confirmation.
            KeyCode::Char('e') => {
                if let Some(a) = app.selected_alert() {
                    if !a.actor.login.is_empty() {
                        let login = a.actor.login.clone();
                        app.confirm = Some(Confirm {
                            prompt: format!("evict (kick) user {login}?"),
                            outcome: Outcome::Exec("kick".to_string(), vec![login]),
                        });
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
            KeyCode::Char('h') => {
                app.hide_acked = !app.hide_acked;
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

const HELP_LINES: &[(&str, &str)] = &[
    ("move", "up/down  pgup/pgdn  home/end"),
    ("filter", "s severity   f kind   / search   h hide-acked"),
    ("sort", "t  (time / severity / kind)"),
    ("view", "Enter details   ? this help"),
    ("act", "p pin to console   a attribute   w watch path"),
    ("", "x ack (toggle)   k kill pid   e evict (kick) user"),
    ("quit", "q   (staged ack marks are saved on quit)"),
];

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.detail {
            vec![Constraint::Min(5), Constraint::Length(11), Constraint::Length(1)]
        } else {
            vec![Constraint::Min(5), Constraint::Length(1)]
        })
        .split(f.area());

    if app.help {
        draw_help(f, chunks[0]);
    } else {
        let header = Row::new(["AK", "TIME", "SEV", "KIND", "PATH", "WHO"])
            .style(Style::default().add_modifier(Modifier::BOLD));
        let rows: Vec<Row> = app
            .view
            .iter()
            .map(|&i| {
                let r = &app.rows[i];
                let a = &r.alert;
                let acked = r.acked || app.pending_ack.contains(&r.cursor);
                let mark = if acked { "*" } else { "" };
                let mut style = sev_style(a);
                if acked {
                    style = style.add_modifier(Modifier::DIM);
                }
                Row::new([
                    mark.to_string(),
                    hms(a.unix_time),
                    sev_label(a).to_string(),
                    a.kind.clone(),
                    a.path.clone(),
                    who(a),
                ])
                .style(style)
            })
            .collect();
        let widths = [
            Constraint::Length(2),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Min(20),
            Constraint::Length(22),
        ];
        let acks = app.pending_ack.len();
        let title = if acks > 0 {
            format!(" Alerts ({}/{})  {} ack pending ", app.view.len(), app.rows.len(), acks)
        } else {
            format!(" Alerts ({}/{}) ", app.view.len(), app.rows.len())
        };
        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        f.render_stateful_widget(table, chunks[0], &mut app.state);
    }

    if app.detail {
        let text = match app.selected_row() {
            Some(r) => {
                let a = &r.alert;
                let act = &a.actor;
                vec![
                    Line::from(format!("cursor:   {}   acked: {}", r.cursor, if app.is_acked(r) { "yes" } else { "no" })),
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
    let footer = draw_footer(app);
    f.render_widget(Paragraph::new(footer), chunks[footer_idx]);
}

fn draw_help(f: &mut Frame, area: ratatui::layout::Rect) {
    let mut lines = vec![Line::from(Span::styled(
        "Keys",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    for (group, keys) in HELP_LINES {
        lines.push(Line::from(vec![
            Span::styled(format!("{:>7}  ", group), Style::default().fg(Color::Cyan)),
            Span::raw(*keys),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "press any key to close",
        Style::default().fg(Color::DarkGray),
    )));
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Help "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

// A single compact status line: confirm prompt, or search input, or filter state + a hint.
fn draw_footer(app: &App) -> Line<'static> {
    if let Some(c) = &app.confirm {
        return Line::from(vec![
            Span::styled(c.prompt.clone(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled("y", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw(" / "),
            Span::styled("N", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" (any other key cancels)"),
        ]);
    }
    if app.searching {
        return Line::from(vec![
            Span::styled("search: ", Style::default().fg(Color::Cyan)),
            Span::raw(app.search.clone()),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ]);
    }
    let acked = if app.hide_acked { "hidden" } else { "shown" };
    Line::from(vec![
        Span::styled(
            format!(
                "sev:{}  kind:{}  sort:{}  acked:{}",
                app.sev.label(),
                app.kind_filter().unwrap_or("all"),
                app.sort.label(),
                acked,
            ),
            Style::default().fg(Color::Gray),
        ),
        Span::raw("   "),
        Span::styled("?", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" keys  "),
        Span::styled("q", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" quit"),
    ])
}

#[cfg(test)]
mod tests {
    use super::parse_window;

    #[test]
    fn windows_parse() {
        assert_eq!(parse_window("45s"), Some(45));
        assert_eq!(parse_window("30m"), Some(1800));
        assert_eq!(parse_window("2h"), Some(7200));
        assert_eq!(parse_window("1d"), Some(86_400));
        // bare counts and junk are not windows
        assert_eq!(parse_window("100"), None);
        assert_eq!(parse_window("s"), None);
        assert_eq!(parse_window(""), None);
    }
}
