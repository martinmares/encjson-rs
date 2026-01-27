use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap};
use ratatui::Terminal;
use serde::Deserialize;
use serde_json::Value;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Mode {
    Normal,
    Filter,
    Edit,
    TenantSelect,
    StatusSelect,
    NoteEdit,
    TagsEdit,
    TenantAdd,
    TenantRename,
    RequestEdit,
    RequestFieldEdit,
    RequestTenantSelect,
    RequestReject,
    ConfirmExit,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum View {
    Keys,
    Tenants,
    Tags,
    Requests,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct KeyItem {
    public_hex: String,
    tenant: String,
    status: String,
    note: String,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct RequestItem {
    id: i64,
    public_hex: String,
    tenant: String,
    note: String,
    tags: Vec<String>,
    status: String,
    requested_by: Option<String>,
    requested_at: String,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CtlData {
    pub items: Vec<KeyItem>,
    pub tenants: Option<Vec<String>>,
    pub statuses: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub requests: Option<Vec<RequestItem>>,
}

struct App {
    view: View,
    items: Vec<KeyItem>,
    selected_keys: usize,
    selected_tenants: usize,
    selected_tags: usize,
    selected_requests: usize,
    mode: Mode,
    status_base: String,
    status_temp: Option<TempStatus>,
    filter: Option<String>,
    input: Input,
    draft: Option<KeyDraft>,
    request_draft: Option<RequestDraft>,
    tenant_choices: Vec<String>,
    status_choices: Vec<String>,
    tenants: Vec<String>,
    tags: Vec<String>,
    requests: Vec<RequestItem>,
    edit_field: usize,
    data_path: Option<String>,
    save_tenants: bool,
    save_statuses: bool,
    dirty: bool,
    help_active: bool,
    read_only: bool,
    remote: Option<RemoteConfig>,
}

#[derive(Debug, Clone)]
struct TempStatus {
    message: String,
    expires_at: Instant,
    is_error: bool,
}

#[derive(Debug, Clone)]
struct KeyDraft {
    tenant: String,
    status: String,
    note: String,
    tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct RequestDraft {
    id: i64,
    tenant: String,
    note: String,
    tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct RemoteConfig {
    base_url: String,
    access_token: String,
}

impl App {
    fn new() -> Self {
        let mut status_base = "ready".to_string();
        let mut items = sample_items();
        let mut requests = Vec::new();
        let mut tenant_choices = Vec::new();
        let mut status_choices = Vec::new();
        let mut tenants = Vec::new();
        let mut tags = Vec::new();
        let mut data_path = None;
        let mut save_tenants = false;
        let mut save_statuses = false;

        match load_ctl_data() {
            Ok(Some(data)) => {
                status_base = format!("mock data: {}", data_source_label());
                items = data.items;
                requests = data.requests.unwrap_or_default();
                save_tenants = data.tenants.is_some();
                save_statuses = data.statuses.is_some();
                tenant_choices =
                    merge_choices(data.tenants, items.iter().map(|item| item.tenant.clone()));
                status_choices =
                    merge_choices(data.statuses, items.iter().map(|item| item.status.clone()));
                tenants = tenant_choices.clone();
                tags = data.tags.unwrap_or_default();
                data_path = Some(data_source_label());
            }
            Ok(None) => {}
            Err(err) => {
                status_base = format!("mock load failed: {err}");
            }
        }

        if tenant_choices.is_empty() {
            tenant_choices = vec![
                "cetin".to_string(),
                "o2".to_string(),
                "cez".to_string(),
            ];
        }
        if status_choices.is_empty() {
            status_choices = vec![
                "active".to_string(),
                "deprecated".to_string(),
                "hidden".to_string(),
            ];
        }
        if tenants.is_empty() {
            tenants = tenant_choices.clone();
        }

        Self {
            view: View::Keys,
            items,
            selected_keys: 0,
            selected_tenants: 0,
            selected_tags: 0,
            selected_requests: 0,
            mode: Mode::Normal,
            status_base,
            status_temp: None,
            filter: None,
            input: Input::default(),
            draft: None,
            request_draft: None,
            tenant_choices,
            status_choices,
            tenants,
            tags,
            requests,
            edit_field: 0,
            data_path,
            save_tenants,
            save_statuses,
            dirty: false,
            help_active: false,
            read_only: false,
            remote: None,
        }
    }

    fn from_data(data: Option<CtlData>, status: Option<String>, read_only: bool) -> Self {
        let mut items = sample_items();
        let mut requests = Vec::new();
        let mut tenant_choices = Vec::new();
        let mut status_choices = Vec::new();
        let mut tenants = Vec::new();
        let mut tags = Vec::new();
        if let Some(data) = data {
            items = data.items;
            tenant_choices =
                merge_choices(data.tenants, items.iter().map(|item| item.tenant.clone()));
            status_choices =
                merge_choices(data.statuses, items.iter().map(|item| item.status.clone()));
            tenants = tenant_choices.clone();
            tags = data.tags.unwrap_or_default();
            requests = data.requests.unwrap_or_default();
        }
        if tenant_choices.is_empty() {
            tenant_choices = items
                .iter()
                .map(|item| item.tenant.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        }
        if status_choices.is_empty() {
            status_choices = vec![
                "active".to_string(),
                "deprecated".to_string(),
                "hidden".to_string(),
            ];
        }
        if tenants.is_empty() {
            tenants = tenant_choices.clone();
        }
        Self {
            view: View::Keys,
            items,
            selected_keys: 0,
            selected_tenants: 0,
            selected_tags: 0,
            selected_requests: 0,
            mode: Mode::Normal,
            status_base: status.unwrap_or_else(|| "ready".to_string()),
            status_temp: None,
            filter: None,
            input: Input::default(),
            draft: None,
            request_draft: None,
            tenant_choices,
            status_choices,
            tenants,
            tags,
            requests,
            edit_field: 0,
            data_path: None,
            save_tenants: false,
            save_statuses: false,
            dirty: false,
            help_active: false,
            read_only,
            remote: None,
        }
    }

    fn with_remote(mut self, base_url: String, access_token: String) -> Self {
        self.remote = Some(RemoteConfig { base_url, access_token });
        self
    }
}

fn load_ctl_data() -> Result<Option<CtlData>, Box<dyn Error>> {
    let path = match env::var("ENCJSON_CTL_DATA") {
        Ok(path) if !path.trim().is_empty() => path,
        _ => return Ok(None),
    };
    let contents = fs::read_to_string(&path)?;
    let data = serde_json::from_str::<CtlData>(&contents)?;
    Ok(Some(data))
}

fn data_source_label() -> String {
    env::var("ENCJSON_CTL_DATA").unwrap_or_else(|_| "default".to_string())
}

fn merge_choices<I>(primary: Option<Vec<String>>, extra: I) -> Vec<String>
where
    I: Iterator<Item = String>,
{
    let mut set = BTreeSet::new();
    if let Some(list) = primary {
        for item in list {
            if !item.trim().is_empty() {
                set.insert(item);
            }
        }
    }
    for item in extra {
        if !item.trim().is_empty() {
            set.insert(item);
        }
    }
    set.into_iter().collect()
}

fn choice_index(choices: &[String], value: &str) -> usize {
    choices
        .iter()
        .position(|item| item == value)
        .unwrap_or(0)
}

pub fn run_ctl_ui() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

#[allow(dead_code)]
pub fn run_ctl_ui_with_data(
    data: Option<CtlData>,
    status: Option<String>,
    read_only: bool,
) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::from_data(data, status, read_only);
    let res = run_app_with(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

pub fn run_ctl_ui_with_remote(
    base_url: String,
    access_token: String,
) -> Result<(), Box<dyn Error>> {
    let status = format!("remote: {}", base_url);
    let data = fetch_remote_keys(&base_url, &access_token)?;
    let tenants = fetch_remote_tenants(&base_url, &access_token)?;
    let statuses = fetch_remote_statuses(&base_url, &access_token)?;
    let requests = fetch_remote_requests(&base_url, &access_token)?;
    let mut app = App::from_data(
        Some(CtlData {
            items: data,
            tenants: Some(tenants),
            statuses: Some(statuses),
            tags: None,
            requests: Some(requests),
        }),
        Some(status),
        false,
    )
    .with_remote(base_url, access_token);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app_with(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), Box<dyn Error>> {
    let mut app = App::new();
    run_app_with(terminal, &mut app)
}

fn run_app_with(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn Error>> {
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(200);

    loop {
        terminal.draw(|f| render_ui(f, app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if handle_key(app, key)? {
                        return Ok(());
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<bool, Box<dyn Error>> {
    if app.help_active {
        match key.code {
            KeyCode::Char('h') | KeyCode::Esc => {
                app.help_active = false;
            }
            _ => {}
        }
        return Ok(false);
    }

    match app.mode {
        Mode::Normal => match key.code {
            KeyCode::Tab => {
                app.view = match app.view {
                    View::Keys => View::Tenants,
                    View::Tenants => View::Tags,
                    View::Tags => View::Requests,
                    View::Requests => View::Keys,
                };
                app.status_temp = None;
                refresh_remote_data(app);
            }
            KeyCode::BackTab => {
                app.view = match app.view {
                    View::Keys => View::Requests,
                    View::Tenants => View::Keys,
                    View::Tags => View::Tenants,
                    View::Requests => View::Tags,
                };
                app.status_temp = None;
                refresh_remote_data(app);
            }
            KeyCode::Up => {
                move_selection(app, -1);
            }
            KeyCode::Down => {
                move_selection(app, 1);
            }
            KeyCode::PageUp => {
                move_selection(app, -10);
            }
            KeyCode::PageDown => {
                move_selection(app, 10);
            }
            KeyCode::Enter if app.view == View::Keys => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                if let Some(remote) = &app.remote {
                    if let Some(item) = selected_item(app) {
                        match fetch_remote_key(remote, &item.public_hex) {
                            Ok(updated) => update_item(app, updated),
                            Err(err) => set_status_error(app, format!("detail fetch failed: {err}")),
                        }
                    }
                }
                if let Some(item) = selected_item(app) {
                    app.draft = Some(KeyDraft {
                        tenant: item.tenant.clone(),
                        status: item.status.clone(),
                        note: item.note.clone(),
                        tags: item.tags.clone(),
                    });
                    app.edit_field = 0;
                    app.mode = Mode::Edit;
                }
            }
            KeyCode::Char('e') if app.view == View::Keys => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                if let Some(remote) = &app.remote {
                    if let Some(item) = selected_item(app) {
                        match fetch_remote_key(remote, &item.public_hex) {
                            Ok(updated) => update_item(app, updated),
                            Err(err) => set_status_error(app, format!("detail fetch failed: {err}")),
                        }
                    }
                }
                if let Some(item) = selected_item(app) {
                    app.draft = Some(KeyDraft {
                        tenant: item.tenant.clone(),
                        status: item.status.clone(),
                        note: item.note.clone(),
                        tags: item.tags.clone(),
                    });
                    app.edit_field = 0;
                    app.mode = Mode::Edit;
                }
            }
            KeyCode::Char('e') if app.view == View::Requests => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                if let Some(request) = selected_request(app) {
                    app.request_draft = Some(RequestDraft {
                        id: request.id,
                        tenant: request.tenant.clone(),
                        note: request.note.clone(),
                        tags: request.tags.clone(),
                    });
                    app.edit_field = 0;
                    app.mode = Mode::RequestEdit;
                }
            }
            KeyCode::Char('/') => {
                app.input = Input::new(app.filter.clone().unwrap_or_default());
                app.mode = Mode::Filter;
            }
            KeyCode::Char('n') if app.view == View::Tenants => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                app.input = Input::default();
                app.mode = Mode::TenantAdd;
            }
            KeyCode::Char('e') if app.view == View::Tenants => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                if let Some(name) = selected_tenant_name(app) {
                    app.input = Input::new(name);
                    app.mode = Mode::TenantRename;
                }
            }
            KeyCode::Char('d') if app.view == View::Tenants => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                if let Err(err) = delete_tenant(app) {
                    set_status_error(app, format!("tenant delete failed: {err}"));
                } else {
                    set_status(app, "tenant deleted");
                    app.dirty = true;
                }
            }
            KeyCode::Char('a') if app.view == View::Requests => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                if let Err(err) = approve_request(app) {
                    set_status_error(app, format!("approve failed: {err}"));
                } else {
                    set_status(app, "request approved");
                    app.dirty = true;
                }
            }
            KeyCode::Char('x') if app.view == View::Requests => {
                if app.read_only {
                    set_status(app, "read-only");
                    return Ok(false);
                }
                app.input = Input::default();
                app.mode = Mode::RequestReject;
            }
            KeyCode::Char('q') => {
                if app.dirty {
                    app.mode = Mode::ConfirmExit;
                } else {
                    return Ok(true);
                }
            }
            KeyCode::Char('h') => {
                app.help_active = true;
            }
            _ => {}
        },
        Mode::Filter => match key.code {
            KeyCode::Enter => {
                let value = app.input.value().trim().to_string();
                app.filter = if value.is_empty() { None } else { Some(value) };
                app.mode = Mode::Normal;
                reset_selection(app);
            }
            KeyCode::Esc => {
                app.mode = Mode::Normal;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::Edit => match key.code {
            KeyCode::Up => {
                if app.edit_field > 0 {
                    app.edit_field -= 1;
                }
            }
            KeyCode::Down => {
                if app.edit_field < 3 {
                    app.edit_field += 1;
                }
            }
            KeyCode::Enter => match app.edit_field {
                0 => {
                    if let Some(draft) = app.draft.as_ref() {
                        app.edit_field = choice_index(&app.tenant_choices, &draft.tenant);
                    } else {
                        app.edit_field = 0;
                    }
                    app.mode = Mode::TenantSelect;
                }
                1 => {
                    if let Some(draft) = app.draft.as_ref() {
                        app.edit_field = choice_index(&app.status_choices, &draft.status);
                    } else {
                        app.edit_field = 0;
                    }
                    app.mode = Mode::StatusSelect;
                }
                2 => {
                    if let Some(draft) = app.draft.as_ref() {
                        let tags = draft.tags.join(", ");
                        let len = tags.chars().count();
                        app.input = Input::new(tags).with_cursor(len);
                    } else {
                        app.input = Input::default();
                    }
                    app.mode = Mode::TagsEdit;
                }
                3 => {
                    if let Some(draft) = app.draft.as_ref() {
                        let len = draft.note.chars().count();
                        app.input = Input::new(draft.note.clone()).with_cursor(len);
                    } else {
                        app.input = Input::default();
                    }
                    app.mode = Mode::NoteEdit;
                }
                _ => {}
            },
            KeyCode::Char('s') => {
                match apply_draft(app) {
                    Ok(saved) => {
                        if saved {
                            set_status(app, "saved");
                            app.dirty = true;
                        }
                    }
                    Err(err) => {
                        set_status_error(app, format!("save failed: {err}"));
                    }
                }
                app.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                app.draft = None;
                app.mode = Mode::Normal;
            }
            _ => {}
        },
        Mode::TenantSelect => match key.code {
            KeyCode::Up => {
                if app.edit_field > 0 {
                    app.edit_field -= 1;
                }
            }
            KeyCode::Down => {
                if app.edit_field + 1 < app.tenant_choices.len() {
                    app.edit_field += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(draft) = app.draft.as_mut() {
                    if let Some(value) = app.tenant_choices.get(app.edit_field) {
                        draft.tenant = value.clone();
                    }
                }
                app.edit_field = 0;
                app.mode = Mode::Edit;
            }
            KeyCode::Esc => {
                app.edit_field = 0;
                app.mode = Mode::Edit;
            }
            _ => {}
        },
        Mode::StatusSelect => match key.code {
            KeyCode::Up => {
                if app.edit_field > 0 {
                    app.edit_field -= 1;
                }
            }
            KeyCode::Down => {
                if app.edit_field + 1 < app.status_choices.len() {
                    app.edit_field += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(draft) = app.draft.as_mut() {
                    if let Some(value) = app.status_choices.get(app.edit_field) {
                        draft.status = value.clone();
                    }
                }
                app.edit_field = 1;
                app.mode = Mode::Edit;
            }
            KeyCode::Esc => {
                app.edit_field = 1;
                app.mode = Mode::Edit;
            }
            _ => {}
        },
        Mode::NoteEdit => match key.code {
            KeyCode::Enter => {
                if let Some(draft) = app.draft.as_mut() {
                    draft.note = app.input.value().to_string();
                }
                app.mode = Mode::Edit;
            }
            KeyCode::Esc => {
                app.mode = Mode::Edit;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::TagsEdit => match key.code {
            KeyCode::Enter => {
                if let Some(draft) = app.draft.as_mut() {
                    draft.tags = parse_tags_input(app.input.value());
                }
                app.mode = Mode::Edit;
            }
            KeyCode::Esc => {
                app.mode = Mode::Edit;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::RequestEdit => match key.code {
            KeyCode::Up => {
                if app.edit_field > 0 {
                    app.edit_field -= 1;
                }
            }
            KeyCode::Down => {
                if app.edit_field < 2 {
                    app.edit_field += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(draft) = app.request_draft.as_ref() {
                    if app.edit_field == 0 {
                        app.edit_field = choice_index(&app.tenant_choices, &draft.tenant);
                        app.mode = Mode::RequestTenantSelect;
                    } else {
                        let value = match app.edit_field {
                            1 => draft.tags.join(", "),
                            2 => draft.note.clone(),
                            _ => String::new(),
                        };
                        let len = value.chars().count();
                        app.input = Input::new(value).with_cursor(len);
                        app.mode = Mode::RequestFieldEdit;
                    }
                }
            }
            KeyCode::Char('s') => {
                match apply_request_draft(app) {
                    Ok(saved) => {
                        if saved {
                            set_status(app, "request updated");
                            app.dirty = true;
                        }
                    }
                    Err(err) => set_status_error(app, format!("request update failed: {err}")),
                }
                app.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                app.request_draft = None;
                app.mode = Mode::Normal;
            }
            _ => {}
        },
        Mode::RequestTenantSelect => match key.code {
            KeyCode::Up => {
                if app.edit_field > 0 {
                    app.edit_field -= 1;
                }
            }
            KeyCode::Down => {
                if app.edit_field + 1 < app.tenant_choices.len() {
                    app.edit_field += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(draft) = app.request_draft.as_mut() {
                    if let Some(value) = app.tenant_choices.get(app.edit_field) {
                        draft.tenant = value.clone();
                    }
                }
                app.edit_field = 0;
                app.mode = Mode::RequestEdit;
            }
            KeyCode::Esc => {
                app.edit_field = 0;
                app.mode = Mode::RequestEdit;
            }
            _ => {}
        },
        Mode::RequestFieldEdit => match key.code {
            KeyCode::Enter => {
                if let Some(draft) = app.request_draft.as_mut() {
                    match app.edit_field {
                        0 => draft.tenant = app.input.value().to_string(),
                        1 => draft.tags = parse_tags_input(app.input.value()),
                        2 => draft.note = app.input.value().to_string(),
                        _ => {}
                    }
                }
                app.mode = Mode::RequestEdit;
            }
            KeyCode::Esc => {
                app.mode = Mode::RequestEdit;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::TenantAdd => match key.code {
            KeyCode::Enter => {
                let name = app.input.value().trim();
                if name.is_empty() {
                    set_status_error(app, "tenant name required");
                    app.mode = Mode::Normal;
                    return Ok(false);
                }
                if let Err(err) = add_tenant(app, name.to_string()) {
                    set_status_error(app, format!("tenant add failed: {err}"));
                } else {
                    set_status(app, "tenant added");
                    app.dirty = true;
                }
                app.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                app.mode = Mode::Normal;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::TenantRename => match key.code {
            KeyCode::Enter => {
                let new_name = app.input.value().trim();
                if new_name.is_empty() {
                    set_status_error(app, "tenant name required");
                    app.mode = Mode::Normal;
                    return Ok(false);
                }
                if let Err(err) = rename_tenant(app, new_name.to_string()) {
                    set_status_error(app, format!("tenant rename failed: {err}"));
                } else {
                    set_status(app, "tenant renamed");
                    app.dirty = true;
                }
                app.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                app.mode = Mode::Normal;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::RequestReject => match key.code {
            KeyCode::Enter => {
                let reason = app.input.value().trim().to_string();
                if let Err(err) = reject_request(app, reason) {
                    set_status_error(app, format!("reject failed: {err}"));
                } else {
                    set_status(app, "request rejected");
                    app.dirty = true;
                }
                app.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                app.mode = Mode::Normal;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::ConfirmExit => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => return Ok(true),
            KeyCode::Char('n') | KeyCode::Char('N') => return Ok(true),
            KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Esc => {
                app.mode = Mode::Normal;
            }
            _ => {}
        },
    }
    Ok(false)
}

fn render_ui(f: &mut ratatui::Frame<'_>, app: &App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    let header = Paragraph::new(render_tabs(app))
        .alignment(Alignment::Left)
        .block(Block::default().borders(Borders::ALL).title("encjson-ctl"));
    f.render_widget(header, chunks[0]);

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);
    render_main_view(f, app, main_chunks.to_vec());

    let (status_text, status_is_error) = current_status(app);
    let status = format!(
        "status: {} | items: {}/{} | filter: {}",
        status_text,
        active_count(app),
        active_total(app),
        app.filter.clone().unwrap_or_else(|| "-".to_string())
    );
    let status_line = Paragraph::new(status).alignment(Alignment::Left);
    let status_style = if status_is_error {
        Style::default()
            .add_modifier(Modifier::REVERSED)
            .fg(Color::Red)
    } else {
        Style::default().add_modifier(Modifier::REVERSED)
    };
    f.render_widget(status_line.style(status_style), chunks[2]);

    let help = match app.mode {
        Mode::Normal | Mode::Filter => {
            "help: Tab switch | Up/Down select | / filter | PgUp/PgDn | q quit | h help"
        }
        Mode::Edit => "help: Enter edit | s save | Esc cancel",
        Mode::TenantSelect => "help: Select tenant | Enter apply | Esc cancel",
        Mode::StatusSelect => "help: Select status | Enter apply | Esc cancel",
        Mode::NoteEdit => "help: Edit note | Enter apply | Esc cancel",
        Mode::TagsEdit => "help: Edit tags | Enter apply | Esc cancel",
        Mode::TenantAdd => "help: New tenant | Enter save | Esc cancel",
        Mode::TenantRename => "help: Rename tenant | Enter save | Esc cancel",
        Mode::RequestEdit => "help: Enter edit | s save | Esc cancel",
        Mode::RequestFieldEdit => "help: Edit field | Enter apply | Esc cancel",
        Mode::RequestTenantSelect => "help: Select tenant | Enter apply | Esc cancel",
        Mode::RequestReject => "help: Reject reason | Enter save | Esc cancel",
        Mode::ConfirmExit => "help: Exit? y/n/c",
    };
    let help_line = Paragraph::new(help).alignment(Alignment::Left);
    f.render_widget(help_line, chunks[3]);

    if app.mode == Mode::Filter {
        let area = centered_rect(60, 3, area);
        f.render_widget(Clear, area);
        render_text_input(f, area, "Filter", "filter", app);
    }

    if app.mode == Mode::ConfirmExit {
        let area = centered_rect_fixed(48, 3, area);
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Save changes?")
            .style(Style::default().fg(Color::Yellow));
        let text = Line::from(vec![
            Span::styled("y", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" save  "),
            Span::styled("n", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" discard  "),
            Span::styled("c", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" cancel"),
        ]);
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Yellow));
        f.render_widget(paragraph, area);
    }

    if matches!(app.mode, Mode::Edit | Mode::NoteEdit | Mode::TagsEdit) {
        render_edit_dialog(f, app);
    }
    if app.mode == Mode::TenantSelect {
        render_select_dialog(f, " Select tenant ", &app.tenant_choices, app.edit_field);
    }
    if app.mode == Mode::StatusSelect {
        render_select_dialog(f, " Select status ", &app.status_choices, app.edit_field);
    }
    if app.mode == Mode::TenantAdd {
        let area = centered_rect(60, 3, area);
        f.render_widget(Clear, area);
        render_text_input(f, area, "New tenant", "name", app);
    }
    if app.mode == Mode::TenantRename {
        let area = centered_rect(60, 3, area);
        f.render_widget(Clear, area);
        render_text_input(f, area, "Rename tenant", "name", app);
    }
    if matches!(app.mode, Mode::RequestEdit | Mode::RequestFieldEdit) {
        render_request_edit_dialog(f, app);
    }
    if app.mode == Mode::RequestTenantSelect {
        render_select_dialog(f, " Select tenant ", &app.tenant_choices, app.edit_field);
    }
    if app.mode == Mode::RequestReject {
        let area = centered_rect(60, 3, area);
        f.render_widget(Clear, area);
        render_text_input(f, area, "Reject reason (optional)", "reason", app);
    }
    if app.help_active {
        render_help(f, area, app);
    }
}

fn render_tabs(app: &App) -> Line<'static> {
    let mut spans = Vec::new();
    spans.push(tab_span("Keys", app.view == View::Keys, false));
    spans.push(Span::raw("│"));
    spans.push(tab_span("Tenants", app.view == View::Tenants, false));
    spans.push(Span::raw("│"));
    spans.push(tab_span("Tags", app.view == View::Tags, false));
    let pending = app.requests.iter().any(|r| r.status == "pending");
    spans.push(Span::raw("│"));
    spans.push(tab_span("Requests", app.view == View::Requests, pending));
    Line::from(spans)
}

fn render_text_input(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    title: &str,
    label: &str,
    app: &App,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().fg(Color::Yellow))
        .padding(Padding::horizontal(1));
    let line = Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Yellow)),
        Span::styled(
            format!("{label}: "),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            app.input.value(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ]);
    let input = Paragraph::new(line)
        .block(block)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(input, area);
    let label_len = label.chars().count() as u16;
    let cursor_x = area.x + 1 + 2 + label_len + 3 + app.input.visual_cursor() as u16;
    let cursor_y = area.y + 1;
    f.set_cursor_position((cursor_x, cursor_y));
}

fn current_status(app: &App) -> (String, bool) {
    if let Some(temp) = app.status_temp.as_ref() {
        if Instant::now() < temp.expires_at {
            return (temp.message.clone(), temp.is_error);
        }
    }
    (app.status_base.clone(), false)
}

fn set_status(app: &mut App, message: impl Into<String>) {
    app.status_base = message.into();
    app.status_temp = None;
}

fn set_status_error(app: &mut App, message: impl Into<String>) {
    app.status_temp = Some(TempStatus {
        message: message.into(),
        expires_at: Instant::now() + Duration::from_secs(5),
        is_error: true,
    });
}

fn render_help(f: &mut ratatui::Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let popup = centered_rect_percent(70, 60, area);
    f.render_widget(Clear, popup);
    let block = Block::default().borders(Borders::ALL).title("Help");
    f.render_widget(block, popup);

    let lines = help_lines(app.view);
    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .block(Block::default())
        .wrap(Wrap { trim: true });
    let inner = popup.inner(Margin::new(1, 1));
    f.render_widget(paragraph, inner);
}

fn help_lines(view: View) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Tab/Shift+Tab switch tabs"),
        Line::from("Up/Down select"),
        Line::from("/ filter"),
        Line::from("PgUp/PgDn page"),
        Line::from("q quit"),
        Line::from("h close help"),
        Line::from(""),
    ];

    match view {
        View::Keys => {
            lines.push(Line::from("Enter edit key"));
            lines.push(Line::from("s save (in editor)"));
        }
        View::Tenants => {
            lines.push(Line::from("n new tenant"));
            lines.push(Line::from("e rename tenant"));
            lines.push(Line::from("d delete tenant"));
        }
        View::Tags => {
            lines.push(Line::from("no actions yet"));
        }
        View::Requests => {
            lines.push(Line::from("e edit request"));
            lines.push(Line::from("a approve request"));
            lines.push(Line::from("x reject request"));
        }
    }

    lines
}

fn tab_span(label: &str, active: bool, warn: bool) -> Span<'static> {
    let style = if active {
        Style::default().add_modifier(Modifier::BOLD)
    } else if warn {
        Style::default().fg(Color::Red)
    } else {
        Style::default()
    };
    Span::styled(format!(" {label} "), style)
}

fn render_main_view(
    f: &mut ratatui::Frame<'_>,
    app: &App,
    chunks: Vec<ratatui::layout::Rect>,
) {
    match app.view {
        View::Keys => render_keys_view(f, app, chunks),
        View::Tenants => {
            let indices = filtered_simple_indices(&app.tenants, app.filter.as_ref());
            render_simple_list(
                f,
                app,
                "Tenants",
                "Details",
                &app.tenants,
                &indices,
                app.selected_tenants,
                chunks,
            );
        }
        View::Tags => {
            let indices = filtered_simple_indices(&app.tags, app.filter.as_ref());
            render_simple_list(
                f,
                app,
                "Tags",
                "Details",
                &app.tags,
                &indices,
                app.selected_tags,
                chunks,
            );
        }
        View::Requests => render_requests_view(f, app, chunks),
    }
}

fn render_keys_view(
    f: &mut ratatui::Frame<'_>,
    app: &App,
    chunks: Vec<ratatui::layout::Rect>,
) {
    let indices = filtered_keys_indices(app);
    let list_items: Vec<ListItem> = if indices.is_empty() {
        vec![ListItem::new(Line::from(" no items"))]
    } else {
        indices
            .iter()
            .map(|idx| ListItem::new(Line::from(format_key_label(&app.items[*idx]))))
            .collect()
    };
    let mut state = ListState::default();
    if !indices.is_empty() {
        let selected = app.selected_keys.min(indices.len().saturating_sub(1));
        let list_height = chunks[0].height.saturating_sub(2) as usize;
        let offset = list_offset(selected, list_height);
        state = state.with_selected(Some(selected)).with_offset(offset);
    }
    let list_block = Block::default()
        .borders(Borders::ALL)
        .title("Keys");
    let list = List::new(list_items)
        .block(list_block)
        .highlight_symbol(">> ")
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, chunks[0], &mut state);

    let details = Paragraph::new(build_details(app))
        .block(Block::default().borders(Borders::ALL).title("Details"));
    f.render_widget(details, chunks[1]);
}

fn render_requests_view(
    f: &mut ratatui::Frame<'_>,
    app: &App,
    chunks: Vec<ratatui::layout::Rect>,
) {
    let indices = filtered_requests_indices(app);
    let list_items: Vec<ListItem> = if indices.is_empty() {
        vec![ListItem::new(Line::from(" no requests"))]
    } else {
        indices
            .iter()
            .map(|idx| ListItem::new(Line::from(format_request_label(&app.requests[*idx]))))
            .collect()
    };
    let mut state = ListState::default();
    if !indices.is_empty() {
        let selected = app.selected_requests.min(indices.len().saturating_sub(1));
        let list_height = chunks[0].height.saturating_sub(2) as usize;
        let offset = list_offset(selected, list_height);
        state = state.with_selected(Some(selected)).with_offset(offset);
    }
    let list_block = Block::default()
        .borders(Borders::ALL)
        .title("Requests");
    let list = List::new(list_items)
        .block(list_block)
        .highlight_symbol(">> ")
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, chunks[0], &mut state);

    let details = Paragraph::new(build_details(app))
        .block(Block::default().borders(Borders::ALL).title("Details"));
    f.render_widget(details, chunks[1]);
}

fn render_simple_list(
    f: &mut ratatui::Frame<'_>,
    app: &App,
    title: &str,
    details_title: &str,
    items: &[String],
    indices: &[usize],
    selected: usize,
    chunks: Vec<ratatui::layout::Rect>,
) {
    let list_items: Vec<ListItem> = if indices.is_empty() {
        vec![ListItem::new(Line::from(" no items"))]
    } else {
        indices
            .iter()
            .map(|idx| ListItem::new(Line::from(format!(" {}", items[*idx]))))
            .collect()
    };
    let mut state = ListState::default();
    if !indices.is_empty() {
        let selected = selected.min(indices.len().saturating_sub(1));
        let list_height = chunks[0].height.saturating_sub(2) as usize;
        let offset = list_offset(selected, list_height);
        state = state.with_selected(Some(selected)).with_offset(offset);
    }
    let list_block = Block::default()
        .borders(Borders::ALL)
        .title(title);
    let list = List::new(list_items)
        .block(list_block)
        .highlight_symbol(">> ")
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, chunks[0], &mut state);

    let details = Paragraph::new(build_details(app))
        .block(Block::default().borders(Borders::ALL).title(details_title));
    f.render_widget(details, chunks[1]);
}

fn filtered_indices(app: &App) -> Vec<usize> {
    let Some(filter) = app.filter.as_ref() else {
        return (0..app.items.len()).collect();
    };
    let needle = filter.to_lowercase();
    if needle.is_empty() {
        return (0..app.items.len()).collect();
    }
    app.items
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            let hay = format!(
                "{} {} {} {}",
                item.public_hex, item.tenant, item.status, item.note
            )
            .to_lowercase();
            if hay.contains(&needle) {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

fn filtered_keys_indices(app: &App) -> Vec<usize> {
    filtered_indices(app)
}

fn filtered_requests_indices(app: &App) -> Vec<usize> {
    let Some(filter) = app.filter.as_ref() else {
        return (0..app.requests.len()).collect();
    };
    let needle = filter.to_lowercase();
    if needle.is_empty() {
        return (0..app.requests.len()).collect();
    }
    app.requests
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            let hay = format!(
                "{} {} {} {}",
                item.public_hex, item.tenant, item.status, item.note
            )
            .to_lowercase();
            if hay.contains(&needle) {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

fn filtered_simple_indices(items: &[String], filter: Option<&String>) -> Vec<usize> {
    let Some(filter) = filter else {
        return (0..items.len()).collect();
    };
    let needle = filter.to_lowercase();
    if needle.is_empty() {
        return (0..items.len()).collect();
    }
    items
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| {
            if item.to_lowercase().contains(&needle) {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

fn move_selection(app: &mut App, delta: isize) {
    match app.view {
        View::Keys => {
            let indices = filtered_keys_indices(app);
            if indices.is_empty() {
                app.selected_keys = 0;
                return;
            }
            let mut next = app.selected_keys as isize + delta;
            if next < 0 {
                next = 0;
            }
            if next as usize >= indices.len() {
                next = (indices.len() - 1) as isize;
            }
            app.selected_keys = next as usize;
        }
        View::Tenants => {
            let indices = filtered_simple_indices(&app.tenants, app.filter.as_ref());
            adjust_selected(&mut app.selected_tenants, indices.len(), delta);
        }
        View::Tags => {
            let indices = filtered_simple_indices(&app.tags, app.filter.as_ref());
            adjust_selected(&mut app.selected_tags, indices.len(), delta);
        }
        View::Requests => {
            let indices = filtered_requests_indices(app);
            if indices.is_empty() {
                app.selected_requests = 0;
                return;
            }
            let mut next = app.selected_requests as isize + delta;
            if next < 0 {
                next = 0;
            }
            if next as usize >= indices.len() {
                next = (indices.len() - 1) as isize;
            }
            app.selected_requests = next as usize;
        }
    }
}

fn adjust_selected(selected: &mut usize, len: usize, delta: isize) {
    if len == 0 {
        *selected = 0;
        return;
    }
    let mut next = *selected as isize + delta;
    if next < 0 {
        next = 0;
    }
    if next as usize >= len {
        next = (len - 1) as isize;
    }
    *selected = next as usize;
}

fn reset_selection(app: &mut App) {
    match app.view {
        View::Keys => app.selected_keys = 0,
        View::Tenants => app.selected_tenants = 0,
        View::Tags => app.selected_tags = 0,
        View::Requests => app.selected_requests = 0,
    }
}

fn refresh_remote_data(app: &mut App) {
    let Some(remote) = app.remote.as_ref() else {
        return;
    };

    let keys = match fetch_remote_keys(&remote.base_url, &remote.access_token) {
        Ok(items) => items,
        Err(err) => {
            set_status_error(app, format!("refresh keys failed: {err}"));
            return;
        }
    };
    let tenants = match fetch_remote_tenants(&remote.base_url, &remote.access_token) {
        Ok(items) => items,
        Err(err) => {
            set_status_error(app, format!("refresh tenants failed: {err}"));
            return;
        }
    };
    let statuses = match fetch_remote_statuses(&remote.base_url, &remote.access_token) {
        Ok(items) => items,
        Err(err) => {
            set_status_error(app, format!("refresh statuses failed: {err}"));
            return;
        }
    };
    let requests = match fetch_remote_requests(&remote.base_url, &remote.access_token) {
        Ok(items) => items,
        Err(err) => {
            set_status_error(app, format!("refresh requests failed: {err}"));
            return;
        }
    };

    app.items = keys;
    app.tenants = tenants.clone();
    app.tenant_choices = tenants;
    app.status_choices = statuses;
    app.requests = requests;
    reset_selection(app);
}

fn list_offset(selected: usize, height: usize) -> usize {
    if height == 0 {
        return 0;
    }
    if selected + 1 > height {
        selected + 1 - height
    } else {
        0
    }
}

fn format_key_label(item: &KeyItem) -> String {
    let tenant = truncate(&item.tenant, 10);
    let status = truncate(&item.status, 10);
    let note = truncate(&item.note, 18);
    let public_hex = short_hex(&item.public_hex);
    format!("{public_hex} {tenant:<10} {status:<10} {note}")
}

fn short_hex(value: &str) -> String {
    if value.len() <= 12 {
        return value.to_string();
    }
    let head_len = value.len() / 2;
    format!("{}...", &value[..head_len])
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut out = value.chars().take(max.saturating_sub(3)).collect::<String>();
    out.push_str("...");
    out
}

fn format_request_label(item: &RequestItem) -> String {
    let public_hex = short_hex(&item.public_hex);
    let tenant = truncate(&item.tenant, 10);
    let status = truncate(&item.status, 10);
    let note = truncate(&item.note, 18);
    format!("{public_hex} {tenant:<10} {status:<10} {note}")
}

fn build_details(app: &App) -> Vec<Line<'static>> {
    match app.view {
        View::Keys => {
            let indices = filtered_keys_indices(app);
            if indices.is_empty() {
                return vec![Line::from("no selection")];
            }
            let selected = app.selected_keys.min(indices.len().saturating_sub(1));
            let item = &app.items[indices[selected]];
            vec![
                detail_line("public_hex", &item.public_hex),
                detail_line("tenant", &item.tenant),
                detail_line("status", &item.status),
                detail_line(
                    "tags",
                    if item.tags.is_empty() {
                        "-".to_string()
                    } else {
                        item.tags.join(", ")
                    },
                ),
                detail_line(
                    "note",
                    if item.note.trim().is_empty() { "-" } else { &item.note },
                ),
            ]
        }
        View::Tenants => {
            let indices = filtered_simple_indices(&app.tenants, app.filter.as_ref());
            if indices.is_empty() {
                return vec![Line::from("no tenants")];
            }
            let selected = app.selected_tenants.min(indices.len().saturating_sub(1));
            let name = &app.tenants[indices[selected]];
            vec![detail_line("tenant", name)]
        }
        View::Tags => {
            let indices = filtered_simple_indices(&app.tags, app.filter.as_ref());
            if indices.is_empty() {
                return vec![Line::from("no tags")];
            }
            let selected = app.selected_tags.min(indices.len().saturating_sub(1));
            let name = &app.tags[indices[selected]];
            vec![detail_line("tag", name)]
        }
        View::Requests => {
            let indices = filtered_requests_indices(app);
            if indices.is_empty() {
                return vec![Line::from("no requests")];
            }
            let selected = app.selected_requests.min(indices.len().saturating_sub(1));
            let item = &app.requests[indices[selected]];
            vec![
                detail_line("id", item.id.to_string()),
                detail_line("public_hex", &item.public_hex),
                detail_line("tenant", &item.tenant),
                detail_line("status", &item.status),
                detail_line(
                    "tags",
                    if item.tags.is_empty() {
                        "-".to_string()
                    } else {
                        item.tags.join(", ")
                    },
                ),
                detail_line(
                    "note",
                    if item.note.trim().is_empty() { "-" } else { &item.note },
                ),
                detail_line(
                    "requested_by",
                    item.requested_by.as_deref().unwrap_or("-"),
                ),
                detail_line("requested_at", &item.requested_at),
            ]
        }
    }
}

fn detail_line(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.into()),
    ])
}

fn selected_item(app: &App) -> Option<&KeyItem> {
    let indices = filtered_keys_indices(app);
    if indices.is_empty() {
        return None;
    }
    let selected = app.selected_keys.min(indices.len().saturating_sub(1));
    let idx = indices[selected];
    app.items.get(idx)
}

fn selected_tenant_name(app: &App) -> Option<String> {
    let indices = filtered_simple_indices(&app.tenants, app.filter.as_ref());
    if indices.is_empty() {
        return None;
    }
    let selected = app.selected_tenants.min(indices.len().saturating_sub(1));
    app.tenants.get(indices[selected]).cloned()
}

fn selected_request(app: &App) -> Option<RequestItem> {
    let indices = filtered_requests_indices(app);
    if indices.is_empty() {
        return None;
    }
    let selected = app.selected_requests.min(indices.len().saturating_sub(1));
    app.requests.get(indices[selected]).cloned()
}

fn parse_tags_input(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
        .collect()
}

fn add_tenant(app: &mut App, name: String) -> Result<(), Box<dyn Error>> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("tenant name required".into());
    }
    if let Some(remote) = &app.remote {
        remote_create_tenant(remote, &name)?;
    }
    if !app.tenants.contains(&name) {
        app.tenants.push(name.clone());
        app.tenants.sort();
    }
    if !app.tenant_choices.contains(&name) {
        app.tenant_choices.push(name);
        app.tenant_choices.sort();
    }
    persist_ctl_data(app)?;
    Ok(())
}

fn rename_tenant(app: &mut App, new_name: String) -> Result<(), Box<dyn Error>> {
    let new_name = new_name.trim().to_string();
    if new_name.is_empty() {
        return Err("tenant name required".into());
    }
    let Some(old_name) = selected_tenant_name(app) else {
        return Err("no tenant selected".into());
    };
    if old_name == new_name {
        return Ok(());
    }
    if let Some(remote) = &app.remote {
        remote_rename_tenant(remote, &old_name, &new_name)?;
    }
    for tenant in &mut app.tenants {
        if tenant == &old_name {
            *tenant = new_name.clone();
        }
    }
    for choice in &mut app.tenant_choices {
        if choice == &old_name {
            *choice = new_name.clone();
        }
    }
    for item in &mut app.items {
        if item.tenant == old_name {
            item.tenant = new_name.clone();
        }
    }
    app.tenants.sort();
    app.tenant_choices.sort();
    persist_ctl_data(app)?;
    Ok(())
}

fn delete_tenant(app: &mut App) -> Result<(), Box<dyn Error>> {
    let Some(name) = selected_tenant_name(app) else {
        return Err("no tenant selected".into());
    };
    if let Some(remote) = &app.remote {
        remote_delete_tenant(remote, &name)?;
    }
    app.tenants.retain(|tenant| tenant != &name);
    app.tenant_choices.retain(|tenant| tenant != &name);
    if app.selected_tenants > 0 && app.selected_tenants >= app.tenants.len() {
        app.selected_tenants = app.tenants.len().saturating_sub(1);
    }
    persist_ctl_data(app)?;
    Ok(())
}

fn approve_request(app: &mut App) -> Result<(), Box<dyn Error>> {
    let Some(request) = selected_request(app) else {
        return Err("no request selected".into());
    };
    if let Some(remote) = &app.remote {
        remote_approve_request(
            remote,
            request.id,
            &request.tenant,
            &request.note,
            &request.tags,
        )?;
        app.requests = fetch_remote_requests(&remote.base_url, &remote.access_token)?;
        app.items = fetch_remote_keys(&remote.base_url, &remote.access_token)?;
    } else {
        app.requests.retain(|item| item.id != request.id);
        persist_ctl_data(app)?;
    }
    Ok(())
}

fn reject_request(app: &mut App, reason: String) -> Result<(), Box<dyn Error>> {
    let Some(request) = selected_request(app) else {
        return Err("no request selected".into());
    };
    if let Some(remote) = &app.remote {
        remote_reject_request(remote, request.id, &reason)?;
        app.requests = fetch_remote_requests(&remote.base_url, &remote.access_token)?;
        app.items = fetch_remote_keys(&remote.base_url, &remote.access_token)?;
    } else {
        app.requests.retain(|item| item.id != request.id);
        persist_ctl_data(app)?;
    }
    Ok(())
}

fn apply_request_draft(app: &mut App) -> Result<bool, Box<dyn Error>> {
    let Some(draft) = app.request_draft.as_ref() else {
        return Ok(false);
    };
    if let Some(remote) = &app.remote {
        remote_update_request(remote, draft)?;
        app.requests = fetch_remote_requests(&remote.base_url, &remote.access_token)?;
        app.items = fetch_remote_keys(&remote.base_url, &remote.access_token)?;
    } else if let Some(item) = app
        .requests
        .iter_mut()
        .find(|item| item.id == draft.id)
    {
        item.tenant = draft.tenant.clone();
        item.note = draft.note.clone();
        item.tags = draft.tags.clone();
        persist_ctl_data(app)?;
    }
    Ok(true)
}

fn apply_draft(app: &mut App) -> Result<bool, Box<dyn Error>> {
    let indices = filtered_keys_indices(app);
    if indices.is_empty() {
        return Ok(false);
    }
    let selected = app.selected_keys.min(indices.len().saturating_sub(1));
    let idx = indices[selected];
    if let Some(draft) = app.draft.take() {
        if let Some(remote) = &app.remote {
            let updated = update_remote_key(remote, &app.items[idx].public_hex, &draft)?;
            update_item(app, updated);
        } else if let Some(item) = app.items.get_mut(idx) {
            item.tenant = draft.tenant;
            item.status = draft.status;
            item.note = draft.note;
            item.tags = draft.tags;
        }
        persist_ctl_data(app)?;
        return Ok(true);
    }
    Ok(false)
}

fn update_item(app: &mut App, updated: KeyItem) {
    if let Some(pos) = app.items.iter().position(|item| item.public_hex == updated.public_hex) {
        app.items[pos] = updated;
    }
}

fn active_count(app: &App) -> usize {
    match app.view {
        View::Keys => filtered_keys_indices(app).len(),
        View::Tenants => filtered_simple_indices(&app.tenants, app.filter.as_ref()).len(),
        View::Tags => filtered_simple_indices(&app.tags, app.filter.as_ref()).len(),
        View::Requests => filtered_requests_indices(app).len(),
    }
}

fn active_total(app: &App) -> usize {
    match app.view {
        View::Keys => app.items.len(),
        View::Tenants => app.tenants.len(),
        View::Tags => app.tags.len(),
        View::Requests => app.requests.len(),
    }
}

fn remote_url(base_url: &str, path: &str) -> String {
    format!("{}/{}", base_url.trim_end_matches('/'), path.trim_start_matches('/'))
}

fn fetch_remote_keys(base_url: &str, access_token: &str) -> Result<Vec<KeyItem>, Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(base_url, "/v1/keys");
    let response = client.get(url).bearer_auth(access_token).send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        return Err(format!("vault request failed ({}): {}", status, body.trim()).into());
    }
    let items: Vec<KeyItem> = serde_json::from_str(&body)?;
    Ok(items)
}

fn fetch_remote_key(remote: &RemoteConfig, public_hex: &str) -> Result<KeyItem, Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, &format!("/v1/keys/{}", public_hex));
    let response = client
        .get(url)
        .bearer_auth(&remote.access_token)
        .send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        return Err(format!("vault request failed ({}): {}", status, body.trim()).into());
    }
    let item: KeyItem = serde_json::from_str(&body)?;
    Ok(item)
}

fn fetch_remote_tenants(
    base_url: &str,
    access_token: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(base_url, "/v1/tenants");
    let response = client.get(url).bearer_auth(access_token).send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        return Err(format!("vault request failed ({}): {}", status, body.trim()).into());
    }
    let tenants: Vec<Value> = serde_json::from_str(&body)?;
    let names = tenants
        .into_iter()
        .filter_map(|value| value.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();
    Ok(names)
}

fn fetch_remote_statuses(
    base_url: &str,
    access_token: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(base_url, "/v1/statuses");
    let response = client.get(url).bearer_auth(access_token).send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        return Err(format!("vault request failed ({}): {}", status, body.trim()).into());
    }
    let statuses: Vec<String> = serde_json::from_str(&body)?;
    Ok(statuses)
}

fn fetch_remote_requests(
    base_url: &str,
    access_token: &str,
) -> Result<Vec<RequestItem>, Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(base_url, "/v1/requests?status=pending");
    let response = client.get(url).bearer_auth(access_token).send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        return Err(format!("vault request failed ({}): {}", status, body.trim()).into());
    }
    let items: Vec<RequestItem> = serde_json::from_str(&body)?;
    Ok(items)
}

fn remote_create_tenant(remote: &RemoteConfig, name: &str) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, "/v1/tenants");
    let body = serde_json::json!({ "name": name });
    let response = client
        .post(url)
        .bearer_auth(&remote.access_token)
        .json(&body)
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        return Err(format!("tenant create failed ({}): {}", status, text.trim()).into());
    }
    Ok(())
}

fn remote_rename_tenant(
    remote: &RemoteConfig,
    old_name: &str,
    new_name: &str,
) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, &format!("/v1/tenants/{}", old_name));
    let body = serde_json::json!({ "name": new_name });
    let response = client
        .patch(url)
        .bearer_auth(&remote.access_token)
        .json(&body)
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        return Err(format!("tenant rename failed ({}): {}", status, text.trim()).into());
    }
    Ok(())
}

fn remote_delete_tenant(remote: &RemoteConfig, name: &str) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, &format!("/v1/tenants/{}", name));
    let response = client
        .delete(url)
        .bearer_auth(&remote.access_token)
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        return Err(format!("tenant delete failed ({}): {}", status, text.trim()).into());
    }
    Ok(())
}

fn remote_approve_request(
    remote: &RemoteConfig,
    id: i64,
    tenant: &str,
    note: &str,
    tags: &[String],
) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, &format!("/v1/requests/{}/approve", id));
    let body = serde_json::json!({
        "tenant": tenant,
        "status": "active",
        "note": note,
        "tags": tags,
    });
    let response = client
        .post(url)
        .bearer_auth(&remote.access_token)
        .json(&body)
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        return Err(format!("approve failed ({}): {}", status, text.trim()).into());
    }
    Ok(())
}

fn remote_reject_request(
    remote: &RemoteConfig,
    id: i64,
    reason: &str,
) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, &format!("/v1/requests/{}/reject", id));
    let body = serde_json::json!({ "reason": reason });
    let response = client
        .post(url)
        .bearer_auth(&remote.access_token)
        .json(&body)
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        return Err(format!("reject failed ({}): {}", status, text.trim()).into());
    }
    Ok(())
}

fn remote_update_request(
    remote: &RemoteConfig,
    draft: &RequestDraft,
) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, &format!("/v1/requests/{}", draft.id));
    let body = serde_json::json!({
        "tenant": draft.tenant,
        "note": draft.note,
        "tags": draft.tags,
    });
    let response = client
        .patch(url)
        .bearer_auth(&remote.access_token)
        .json(&body)
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        return Err(format!("request update failed ({}): {}", status, text.trim()).into());
    }
    Ok(())
}

fn update_remote_key(
    remote: &RemoteConfig,
    public_hex: &str,
    draft: &KeyDraft,
) -> Result<KeyItem, Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    let url = remote_url(&remote.base_url, &format!("/v1/keys/{}", public_hex));
    let body = serde_json::json!({
        "tenant": draft.tenant,
        "status": draft.status,
        "note": draft.note,
        "tags": draft.tags,
    });
    let response = client
        .patch(url)
        .bearer_auth(&remote.access_token)
        .json(&body)
        .send()?;
    let status = response.status();
    let text = response.text()?;
    if !status.is_success() {
        return Err(format!("vault update failed ({}): {}", status, text.trim()).into());
    }
    let updated: KeyItem = serde_json::from_str(&text)?;
    Ok(updated)
}

fn persist_ctl_data(app: &App) -> Result<(), Box<dyn Error>> {
    let Some(path) = app.data_path.as_ref() else {
        return Ok(());
    };
    let tenants = if app.save_tenants {
        Some(app.tenant_choices.clone())
    } else {
        None
    };
    let statuses = if app.save_statuses {
        Some(app.status_choices.clone())
    } else {
        None
    };
    let data = CtlData {
        items: app.items.clone(),
        tenants,
        statuses,
        tags: if app.tags.is_empty() { None } else { Some(app.tags.clone()) },
        requests: if app.requests.is_empty() {
            None
        } else {
            Some(app.requests.clone())
        },
    };
    let contents = serde_json::to_string_pretty(&data)?;
    fs::write(path, format!("{contents}\n"))?;
    Ok(())
}

fn render_edit_dialog(f: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(60, 10, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Edit key")
        .style(Style::default().fg(Color::Yellow));
    let mut lines = Vec::new();
    let mut cursor = None;
    if let Some(item) = selected_item(app) {
        lines.push(form_line_readonly("public_hex", &item.public_hex));
        lines.push(Line::from(""));
    }
    if let Some(draft) = app.draft.as_ref() {
        let tags_value = if matches!(app.mode, Mode::TagsEdit) && app.edit_field == 2 {
            app.input.value().to_string()
        } else if draft.tags.is_empty() {
            "-".to_string()
        } else {
            draft.tags.join(", ")
        };
        let note_value = if matches!(app.mode, Mode::NoteEdit) && app.edit_field == 3 {
            app.input.value().to_string()
        } else if draft.note.trim().is_empty() {
            "-".to_string()
        } else {
            draft.note.clone()
        };
        lines.push(form_line("tenant", &draft.tenant, app.edit_field == 0));
        lines.push(form_line("status", &draft.status, app.edit_field == 1));
        lines.push(form_line("tags", &tags_value, app.edit_field == 2));
        lines.push(form_line("note", &note_value, app.edit_field == 3));
        lines.push(Line::from(""));
        lines.push(Line::from("Enter edit | s save | Esc cancel"));
        if matches!(app.mode, Mode::TagsEdit | Mode::NoteEdit) {
            let (label, line_index) = if app.edit_field == 2 {
                ("tags", 2 + 2)
            } else {
                ("note", 2 + 3)
            };
            let label_len = label.chars().count() as u16;
            let cursor_x = area.x + 1 + 2 + label_len + 2 + app.input.visual_cursor() as u16;
            let cursor_y = area.y + 1 + line_index as u16;
            cursor = Some((cursor_x, cursor_y));
        }
    }
    let paragraph = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Left)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(paragraph, area);
    if let Some((x, y)) = cursor {
        f.set_cursor_position((x, y));
    }
}

fn render_request_edit_dialog(f: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(60, 9, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Edit request")
        .style(Style::default().fg(Color::Yellow));
    let mut lines = Vec::new();
    let mut cursor = None;
    if let Some(draft) = app.request_draft.as_ref() {
        lines.push(form_line_readonly("request_id", draft.id.to_string()));
        lines.push(Line::from(""));
        let tenant_value = draft.tenant.clone();
        let tags_value = if matches!(app.mode, Mode::RequestFieldEdit) && app.edit_field == 1 {
            app.input.value().to_string()
        } else if draft.tags.is_empty() {
            "-".to_string()
        } else {
            draft.tags.join(", ")
        };
        let note_value = if matches!(app.mode, Mode::RequestFieldEdit) && app.edit_field == 2 {
            app.input.value().to_string()
        } else if draft.note.trim().is_empty() {
            "-".to_string()
        } else {
            draft.note.clone()
        };
        lines.push(form_line("tenant", &tenant_value, app.edit_field == 0));
        lines.push(form_line("tags", &tags_value, app.edit_field == 1));
        lines.push(form_line("note", &note_value, app.edit_field == 2));
        if !app.tenant_choices.contains(&draft.tenant) {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("(neexistující tenant: \"{}\")", draft.tenant),
                    Style::default().fg(Color::Red),
                ),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("Enter edit | s save | Esc cancel"));
        if matches!(app.mode, Mode::RequestFieldEdit) {
            let (label, line_index) = match app.edit_field {
                0 => ("tenant", 2 + 0),
                1 => ("tags", 2 + 1),
                _ => ("note", 2 + 2),
            };
            let label_len = label.chars().count() as u16;
            let cursor_x = area.x + 1 + 2 + label_len + 2 + app.input.visual_cursor() as u16;
            let cursor_y = area.y + 1 + line_index as u16;
            cursor = Some((cursor_x, cursor_y));
        }
    }
    let paragraph = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Left)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(paragraph, area);
    if let Some((x, y)) = cursor {
        f.set_cursor_position((x, y));
    }
}

fn form_line(label: &str, value: &str, active: bool) -> Line<'static> {
    let prefix = if active { "> " } else { "  " };
    let style = if active {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    Line::from(vec![
        Span::styled(prefix, Style::default().fg(Color::Yellow)),
        Span::styled(format!("{label}: "), style),
        Span::styled(value.to_string(), style),
    ])
}

fn form_line_readonly(label: &str, value: impl Into<String>) -> Line<'static> {
    let value = value.into();
    Line::from(vec![
        Span::styled("  ", Style::default().fg(Color::Yellow)),
        Span::styled(format!("{label}: "), Style::default().fg(Color::DarkGray)),
        Span::styled(value, Style::default().fg(Color::DarkGray)),
    ])
}

fn render_select_dialog(
    f: &mut ratatui::Frame<'_>,
    title: &str,
    items: &[String],
    selected: usize,
) {
    let area = centered_rect(40, 8, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().fg(Color::Yellow))
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    let list_items: Vec<ListItem> = items
        .iter()
        .map(|item| ListItem::new(Line::from(item.clone())))
        .collect();
    let mut state = ListState::default();
    if !items.is_empty() {
        state = state.with_selected(Some(selected.min(items.len() - 1)));
    }
    let list = List::new(list_items)
        .block(block)
        .highlight_symbol(" > ")
        .style(Style::default().fg(Color::Yellow))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut state);
    let cursor_x = inner.x;
    let cursor_y = inner.y + selected.min(items.len().saturating_sub(1)) as u16;
    f.set_cursor_position((cursor_x, cursor_y));
}

fn sample_items() -> Vec<KeyItem> {
    vec![
        KeyItem {
            public_hex: "0333595220a5f1321385b8eac8c700b5ed35ca9efe73fddf3ea1488a0f19b773".to_string(),
            tenant: "cetin".to_string(),
            status: "active".to_string(),
            note: "db access".to_string(),
            tags: vec!["db".to_string()],
        },
        KeyItem {
            public_hex: "f5f657822c9a9dab5b214fa08c7ee2fe0d34f4e581d98f8b8a409b3ee06518a5".to_string(),
            tenant: "o2".to_string(),
            status: "active".to_string(),
            note: "app deploy".to_string(),
            tags: vec!["deploy".to_string()],
        },
        KeyItem {
            public_hex: "6081b6dd62270efe1dcc305d1bb7dd4993f5fbd8cce354067a4b9c3a96774d43".to_string(),
            tenant: "cez".to_string(),
            status: "deprecated".to_string(),
            note: "legacy".to_string(),
            tags: Vec::new(),
        },
    ]
}

fn centered_rect(percent_x: u16, height: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1]);
    horizontal[1]
}

fn centered_rect_percent(
    percent_x: u16,
    percent_y: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1]);
    horizontal[1]
}

fn centered_rect_fixed(width: u16, height: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(popup_layout[1]);
    horizontal[1]
}
