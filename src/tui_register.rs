use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::Terminal;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

use crate::{load_private_key, send_register_request, RegisterPayload};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Mode {
    List,
    Edit,
    TenantSelect,
    TenantAdd,
    TagsEdit,
    NoteEdit,
}

#[derive(Debug, Clone)]
struct Draft {
    tenant: String,
    tags: Vec<String>,
    note: String,
}

struct App {
    keys: Vec<String>,
    selected: usize,
    mode: Mode,
    edit_field: usize,
    input: Input,
    tenants: Vec<String>,
    draft: Option<Draft>,
    status: String,
    status_error: bool,
    status_until: Option<Instant>,
}

impl App {
    fn new(keys: Vec<String>, tenants: Vec<String>) -> Self {
        Self {
            keys,
            selected: 0,
            mode: Mode::List,
            edit_field: 0,
            input: Input::default(),
            tenants,
            draft: None,
            status: "ready".to_string(),
            status_error: false,
            status_until: None,
        }
    }
}

pub fn run_register_tui(
    keys: Vec<String>,
    tenants: Vec<String>,
    vault_url: String,
    token: String,
    keydir: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(keys, tenants);
    let res = run_app(&mut terminal, &mut app, &vault_url, &token, keydir.as_deref());

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    vault_url: &str,
    token: &str,
    keydir: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error>> {
    let tick_rate = Duration::from_millis(200);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| render(f, app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if handle_key(app, key, vault_url, token, keydir)? {
                        break;
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
            if let Some(until) = app.status_until {
                if Instant::now() > until {
                    app.status = "ready".to_string();
                    app.status_error = false;
                    app.status_until = None;
                }
            }
        }
    }

    Ok(())
}

fn handle_key(
    app: &mut App,
    key: KeyEvent,
    vault_url: &str,
    token: &str,
    keydir: Option<&std::path::Path>,
) -> Result<bool, Box<dyn Error>> {
    match app.mode {
        Mode::List => match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Up => {
                if app.selected > 0 {
                    app.selected -= 1;
                }
            }
            KeyCode::Down => {
                if app.selected + 1 < app.keys.len() {
                    app.selected += 1;
                }
            }
            KeyCode::Enter => {
                if app.keys.is_empty() {
                    return Ok(false);
                }
                app.draft = Some(Draft {
                    tenant: String::new(),
                    tags: Vec::new(),
                    note: String::new(),
                });
                app.edit_field = 0;
                app.mode = Mode::Edit;
            }
            _ => {}
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
                    if app.tenants.is_empty() {
                        set_status(app, "no tenants available", true);
                    } else {
                        app.edit_field = 0;
                        app.mode = Mode::TenantSelect;
                    }
                }
                1 => {
                    if let Some(draft) = app.draft.as_ref() {
                        let tags = draft.tags.join(", ");
                        let len = tags.chars().count();
                        app.input = Input::new(tags).with_cursor(len);
                    } else {
                        app.input = Input::default();
                    }
                    app.mode = Mode::TagsEdit;
                }
                2 => {
                    if let Some(draft) = app.draft.as_ref() {
                        let len = draft.note.chars().count();
                        app.input = Input::new(draft.note.clone()).with_cursor(len);
                    } else {
                        app.input = Input::default();
                    }
                    app.mode = Mode::NoteEdit;
                }
                3 => {
                    let Some(draft) = app.draft.as_ref() else {
                        return Ok(false);
                    };
                    if draft.tenant.trim().is_empty() || draft.note.trim().is_empty() {
                        set_status(app, "tenant and note required", true);
                        return Ok(false);
                    }
                    let key = app.keys[app.selected].clone();
                    let private_hex = load_private_key(&key, keydir)?;
                    send_register_request(
                        vault_url,
                        token,
                        RegisterPayload {
                            public_hex: key,
                            private_hex,
                            tenant: draft.tenant.clone(),
                            note: draft.note.clone(),
                            tags: draft.tags.clone(),
                        },
                    )?;
                    app.keys.remove(app.selected);
                    if app.selected >= app.keys.len() && app.selected > 0 {
                        app.selected -= 1;
                    }
                    set_status(app, "submitted", false);
                    app.draft = None;
                    app.mode = Mode::List;
                }
                _ => {}
            },
            KeyCode::Esc => {
                app.draft = None;
                app.mode = Mode::List;
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
                if app.edit_field + 1 < app.tenants.len() {
                    app.edit_field += 1;
                }
            }
            KeyCode::Enter => {
                if let Some(draft) = app.draft.as_mut() {
                    if let Some(value) = app.tenants.get(app.edit_field) {
                        draft.tenant = value.clone();
                    }
                }
                app.edit_field = 0;
                app.mode = Mode::Edit;
            }
            KeyCode::Char('n') => {
                app.input = Input::default();
                app.mode = Mode::TenantAdd;
            }
            KeyCode::Esc => {
                app.edit_field = 0;
                app.mode = Mode::Edit;
            }
            _ => {}
        },
        Mode::TenantAdd => match key.code {
            KeyCode::Enter => {
                let tenant = app.input.value().trim().to_string();
                if tenant.is_empty() {
                    set_status(app, "tenant required", true);
                } else {
                    if !app.tenants.contains(&tenant) {
                        app.tenants.push(tenant.clone());
                    }
                    if let Some(draft) = app.draft.as_mut() {
                        draft.tenant = tenant;
                    }
                    app.mode = Mode::Edit;
                }
            }
            KeyCode::Esc => {
                app.mode = Mode::TenantSelect;
            }
            _ => {
                app.input.handle_event(&Event::Key(key));
            }
        },
        Mode::TagsEdit => match key.code {
            KeyCode::Enter => {
                if let Some(draft) = app.draft.as_mut() {
                    draft.tags = parse_tags(app.input.value());
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
    }

    Ok(false)
}

fn render(f: &mut ratatui::Frame<'_>, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)])
        .split(f.area());

    render_list(f, app, layout[0]);
    render_status(f, app, layout[1]);
    render_help(f, app, layout[2]);

    if matches!(app.mode, Mode::Edit | Mode::TagsEdit | Mode::NoteEdit) {
        render_edit_dialog(f, app);
    }
    if app.mode == Mode::TenantSelect {
        render_select_dialog(f, "Select tenant", &app.tenants, app.edit_field);
    }
    if app.mode == Mode::TenantAdd {
        let area = centered_rect_fixed(60, 3, f.area());
        f.render_widget(Clear, area);
        render_text_input(f, area, "New tenant", "tenant", app);
    }
}

fn render_list(f: &mut ratatui::Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let height = area.height.saturating_sub(0) as usize;
    let offset = list_offset(app.selected, height);
    let mut items = Vec::new();
    for (idx, key) in app.keys.iter().enumerate().skip(offset).take(height) {
        let selected = idx == app.selected;
        let prefix = if selected { ">> " } else { "   " };
        items.push(ListItem::new(Line::from(format!("{prefix}{key}"))));
    }
    let mut state = ListState::default();
    if !app.keys.is_empty() {
        state.select(Some(app.selected.saturating_sub(offset)));
    }
    let list = List::new(items)
        .highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("");
    f.render_stateful_widget(list, area, &mut state);

    if app.keys.len() > height {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        let mut state = ScrollbarState::new(app.keys.len()).position(app.selected);
        f.render_stateful_widget(scrollbar, area, &mut state);
    }
}

fn render_status(f: &mut ratatui::Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let style = if app.status_error {
        Style::default().fg(Color::Red)
    } else {
        Style::default()
    };
    let line = Paragraph::new(app.status.clone())
        .alignment(Alignment::Left)
        .style(style);
    f.render_widget(line, area);
}

fn render_help(f: &mut ratatui::Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let help = match app.mode {
        Mode::List => "help: Up/Down select | Enter edit | q quit",
        Mode::Edit => "help: Enter edit/submit | Esc cancel",
        Mode::TenantSelect => "help: Select tenant | n new | Enter apply | Esc cancel",
        Mode::TenantAdd => "help: New tenant | Enter apply | Esc cancel",
        Mode::TagsEdit => "help: Edit tags | Enter apply | Esc cancel",
        Mode::NoteEdit => "help: Edit note | Enter apply | Esc cancel",
    };
    let line = Paragraph::new(help).alignment(Alignment::Left);
    f.render_widget(line, area);
}

fn render_edit_dialog(f: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(50, 24, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Register key")
        .style(Style::default().fg(Color::Yellow));

    let mut lines = Vec::new();
    if let Some(key) = app.keys.get(app.selected) {
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default().fg(Color::Yellow)),
            Span::styled("public_hex: ", Style::default().fg(Color::DarkGray)),
            Span::styled(key.clone(), Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::from(""));
    }
    if let Some(draft) = app.draft.as_ref() {
        let tags = if matches!(app.mode, Mode::TagsEdit) && app.edit_field == 1 {
            app.input.value().to_string()
        } else if draft.tags.is_empty() {
            "-".to_string()
        } else {
            draft.tags.join(", ")
        };
        let note = if matches!(app.mode, Mode::NoteEdit) && app.edit_field == 2 {
            app.input.value().to_string()
        } else if draft.note.trim().is_empty() {
            "-".to_string()
        } else {
            draft.note.clone()
        };
        lines.push(form_line("tenant", &draft.tenant, app.edit_field == 0));
        lines.push(form_line("tags", &tags, app.edit_field == 1));
        lines.push(form_line("note", &note, app.edit_field == 2));
        lines.push(Line::from(""));
        let submit_label = "<submit>";
        let submit_span = if app.edit_field == 3 {
            Span::styled(
                submit_label,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(submit_label, Style::default().fg(Color::Yellow))
        };
        lines.push(Line::from(submit_span).alignment(Alignment::Center));
    }

    let paragraph = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Left)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(paragraph, area);

    if matches!(app.mode, Mode::TagsEdit | Mode::NoteEdit) {
        let (label, line_index) = if app.edit_field == 1 {
            ("tags", 2 + 1)
        } else {
            ("note", 2 + 2)
        };
        let label_len = label.chars().count() as u16;
        let cursor_x = area.x + 1 + 2 + label_len + 2 + app.input.visual_cursor() as u16;
        let cursor_y = area.y + 1 + line_index as u16;
        f.set_cursor_position((cursor_x, cursor_y));
    }
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
        .style(Style::default().fg(Color::Yellow));
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
        .alignment(Alignment::Left)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(input, area);
    let label_len = label.chars().count() as u16;
    let cursor_x = area.x + 1 + 2 + label_len + 2 + app.input.visual_cursor() as u16;
    let cursor_y = area.y + 1;
    f.set_cursor_position((cursor_x, cursor_y));
}

fn render_select_dialog(
    f: &mut ratatui::Frame<'_>,
    title: &str,
    items: &[String],
    selected: usize,
) {
    let height = (items.len() as u16 + 4).clamp(8, 18);
    let area = centered_rect_fixed(60, height, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().fg(Color::Yellow));

    let inner_height = area.height.saturating_sub(2) as usize;
    let offset = list_offset(selected, inner_height);
    let list_items: Vec<ListItem> = items
        .iter()
        .skip(offset)
        .take(inner_height)
        .map(|item| ListItem::new(Line::from(item.clone())))
        .collect();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(selected.saturating_sub(offset)));
    }
    let list = List::new(list_items)
        .block(block)
        .highlight_style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, area, &mut state);
    if items.len() > inner_height {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None);
        let mut sb_state = ScrollbarState::new(items.len()).position(selected);
        f.render_stateful_widget(scrollbar, area, &mut sb_state);
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

fn parse_tags(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

fn set_status(app: &mut App, message: &str, is_error: bool) {
    app.status = message.to_string();
    app.status_error = is_error;
    app.status_until = Some(Instant::now() + Duration::from_secs(5));
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

fn centered_rect(percent_x: u16, percent_y: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let vertical = popup_layout[1];
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical);
    horizontal[1]
}

fn centered_rect_fixed(width: u16, height: u16, area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((area.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((area.width.saturating_sub(width)) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(vertical[1]);
    horizontal[1]
}
