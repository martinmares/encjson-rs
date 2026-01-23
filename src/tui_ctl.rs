use std::error::Error;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph};
use ratatui::Terminal;
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
    ConfirmExit,
}

#[derive(Debug, Clone)]
struct KeyItem {
    public_hex: String,
    tenant: String,
    status: String,
    note: String,
}

struct App {
    items: Vec<KeyItem>,
    selected: usize,
    mode: Mode,
    status: String,
    filter: Option<String>,
    input: Input,
    draft: Option<KeyDraft>,
    tenant_choices: Vec<String>,
    status_choices: Vec<String>,
    edit_field: usize,
}

#[derive(Debug, Clone)]
struct KeyDraft {
    tenant: String,
    status: String,
    note: String,
}

impl App {
    fn new() -> Self {
        Self {
            items: sample_items(),
            selected: 0,
            mode: Mode::Normal,
            status: "ready".to_string(),
            filter: None,
            input: Input::default(),
            draft: None,
            tenant_choices: vec![
                "cetin".to_string(),
                "o2".to_string(),
                "cez".to_string(),
            ],
            status_choices: vec![
                "active".to_string(),
                "deprecated".to_string(),
                "hidden".to_string(),
            ],
            edit_field: 0,
        }
    }
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

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), Box<dyn Error>> {
    let mut app = App::new();
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(200);

    loop {
        terminal.draw(|f| render_ui(f, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if handle_key(&mut app, key)? {
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
    match app.mode {
        Mode::Normal => match key.code {
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
            KeyCode::Enter | KeyCode::Char('e') => {
                if let Some(item) = selected_item(app) {
                    app.draft = Some(KeyDraft {
                        tenant: item.tenant.clone(),
                        status: item.status.clone(),
                        note: item.note.clone(),
                    });
                    app.edit_field = 0;
                    app.mode = Mode::Edit;
                }
            }
            KeyCode::Char('/') => {
                app.input = Input::new(app.filter.clone().unwrap_or_default());
                app.mode = Mode::Filter;
            }
            KeyCode::Char('q') => {
                app.mode = Mode::ConfirmExit;
            }
            _ => {}
        },
        Mode::Filter => match key.code {
            KeyCode::Enter => {
                let value = app.input.value().trim().to_string();
                app.filter = if value.is_empty() { None } else { Some(value) };
                app.mode = Mode::Normal;
                app.selected = 0;
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
                if app.edit_field < 2 {
                    app.edit_field += 1;
                }
            }
            KeyCode::Enter => match app.edit_field {
                0 => app.mode = Mode::TenantSelect,
                1 => app.mode = Mode::StatusSelect,
                2 => {
                    if let Some(draft) = app.draft.as_ref() {
                        app.input = Input::new(draft.note.clone());
                    } else {
                        app.input = Input::default();
                    }
                    app.mode = Mode::NoteEdit;
                }
                _ => {}
            },
            KeyCode::Char('s') => {
                apply_draft(app);
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
        Mode::ConfirmExit => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => return Ok(true),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Esc => {
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
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    let header = Paragraph::new("encjson-ctl").alignment(Alignment::Left);
    f.render_widget(header, chunks[0]);

    let indices = filtered_indices(app);
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

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
        let selected = app.selected.min(indices.len().saturating_sub(1));
        let list_height = main_chunks[0].height.saturating_sub(2) as usize;
        let offset = list_offset(selected, list_height);
        state = state.with_selected(Some(selected)).with_offset(offset);
    }
    let list_block = Block::default()
        .borders(Borders::ALL)
        .title(" Keys ")
        .padding(Padding::horizontal(1));
    let list = List::new(list_items)
        .block(list_block)
        .highlight_symbol(" > ")
        .highlight_style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, main_chunks[0], &mut state);

    let details = Paragraph::new(build_details(app, &indices))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Details ")
                .padding(Padding::horizontal(1)),
        );
    f.render_widget(details, main_chunks[1]);

    let status = format!(
        "status: {} | items: {}/{} | filter: {}",
        app.status,
        indices.len(),
        app.items.len(),
        app.filter.clone().unwrap_or_else(|| "-".to_string())
    );
    let status_line = Paragraph::new(status).alignment(Alignment::Left);
    f.render_widget(
        status_line.style(Style::default().add_modifier(Modifier::REVERSED)),
        chunks[2],
    );

    let help = match app.mode {
        Mode::Normal => "help: Up/Down select | / filter | Enter edit | PgUp/PgDn | q quit",
        Mode::Filter => "Filter (case-insensitive) | Enter apply | Esc cancel",
        Mode::Edit => "Edit fields | Enter select | s save | Esc cancel",
        Mode::TenantSelect => "Select tenant | Enter apply | Esc cancel",
        Mode::StatusSelect => "Select status | Enter apply | Esc cancel",
        Mode::NoteEdit => "Edit note | Enter apply | Esc cancel",
        Mode::ConfirmExit => "Exit? y/n/c",
    };
    let help_line = Paragraph::new(help).alignment(Alignment::Left);
    f.render_widget(help_line, chunks[3]);

    if app.mode == Mode::Filter {
        let area = centered_rect(60, 3, area);
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Filter ")
            .style(Style::default().fg(Color::Yellow))
            .padding(Padding::horizontal(1));
        let line = Line::from(vec![
            Span::raw("> "),
            Span::raw(app.input.value()),
        ]);
        let input = Paragraph::new(line)
            .block(block)
            .style(Style::default().fg(Color::Yellow));
        f.render_widget(input, area);
        let cursor_x = area.x + 2 + app.input.visual_cursor() as u16;
        let cursor_y = area.y + 1;
        f.set_cursor_position((cursor_x, cursor_y));
    }

    if app.mode == Mode::ConfirmExit {
        let area = centered_rect_fixed(48, 3, area);
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Save changes? ")
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

    if app.mode == Mode::Edit {
        render_edit_dialog(f, app);
    }
    if app.mode == Mode::TenantSelect {
        render_select_dialog(f, " Select tenant ", &app.tenant_choices, app.edit_field);
    }
    if app.mode == Mode::StatusSelect {
        render_select_dialog(f, " Select status ", &app.status_choices, app.edit_field);
    }
    if app.mode == Mode::NoteEdit {
        render_note_dialog(f, app);
    }
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

fn move_selection(app: &mut App, delta: isize) {
    let indices = filtered_indices(app);
    if indices.is_empty() {
        app.selected = 0;
        return;
    }
    let mut next = app.selected as isize + delta;
    if next < 0 {
        next = 0;
    }
    if next as usize >= indices.len() {
        next = (indices.len() - 1) as isize;
    }
    app.selected = next as usize;
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
    let short = short_hex(&item.public_hex);
    let tenant = truncate(&item.tenant, 10);
    let status = truncate(&item.status, 10);
    let note = truncate(&item.note, 18);
    format!("{short:<10} {tenant:<10} {status:<10} {note}")
}

fn short_hex(value: &str) -> String {
    if value.len() <= 8 {
        return value.to_string();
    }
    format!("{}...", &value[..8])
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut out = value.chars().take(max.saturating_sub(3)).collect::<String>();
    out.push_str("...");
    out
}

fn build_details(app: &App, indices: &[usize]) -> String {
    if indices.is_empty() {
        return "no selection".to_string();
    }
    let selected = app.selected.min(indices.len().saturating_sub(1));
    let item = &app.items[indices[selected]];
    format!(
        "public_hex: {}\ntenant: {}\nstatus: {}\nnote: {}",
        item.public_hex,
        item.tenant,
        item.status,
        if item.note.trim().is_empty() { "-" } else { &item.note }
    )
}

fn selected_item(app: &App) -> Option<&KeyItem> {
    let indices = filtered_indices(app);
    if indices.is_empty() {
        return None;
    }
    let selected = app.selected.min(indices.len().saturating_sub(1));
    let idx = indices[selected];
    app.items.get(idx)
}

fn apply_draft(app: &mut App) {
    let indices = filtered_indices(app);
    if indices.is_empty() {
        return;
    }
    let selected = app.selected.min(indices.len().saturating_sub(1));
    let idx = indices[selected];
    if let Some(draft) = app.draft.take() {
        if let Some(item) = app.items.get_mut(idx) {
            item.tenant = draft.tenant;
            item.status = draft.status;
            item.note = draft.note;
        }
    }
}

fn render_edit_dialog(f: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(60, 10, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Edit key ")
        .style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area);
    let mut lines = Vec::new();
    if let Some(item) = selected_item(app) {
        lines.push(Line::from(format!("public_hex: {}", item.public_hex)));
        lines.push(Line::from(""));
    }
    if let Some(draft) = app.draft.as_ref() {
        lines.push(Line::from(format!(
            "{} tenant   {}",
            if app.edit_field == 0 { ">" } else { " " },
            draft.tenant
        )));
        lines.push(Line::from(format!(
            "{} status   {}",
            if app.edit_field == 1 { ">" } else { " " },
            draft.status
        )));
        lines.push(Line::from(format!(
            "{} note     {}",
            if app.edit_field == 2 { ">" } else { " " },
            if draft.note.trim().is_empty() { "-" } else { draft.note.as_str() }
        )));
        lines.push(Line::from(""));
        lines.push(Line::from("Enter edit | s save | Esc cancel"));
    }
    let paragraph = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Left)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(paragraph, area);
    let cursor_x = inner.x + 1;
    let cursor_y = inner.y + 2 + app.edit_field as u16;
    f.set_cursor_position((cursor_x, cursor_y));
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

fn render_note_dialog(f: &mut ratatui::Frame<'_>, app: &App) {
    let area = centered_rect(60, 6, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Edit note ")
        .style(Style::default().fg(Color::Yellow))
        .padding(Padding::horizontal(1));
    let line = Line::from(vec![Span::raw(app.input.value())]);
    let paragraph = Paragraph::new(line)
        .block(block)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(paragraph, area);
    let cursor_x = area.x + 1 + app.input.visual_cursor() as u16;
    let cursor_y = area.y + 1;
    f.set_cursor_position((cursor_x, cursor_y));
}

fn sample_items() -> Vec<KeyItem> {
    vec![
        KeyItem {
            public_hex: "0333595220a5f1321385b8eac8c700b5ed35ca9efe73fddf3ea1488a0f19b773".to_string(),
            tenant: "cetin".to_string(),
            status: "active".to_string(),
            note: "db access".to_string(),
        },
        KeyItem {
            public_hex: "f5f657822c9a9dab5b214fa08c7ee2fe0d34f4e581d98f8b8a409b3ee06518a5".to_string(),
            tenant: "o2".to_string(),
            status: "active".to_string(),
            note: "app deploy".to_string(),
        },
        KeyItem {
            public_hex: "6081b6dd62270efe1dcc305d1bb7dd4993f5fbd8cce354067a4b9c3a96774d43".to_string(),
            tenant: "cez".to_string(),
            status: "deprecated".to_string(),
            note: "legacy".to_string(),
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
