use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, Padding, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};
use serde_json::Value;
use time::format_description::parse;
use time::{OffsetDateTime, UtcOffset};
use unicode_width::UnicodeWidthChar;

use crate::crypto::SecureBox;
use crate::error::Error;
use crate::key_store::load_private_key;

#[derive(Debug)]
struct Entry {
    key: String,
    display: String,
    dirty: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Mode {
    Normal,
    Edit,
    Filter,
    AddKey,
    RenameKey,
    Diff,
    ConfirmExit,
    ConfirmDelete,
}

#[derive(Debug)]
struct App {
    entries: Vec<Entry>,
    selected: usize,
    mode: Mode,
    input: String,
    cursor: usize,
    filter: Option<String>,
    pending_delete: Option<usize>,
    pending_rename: Option<usize>,
    deleted_keys: Vec<String>,
    header: String,
    original: HashMap<String, String>,
    diff_scroll: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExitAction {
    Save,
    Discard,
}

pub fn run_edit_ui(path: &Path, keydir: Option<PathBuf>) -> Result<(), Error> {
    let text = fs::read_to_string(path)?;
    let mut root: Value = serde_json::from_str(&text)?;

    let env_key = {
        let obj = root.as_object().ok_or(Error::MissingEnvObject)?;
        if obj.contains_key("environment") {
            "environment"
        } else if obj.contains_key("env") {
            "env"
        } else {
            return Err(Error::MissingEnvObject);
        }
    };

    let env_obj = root
        .get(env_key)
        .and_then(Value::as_object)
        .ok_or(Error::MissingEnvObject)?;

    let sb = match crate::extract_public_key(&root) {
        Ok(public_key_hex) => {
            let private_key_hex = load_private_key(public_key_hex, keydir.as_deref())?;
            Some(SecureBox::new_from_hex(&private_key_hex, public_key_hex)?)
        }
        Err(Error::MissingPublicKey) => None,
        Err(e) => return Err(e),
    };

    let mut entries = Vec::with_capacity(env_obj.len());
    let mut original = HashMap::with_capacity(env_obj.len());
    for (key, value) in env_obj.iter() {
        let display = match value {
            Value::String(s) => match sb.as_ref() {
                Some(sb) => sb.decrypt_value(s)?,
                None => s.clone(),
            },
            other => other.to_string(),
        };
        original.insert(key.clone(), display.clone());
        entries.push(Entry {
            key: key.clone(),
            display,
            dirty: false,
        });
    }

    let mut app = App {
        entries,
        selected: 0,
        mode: Mode::Normal,
        input: String::new(),
        cursor: 0,
        filter: None,
        pending_delete: None,
        pending_rename: None,
        deleted_keys: Vec::new(),
        header: build_header(path)?,
        original,
        diff_scroll: 0,
    };

    let action = run_ui(&mut app)?;

    let has_changes = app.entries.iter().any(|e| e.dirty) || !app.deleted_keys.is_empty();
    if action == ExitAction::Save && has_changes {
        let mut updated_env = env_obj.clone();
        for key in app.deleted_keys.iter() {
            updated_env.remove(key);
        }
        for entry in app.entries.iter().filter(|e| e.dirty) {
            let parsed = parse_json_or_string(&entry.display);
            let updated = match parsed {
                Value::String(s) => match sb.as_ref() {
                    Some(sb) => Value::String(sb.encrypt_value(&s)?),
                    None => Value::String(s),
                },
                other => other,
            };
            updated_env.insert(entry.key.clone(), updated);
        }
        if let Some(obj) = root.as_object_mut() {
            obj.insert(env_key.to_string(), Value::Object(updated_env));
        }
        let out = serde_json::to_string_pretty(&root)?;
        fs::write(path, out)?;
    }

    Ok(())
}

fn run_ui(app: &mut App) -> Result<ExitAction, Error> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = ui_loop(&mut terminal, app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn ui_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> Result<ExitAction, Error> {
    loop {
        terminal.draw(|f| render_ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            let exit = match app.mode {
                Mode::Normal => handle_normal_mode(app, key),
                Mode::Edit => handle_edit_mode(app, key),
                Mode::Filter => handle_filter_mode(app, key),
                Mode::AddKey => handle_add_key_mode(app, key),
                Mode::RenameKey => handle_rename_mode(app, key),
                Mode::Diff => handle_diff_mode(app, key),
                Mode::ConfirmExit => handle_confirm_mode(app, key),
                Mode::ConfirmDelete => handle_delete_mode(app, key),
            };
            if let Some(action) = exit {
                return Ok(action);
            }
        }
    }
}

fn handle_normal_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    let indices = filtered_indices(app);
    if indices.is_empty() {
        app.selected = 0;
    } else if app.selected >= indices.len() {
        app.selected = indices.len() - 1;
    }
    match key.code {
        KeyCode::Up => {
            if app.selected > 0 {
                app.selected -= 1;
            }
        }
        KeyCode::Down => {
            if app.selected + 1 < indices.len() {
                app.selected += 1;
            }
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            if let Some(entry_index) = indices.get(app.selected) {
                let entry = &app.entries[*entry_index];
                app.input = entry.display.clone();
                app.cursor = app.input.len();
                app.mode = Mode::Edit;
            }
        }
        KeyCode::Char('/') => {
            app.input = app.filter.clone().unwrap_or_default();
            app.cursor = app.input.len();
            app.mode = Mode::Filter;
        }
        KeyCode::Char('+') => {
            app.input.clear();
            app.cursor = 0;
            app.mode = Mode::AddKey;
        }
        KeyCode::Char('v') => {
            app.diff_scroll = 0;
            app.mode = Mode::Diff;
        }
        KeyCode::Char('r') => {
            if let Some(entry_index) = indices.get(app.selected).copied() {
                app.pending_rename = Some(entry_index);
                app.input = app.entries[entry_index].key.clone();
                app.cursor = app.input.len();
                app.mode = Mode::RenameKey;
            }
        }
        KeyCode::Char('d') => {
            if let Some(entry_index) = indices.get(app.selected).copied() {
                app.pending_delete = Some(entry_index);
                app.mode = Mode::ConfirmDelete;
            }
        }
        KeyCode::Char('s') => {
            return Some(ExitAction::Save);
        }
        KeyCode::Char('q') | KeyCode::Esc => {
            if app.entries.iter().any(|e| e.dirty) || !app.deleted_keys.is_empty() {
                app.mode = Mode::ConfirmExit;
            } else {
                return Some(ExitAction::Discard);
            }
        }
        _ => {}
    }
    None
}

fn handle_edit_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    let indices = filtered_indices(app);
    if indices.is_empty() {
        app.mode = Mode::Normal;
        return None;
    }
    match key.code {
        KeyCode::Enter => {
            if let Some(entry_index) = indices.get(app.selected).copied() {
                let entry = &mut app.entries[entry_index];
                if entry.display != app.input {
                    entry.display = app.input.clone();
                    entry.dirty = true;
                }
            }
            app.mode = Mode::Normal;
        }
        KeyCode::Esc => {
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    handle_text_input(key, &mut app.input, &mut app.cursor);
    None
}

fn handle_diff_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    match key.code {
        KeyCode::Up => {
            app.diff_scroll = app.diff_scroll.saturating_sub(1);
        }
        KeyCode::Down => {
            app.diff_scroll = app.diff_scroll.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.diff_scroll = app.diff_scroll.saturating_sub(5);
        }
        KeyCode::PageDown => {
            app.diff_scroll = app.diff_scroll.saturating_add(5);
        }
        KeyCode::Char('q') | KeyCode::Esc => {
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    None
}

fn handle_filter_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    match key.code {
        KeyCode::Enter => {
            let trimmed = app.input.trim();
            app.filter = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            };
            app.selected = 0;
            app.mode = Mode::Normal;
        }
        KeyCode::Esc => {
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    handle_text_input(key, &mut app.input, &mut app.cursor);
    None
}

fn handle_add_key_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    match key.code {
        KeyCode::Enter => {
            let trimmed = app.input.trim();
            if !trimmed.is_empty() {
                let candidate = trimmed.to_uppercase();
                if !is_valid_env_key(&candidate) {
                    return None;
                }
                let exists = app.entries.iter().any(|e| e.key == candidate);
                if exists {
                    return None;
                }
                app.entries.push(Entry {
                    key: candidate,
                    display: String::new(),
                    dirty: true,
                });
                let entry_index = app.entries.len() - 1;
                app.filter = None;
                app.selected = entry_index;
                app.input = app.entries[entry_index].display.clone();
                app.cursor = app.input.len();
                app.mode = Mode::Edit;
            } else {
                app.mode = Mode::Normal;
            }
        }
        KeyCode::Esc => {
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    handle_text_input(key, &mut app.input, &mut app.cursor);
    None
}

fn handle_rename_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    match key.code {
        KeyCode::Enter => {
            let trimmed = app.input.trim();
            if !trimmed.is_empty() {
                if let Some(index) = app.pending_rename.take() {
                    let candidate = trimmed.to_uppercase();
                    if !is_valid_env_key(&candidate) {
                        app.pending_rename = Some(index);
                        return None;
                    }
                    let same_key = app.entries[index].key == candidate;
                    let exists = app.entries.iter().any(|e| e.key == candidate);
                    if exists && !same_key {
                        app.pending_rename = Some(index);
                        return None;
                    }
                    if !same_key && index < app.entries.len() {
                        let old_key = app.entries[index].key.clone();
                        app.entries[index].key = candidate;
                        app.entries[index].dirty = true;
                        app.deleted_keys.push(old_key);
                        app.filter = None;
                        app.selected = 0;
                    }
                }
            }
            app.mode = Mode::Normal;
        }
        KeyCode::Esc => {
            app.pending_rename = None;
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    handle_text_input(key, &mut app.input, &mut app.cursor);
    None
}

fn handle_confirm_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => return Some(ExitAction::Save),
        KeyCode::Char('n') | KeyCode::Char('N') => return Some(ExitAction::Discard),
        KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Esc => {
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    None
}

fn handle_delete_mode(app: &mut App, key: KeyEvent) -> Option<ExitAction> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            if let Some(index) = app.pending_delete.take() {
                if index < app.entries.len() {
                    let entry = app.entries.remove(index);
                    app.deleted_keys.push(entry.key);
                }
                app.selected = 0;
            }
            app.mode = Mode::Normal;
        }
        KeyCode::Char('n') | KeyCode::Char('N') => {
            app.pending_delete = None;
            app.mode = Mode::Normal;
        }
        KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Esc => {
            app.pending_delete = None;
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    None
}

fn render_ui(f: &mut ratatui::Frame<'_>, app: &App) {
    let size = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(size);

    let header_line = Paragraph::new(app.header.as_str())
        .alignment(Alignment::Left)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(header_line, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let indices = filtered_indices(app);
    let mut list_state = ratatui::widgets::ListState::default();
    if !indices.is_empty() {
        let selected = app.selected.min(indices.len() - 1);
        list_state.select(Some(selected));
    }

    let items: Vec<ListItem> = indices
        .iter()
        .map(|&idx| {
            let entry = &app.entries[idx];
            let suffix = if entry.dirty { " *" } else { "" };
            ListItem::new(Line::from(format!("{}{}", entry.key, suffix)))
        })
        .collect();

    let list_block = Block::default()
        .borders(Borders::ALL)
        .title(" Keys ")
        .padding(Padding::horizontal(1));
    let list = List::new(items)
        .block(list_block.clone())
        .highlight_symbol(" > ")
        .highlight_style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, body[0], &mut list_state);
    render_scrollbar(f, body[0], &list_block, &list_state, indices.len());

    let value_items: Vec<ListItem> = indices
        .iter()
        .map(|&idx| {
            let entry = &app.entries[idx];
            ListItem::new(visible_value_line(&entry.display))
        })
        .collect();

    let value_block = Block::default()
        .borders(Borders::ALL)
        .title(" Values ")
        .padding(Padding::horizontal(1));
    let values_list = List::new(value_items)
        .block(value_block.clone())
        .highlight_symbol(" > ")
        .highlight_style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(values_list, body[1], &mut list_state);
    render_scrollbar(f, body[1], &value_block, &list_state, indices.len());

    let help = match app.mode {
        Mode::Normal => {
            "Up/Down select | e edit | / filter | + add | r rename | d delete | v diff | s save | q quit"
        }
        Mode::Edit => "Enter save field | Esc cancel | Left/Right move",
        Mode::Filter => "Filter key/value (case-insensitive) | Enter apply | Esc cancel",
        Mode::AddKey => "New key | Enter confirm | Esc cancel",
        Mode::RenameKey => "Rename key | Enter confirm | Esc cancel",
        Mode::Diff => "Diff view | Up/Down scroll | q/Esc close",
        Mode::ConfirmExit => "Save changes? y/n/c",
        Mode::ConfirmDelete => "Delete key? y/n/c",
    };
    let status_line = if let Some(entry) = selected_entry(app) {
        Paragraph::new(format!("key: {}", entry.key))
            .alignment(Alignment::Left)
            .style(Style::default().add_modifier(Modifier::REVERSED))
    } else {
        Paragraph::new(String::new())
            .alignment(Alignment::Left)
            .style(Style::default().add_modifier(Modifier::REVERSED))
    };
    f.render_widget(status_line, chunks[2]);

    let help_line = if let Some(filter) = &app.filter {
        Paragraph::new(format!("{help} | filter: {filter}")).alignment(Alignment::Left)
    } else {
        Paragraph::new(help).alignment(Alignment::Left)
    };
    f.render_widget(help_line, chunks[3]);

    if app.mode == Mode::ConfirmExit {
        let area = centered_rect(35, 12, size);
        f.render_widget(Clear, area);
        let block = Block::default()
            .title("Save changes?")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Yellow));
        let text = Line::from(vec![
            Span::raw("Press "),
            Span::styled("y", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to save, "),
            Span::styled("n", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to discard, "),
            Span::styled("c", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to cancel."),
        ]);
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        f.render_widget(paragraph, area);
    }

    if app.mode == Mode::ConfirmDelete {
        let area = centered_rect(35, 12, size);
        f.render_widget(Clear, area);
        let block = Block::default()
            .title("Delete key?")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Red));
        let text = Line::from(vec![
            Span::raw("Press "),
            Span::styled("y", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to delete, "),
            Span::styled("n", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to cancel."),
        ]);
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Center);
        f.render_widget(paragraph, area);
    }

    if matches!(app.mode, Mode::Filter | Mode::AddKey | Mode::RenameKey) {
        let area = centered_rect(45, 12, size);
        f.render_widget(Clear, area);
        let title = if app.mode == Mode::Filter {
            "Filter keys"
        } else if app.mode == Mode::AddKey {
            "New key"
        } else {
            "Rename key"
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));
        let inner = block.inner(area);
        let warnings = key_input_warnings(app);
        let mut lines = Vec::new();
        lines.push(Line::from(app.input.as_str()));
        for msg in warnings {
            lines.push(Line::from(Span::styled(
                msg,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }
        let paragraph = Paragraph::new(lines).block(block);
        f.render_widget(paragraph, area);
        let (cursor_x, cursor_y) = wrapped_cursor_position(&app.input, app.cursor, inner.width);
        let cursor_x = inner.x + cursor_x;
        let cursor_y = inner.y + cursor_y;
        f.set_cursor_position((cursor_x, cursor_y));
    }

    if app.mode == Mode::Edit {
        let area = centered_rect(70, 35, size);
        f.render_widget(Clear, area);
        let title = if let Some(entry) = selected_entry(app) {
            format!("Edit: {}", entry.key)
        } else {
            "Edit value".to_string()
        };
        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));
        let inner = block.inner(area);
        let edit_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(inner);

        let edit_lines = wrap_text_lines(&app.input, edit_layout[0].width as usize);
        let edit_scroll = value_scroll_offset(
            app,
            edit_layout[0].width as usize,
            edit_layout[0].height as usize,
        );
        let edit_paragraph = Paragraph::new(lines_to_widget(edit_lines.clone()))
            .block(block.clone())
            .scroll((edit_scroll as u16, 0));
        f.render_widget(edit_paragraph, area);
        render_value_scrollbar(f, area, &block, edit_scroll, edit_lines.len());

        let (cursor_x, cursor_y) =
            wrapped_cursor_position(&app.input, app.cursor, edit_layout[0].width);
        let cursor_x = edit_layout[0].x + cursor_x;
        let cursor_y = edit_layout[0].y + cursor_y;
        f.set_cursor_position((cursor_x, cursor_y));

        let preview_block = Block::default()
            .title("Bytes (hex)")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));
        let preview_area = edit_layout[1];
        let preview_inner = preview_block.inner(preview_area);
        let preview_lines = hex_preview_lines(&app.input);
        let preview_scroll =
            preview_scroll_offset(&app.input, app.cursor, preview_inner.height as usize);
        let preview_paragraph = Paragraph::new(preview_lines.clone())
            .block(preview_block.clone())
            .scroll((preview_scroll as u16, 0));
        f.render_widget(preview_paragraph, preview_area);
        render_value_scrollbar(
            f,
            preview_area,
            &preview_block,
            preview_scroll,
            preview_lines.len(),
        );
    }

    if app.mode == Mode::Diff {
        let area = centered_rect(80, 70, size);
        f.render_widget(Clear, area);
        let block = Block::default()
            .title("Diff (unsaved)")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::Cyan));
        let inner = block.inner(area);
        let lines = build_diff_lines(app);
        let max_scroll = lines.len().saturating_sub(inner.height as usize);
        let scroll_y = app.diff_scroll.min(max_scroll);
        let paragraph = Paragraph::new(lines.clone())
            .block(block.clone())
            .scroll((scroll_y as u16, 0));
        f.render_widget(paragraph, area);
        render_value_scrollbar(f, area, &block, scroll_y, lines.len());
    }
}

fn wrapped_cursor_position(text: &str, cursor: usize, width: u16) -> (u16, u16) {
    let width = width as usize;
    if width == 0 {
        return (0, 0);
    }
    let mut x = 0usize;
    let mut y = 0usize;
    let mut idx = 0usize;
    for ch in text.chars() {
        if idx == cursor {
            break;
        }
        if ch == '\n' {
            y += 1;
            x = 0;
            idx += 1;
            continue;
        }
        let w = UnicodeWidthChar::width(ch).unwrap_or(1);
        if x + w > width && x > 0 {
            y += 1;
            x = 0;
        }
        x += w;
        idx += 1;
    }
    (x as u16, y as u16)
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn parse_json_or_string(input: &str) -> Value {
    serde_json::from_str(input).unwrap_or_else(|_| Value::String(input.to_owned()))
}

fn filtered_indices(app: &App) -> Vec<usize> {
    let filter = match &app.filter {
        Some(value) if !value.is_empty() => value.to_lowercase(),
        _ => return (0..app.entries.len()).collect(),
    };
    app.entries
        .iter()
        .enumerate()
        .filter_map(|(idx, entry)| {
            if entry.key.to_lowercase().contains(&filter)
                || entry.display.to_lowercase().contains(&filter)
            {
                Some(idx)
            } else {
                None
            }
        })
        .collect()
}

fn key_input_warnings(app: &App) -> Vec<String> {
    let trimmed = app.input.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let candidate = trimmed.to_uppercase();
    let mut warnings = Vec::new();
    if matches!(app.mode, Mode::AddKey | Mode::RenameKey) && !is_valid_env_key(&candidate) {
        warnings
            .push("Invalid env var name (use A-Z, 0-9, _; not starting with a digit)".to_string());
    }
    match app.mode {
        Mode::AddKey => {
            if app.entries.iter().any(|e| e.key == candidate) {
                warnings.push("Key already exists".to_string());
            }
        }
        Mode::RenameKey => {
            if let Some(index) = app.pending_rename {
                let same = app
                    .entries
                    .get(index)
                    .map(|e| e.key == candidate)
                    .unwrap_or(false);
                if !same && app.entries.iter().any(|e| e.key == candidate) {
                    warnings.push("Key already exists".to_string());
                }
            }
        }
        _ => {}
    }
    warnings
}

fn handle_text_input(key: KeyEvent, input: &mut String, cursor: &mut usize) -> bool {
    let len = input.len();
    match key.code {
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            *cursor = 0;
            true
        }
        KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            *cursor = input.len();
            true
        }
        KeyCode::Left => {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                || key.modifiers.contains(KeyModifiers::ALT)
            {
                *cursor = prev_word_boundary(input, *cursor);
            } else if *cursor > 0 {
                *cursor -= 1;
            }
            true
        }
        KeyCode::Right => {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                || key.modifiers.contains(KeyModifiers::ALT)
            {
                *cursor = next_word_boundary(input, *cursor);
            } else if *cursor < len {
                *cursor += 1;
            }
            true
        }
        KeyCode::Home => {
            *cursor = 0;
            true
        }
        KeyCode::End => {
            *cursor = len;
            true
        }
        KeyCode::Backspace => {
            if *cursor > 0 {
                *cursor -= 1;
                input.remove(*cursor);
            }
            true
        }
        KeyCode::Delete => {
            if *cursor < len {
                input.remove(*cursor);
            }
            true
        }
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::ALT) {
                if c == 'b' {
                    *cursor = prev_word_boundary(input, *cursor);
                    return true;
                }
                if c == 'f' {
                    *cursor = next_word_boundary(input, *cursor);
                    return true;
                }
            }
            if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT {
                input.insert(*cursor, c);
                *cursor += 1;
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn prev_word_boundary(input: &str, cursor: usize) -> usize {
    let bytes = input.as_bytes();
    let mut i = cursor.min(bytes.len());
    if i == 0 {
        return 0;
    }
    while i > 0 && !is_word_byte(bytes[i - 1]) {
        i -= 1;
    }
    while i > 0 && is_word_byte(bytes[i - 1]) {
        i -= 1;
    }
    i
}

fn next_word_boundary(input: &str, cursor: usize) -> usize {
    let bytes = input.as_bytes();
    let mut i = cursor.min(bytes.len());
    while i < bytes.len() && !is_word_byte(bytes[i]) {
        i += 1;
    }
    while i < bytes.len() && is_word_byte(bytes[i]) {
        i += 1;
    }
    i
}

fn build_header(path: &Path) -> Result<String, Error> {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let dir_display = if path.is_absolute() {
        dir.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(dir)
    };
    let fmt = parse(
        "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory]:[offset_minute]",
    )
    .unwrap_or_else(|_| {
        parse("[year]-[month]-[day] [hour]:[minute]:[second]").unwrap()
    });
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| {
            let odt = OffsetDateTime::from(t);
            let local = UtcOffset::local_offset_at(odt)
                .map(|offset| odt.to_offset(offset))
                .unwrap_or(odt);
            local.format(&fmt).ok()
        })
        .unwrap_or_else(|| "unknown".to_string());
    Ok(format!(
        "Editing {} in {} | modified {}",
        file_name,
        dir_display.display(),
        mtime
    ))
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn wrap_text_lines(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let mut lines = vec![String::new()];
    let mut line_width = 0usize;
    for ch in text.chars() {
        if ch == '\n' {
            lines.push(String::new());
            line_width = 0;
            continue;
        }
        let w = UnicodeWidthChar::width(ch).unwrap_or(1);
        if line_width + w > width && line_width > 0 {
            lines.push(String::new());
            line_width = 0;
        }
        if let Some(line) = lines.last_mut() {
            line.push(ch);
        }
        line_width += w;
    }
    lines
}

fn lines_to_widget(lines: Vec<String>) -> Vec<Line<'static>> {
    lines.into_iter().map(|line| Line::from(line)).collect()
}

fn selected_entry(app: &App) -> Option<&Entry> {
    let indices = filtered_indices(app);
    if indices.is_empty() {
        return None;
    }
    let idx = indices[app.selected.min(indices.len() - 1)];
    app.entries.get(idx)
}

fn render_scrollbar(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    block: &Block<'_>,
    state: &ratatui::widgets::ListState,
    content_len: usize,
) {
    let inner = block.inner(area);
    if inner.width == 0 || inner.height == 0 || content_len <= inner.height as usize {
        return;
    }
    let scrollbar_area = Rect {
        x: inner.x + inner.width - 1,
        y: inner.y,
        width: 1,
        height: inner.height,
    };
    let mut scrollbar_state = ScrollbarState::new(content_len);
    scrollbar_state = scrollbar_state.position(state.offset());
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
    f.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
}

fn render_value_scrollbar(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    block: &Block<'_>,
    scroll: usize,
    content_len: usize,
) {
    let inner = block.inner(area);
    if inner.width == 0 || inner.height == 0 || content_len <= inner.height as usize {
        return;
    }
    let scrollbar_area = Rect {
        x: inner.x + inner.width - 1,
        y: inner.y,
        width: 1,
        height: inner.height,
    };
    let mut scrollbar_state = ScrollbarState::new(content_len);
    scrollbar_state = scrollbar_state.position(scroll);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
    f.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
}

fn value_scroll_offset(app: &App, width: usize, height: usize) -> usize {
    if height == 0 {
        return 0;
    }
    if app.mode == Mode::Edit {
        let (_, cursor_y) = wrapped_cursor_position(&app.input, app.cursor, width as u16);
        let cursor_y = cursor_y as usize;
        if cursor_y + 1 > height {
            return cursor_y + 1 - height;
        }
    }
    0
}

fn build_diff_lines(app: &App) -> Vec<Line<'static>> {
    let mut current = HashMap::new();
    for entry in &app.entries {
        current.insert(entry.key.clone(), entry.display.clone());
    }

    let mut keys = BTreeSet::new();
    for key in app.original.keys() {
        keys.insert(key.clone());
    }
    for key in current.keys() {
        keys.insert(key.clone());
    }

    let mut lines = Vec::new();
    for key in keys {
        let original = app.original.get(&key);
        let current_val = current.get(&key);
        match (original, current_val) {
            (None, Some(val)) => {
                lines.push(diff_line('+', &key, val, Color::Green));
            }
            (Some(val), None) => {
                lines.push(diff_line('-', &key, val, Color::Red));
            }
            (Some(old), Some(new)) if old != new => {
                lines.push(diff_line('-', &key, old, Color::Red));
                lines.push(diff_line('+', &key, new, Color::Green));
            }
            _ => {}
        }
    }

    if lines.is_empty() {
        lines.push(Line::from("No changes."));
    }
    lines
}

fn diff_line(prefix: char, key: &str, value: &str, color: Color) -> Line<'static> {
    let value = value.replace('\n', "\\n");
    let text = format!("{prefix} {key}={value}");
    Line::from(Span::styled(text, Style::default().fg(color)))
}

fn visible_value_line(value: &str) -> Line<'static> {
    if value.is_empty() {
        return Line::from(Span::styled(
            "<empty>",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if value.trim().is_empty() {
        let count = value.len();
        return Line::from(Span::styled(
            format!("<spaces:{count}>"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    Line::from(value.to_owned())
}

fn hex_preview_lines(input: &str) -> Vec<Line<'static>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return vec![Line::from(Span::styled(
            "<empty>",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))];
    }
    let mut lines = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex = String::new();
        for (idx, b) in chunk.iter().enumerate() {
            if idx > 0 {
                hex.push(' ');
            }
            hex.push_str(&format!("{:02X}", b));
        }
        let mut ascii = String::new();
        for b in chunk {
            let ch = *b as char;
            if ch.is_ascii_graphic() || ch == ' ' {
                if ch == ' ' {
                    ascii.push('.');
                } else {
                    ascii.push(ch);
                }
            } else {
                ascii.push('.');
            }
        }
        let text = format!("{:04X}  {:<47}  {}", offset, hex, ascii);
        lines.push(Line::from(text));
    }
    lines
}

fn cursor_byte_index(input: &str, cursor: usize) -> usize {
    let mut idx = 0usize;
    for (i, ch) in input.chars().enumerate() {
        if i >= cursor {
            break;
        }
        idx += ch.len_utf8();
    }
    idx
}

fn preview_scroll_offset(input: &str, cursor: usize, height: usize) -> usize {
    if height == 0 {
        return 0;
    }
    let byte_index = cursor_byte_index(input, cursor);
    let line_index = byte_index / 16;
    if line_index + 1 > height {
        line_index + 1 - height
    } else {
        0
    }
}
