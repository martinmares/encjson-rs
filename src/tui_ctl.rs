use std::error::Error;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Mode {
    Normal,
    Filter,
    ConfirmExit,
}

struct App {
    items: Vec<String>,
    selected: usize,
    mode: Mode,
    status: String,
    filter: Option<String>,
    input: Input,
}

impl App {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            mode: Mode::Normal,
            status: "ready".to_string(),
            filter: None,
            input: Input::default(),
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
            KeyCode::Char('/') => {
                app.input = Input::new(app.filter.clone().unwrap_or_default());
                app.mode = Mode::Filter;
            }
            KeyCode::Char('q') | KeyCode::Esc => {
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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(f.size());

    let indices = filtered_indices(app);
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[0]);

    let list_items: Vec<ListItem> = if indices.is_empty() {
        vec![ListItem::new(Line::from(" no items"))]
    } else {
        indices
            .iter()
            .map(|idx| ListItem::new(Line::from(app.items[*idx].clone())))
            .collect()
    };
    let mut state = ListState::default();
    if !indices.is_empty() {
        let selected = app.selected.min(indices.len().saturating_sub(1));
        state.select(Some(selected));
    }
    let list = List::new(list_items)
        .block(Block::default().borders(Borders::ALL).title("Keys"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, main_chunks[0], &mut state);

    let details = Paragraph::new("select an item")
        .block(Block::default().borders(Borders::ALL).title("Details"));
    f.render_widget(details, main_chunks[1]);

    let status = format!(
        "status: {} | items: {} | filter: {}",
        app.status,
        indices.len(),
        app.filter.clone().unwrap_or_else(|| "-".to_string())
    );
    let status_line = Paragraph::new(status).alignment(Alignment::Left);
    f.render_widget(status_line, chunks[1]);

    let help = match app.mode {
        Mode::Normal => "help: Up/Down select | / filter | PgUp/PgDn | q/Esc quit",
        Mode::Filter => "Filter (case-insensitive) | Enter apply | Esc cancel",
        Mode::ConfirmExit => "Exit? y/n/c",
    };
    let help_line = Paragraph::new(help).alignment(Alignment::Left);
    f.render_widget(help_line, chunks[2]);

    if app.mode == Mode::Filter {
        let area = centered_rect(60, 3, f.size());
        f.render_widget(Clear, area);
        let block = Block::default().borders(Borders::ALL).title("Filter");
        let line = Line::from(vec![
            Span::raw("> "),
            Span::raw(app.input.value()),
        ]);
        let input = Paragraph::new(line).block(block);
        f.render_widget(input, area);
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
            if item.to_lowercase().contains(&needle) {
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
