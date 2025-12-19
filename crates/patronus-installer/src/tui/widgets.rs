//! Custom TUI widgets

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap},
    Frame,
};

/// Application color scheme
pub struct Theme;

impl Theme {
    pub const BACKGROUND: Color = Color::Reset;
    pub const FOREGROUND: Color = Color::White;
    pub const PRIMARY: Color = Color::Cyan;
    pub const SECONDARY: Color = Color::Blue;
    pub const SUCCESS: Color = Color::Green;
    pub const WARNING: Color = Color::Yellow;
    pub const ERROR: Color = Color::Red;
    pub const HIGHLIGHT: Color = Color::Cyan;
    pub const MUTED: Color = Color::DarkGray;
}

/// Draw the main application frame with header and footer
pub fn draw_frame(frame: &mut Frame, title: &str) -> Rect {
    let size = frame.area();

    // Create main layout: header, content, footer
    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer
        ])
        .split(size);

    // Draw header
    draw_header(frame, chunks[0], title);

    // Draw footer
    draw_footer(frame, chunks[2]);

    // Return content area
    chunks[1]
}

/// Draw the header bar
fn draw_header(frame: &mut Frame, area: Rect, title: &str) {
    let header = Paragraph::new(title)
        .style(Style::default().fg(Theme::PRIMARY).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Theme::MUTED)),
        );
    frame.render_widget(header, area);
}

/// Draw the footer with navigation hints
fn draw_footer(frame: &mut Frame, area: Rect) {
    let hints = vec![
        Span::styled("←/→", Style::default().fg(Theme::HIGHLIGHT)),
        Span::raw(" Navigate  "),
        Span::styled("Enter", Style::default().fg(Theme::HIGHLIGHT)),
        Span::raw(" Select  "),
        Span::styled("Esc", Style::default().fg(Theme::HIGHLIGHT)),
        Span::raw(" Back  "),
        Span::styled("q", Style::default().fg(Theme::HIGHLIGHT)),
        Span::raw(" Quit"),
    ];

    let footer = Paragraph::new(Line::from(hints))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Theme::MUTED)),
        );
    frame.render_widget(footer, area);
}

/// Draw a centered box with content
pub fn draw_centered_box(frame: &mut Frame, area: Rect, title: &str, width: u16, height: u16) -> Rect {
    let horizontal_padding = (area.width.saturating_sub(width)) / 2;
    let vertical_padding = (area.height.saturating_sub(height)) / 2;

    let box_area = Rect::new(
        area.x + horizontal_padding,
        area.y + vertical_padding,
        width.min(area.width),
        height.min(area.height),
    );

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::PRIMARY));

    frame.render_widget(block, box_area);

    // Return inner area
    Rect::new(
        box_area.x + 1,
        box_area.y + 1,
        box_area.width.saturating_sub(2),
        box_area.height.saturating_sub(2),
    )
}

/// Draw a selectable list
pub fn draw_selection_list<'a>(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    items: impl Iterator<Item = &'a str>,
    selected: usize,
) {
    let list_items: Vec<ListItem> = items
        .enumerate()
        .map(|(i, item)| {
            let style = if i == selected {
                Style::default()
                    .fg(Theme::HIGHLIGHT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Theme::FOREGROUND)
            };

            let prefix = if i == selected { "► " } else { "  " };
            ListItem::new(format!("{}{}", prefix, item)).style(style)
        })
        .collect();

    let list = List::new(list_items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SECONDARY)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(list, area);
}

/// Draw a checkbox list
pub fn draw_checkbox_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    items: &[(&str, bool)],
    focus: usize,
) {
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, (label, checked))| {
            let checkbox = if *checked { "[✓]" } else { "[ ]" };
            let style = if i == focus {
                Style::default()
                    .fg(Theme::HIGHLIGHT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Theme::FOREGROUND)
            };

            ListItem::new(format!("{} {}", checkbox, label)).style(style)
        })
        .collect();

    let list = List::new(list_items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::SECONDARY)),
    );

    frame.render_widget(list, area);
}

/// Draw a progress bar
pub fn draw_progress(frame: &mut Frame, area: Rect, label: &str, progress: f32) {
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(label)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SECONDARY)),
        )
        .gauge_style(Style::default().fg(Theme::SUCCESS))
        .percent((progress as u16).min(100))
        .label(format!("{:.0}%", progress));

    frame.render_widget(gauge, area);
}

/// Draw an info box
pub fn draw_info(frame: &mut Frame, area: Rect, title: &str, content: &str) {
    let paragraph = Paragraph::new(content)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SECONDARY)),
        );

    frame.render_widget(paragraph, area);
}

/// Draw an error message
pub fn draw_error(frame: &mut Frame, area: Rect, message: &str) {
    let paragraph = Paragraph::new(message)
        .style(Style::default().fg(Theme::ERROR))
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .title("Error")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::ERROR)),
        );

    frame.render_widget(paragraph, area);
}

/// Draw a key-value table
pub fn draw_table(frame: &mut Frame, area: Rect, title: &str, rows: &[(&str, &str)]) {
    let text: Vec<Line> = rows
        .iter()
        .map(|(key, value)| {
            Line::from(vec![
                Span::styled(
                    format!("{}: ", key),
                    Style::default().fg(Theme::MUTED),
                ),
                Span::styled(*value, Style::default().fg(Theme::FOREGROUND)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::SECONDARY)),
    );

    frame.render_widget(paragraph, area);
}

/// Draw ASCII art logo
pub fn draw_logo(frame: &mut Frame, area: Rect) {
    let logo = r#"
  ____       _
 |  _ \ __ _| |_ _ __ ___  _ __  _   _ ___
 | |_) / _` | __| '__/ _ \| '_ \| | | / __|
 |  __/ (_| | |_| | | (_) | | | | |_| \__ \
 |_|   \__,_|\__|_|  \___/|_| |_|\__,_|___/

    "#;

    let paragraph = Paragraph::new(logo)
        .style(Style::default().fg(Theme::PRIMARY))
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, area);
}
