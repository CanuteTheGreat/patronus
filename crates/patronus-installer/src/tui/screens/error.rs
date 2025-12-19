//! Error screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_error, draw_frame, Theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Error");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Error message
            Constraint::Length(3), // Actions
        ])
        .margin(2)
        .split(content_area);

    // Error message
    let message = app
        .error_message
        .as_deref()
        .unwrap_or("An unknown error occurred");

    draw_error(frame, chunks[0], message);

    // Actions
    let actions = Line::from(vec![
        Span::raw("Press "),
        Span::styled("Enter", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" to go back and try again or "),
        Span::styled("q", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" to quit"),
    ]);
    let para = Paragraph::new(actions).alignment(Alignment::Center);
    frame.render_widget(para, chunks[1]);
}
