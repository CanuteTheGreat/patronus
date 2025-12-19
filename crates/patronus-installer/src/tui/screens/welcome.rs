//! Welcome screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, draw_logo, Theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, _app: &InstallerApp) {
    let content_area = draw_frame(frame, "Welcome to Patronus Installer");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Logo
            Constraint::Min(5),    // Description
            Constraint::Length(3), // Instructions
        ])
        .margin(2)
        .split(content_area);

    // Draw logo
    draw_logo(frame, chunks[0]);

    // Description
    let description = vec![
        Line::from(""),
        Line::from("Patronus is a modern, high-performance firewall and SD-WAN solution"),
        Line::from("built with Rust for security, reliability, and speed."),
        Line::from(""),
        Line::from("This installer will guide you through:"),
        Line::from("  • Disk partitioning and formatting"),
        Line::from("  • Network configuration"),
        Line::from("  • User account setup"),
        Line::from("  • Service configuration"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Requirements: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("8GB+ disk, 2GB+ RAM"),
        ]),
    ];

    let para = Paragraph::new(description)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Theme::FOREGROUND));
    frame.render_widget(para, chunks[1]);

    // Instructions
    let instructions = Line::from(vec![
        Span::raw("Press "),
        Span::styled("Enter", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" to continue or "),
        Span::styled("q", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" to quit"),
    ]);

    let para = Paragraph::new(instructions).alignment(Alignment::Center);
    frame.render_widget(para, chunks[2]);
}
