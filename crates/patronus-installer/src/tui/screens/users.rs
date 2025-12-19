//! User setup screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, Theme};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "User Setup");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Info
            Constraint::Min(10),   // User form
            Constraint::Length(3), // Instructions
        ])
        .margin(1)
        .split(content_area);

    // Info text
    let info = vec![
        Line::from("Create an administrator account for the system."),
        Line::from("This user will have sudo access and can manage Patronus."),
        Line::from(""),
    ];
    let para = Paragraph::new(info);
    frame.render_widget(para, chunks[0]);

    // User form (simplified - shows current values)
    let user = app.config.users.first();
    let (username, groups) = user
        .map(|u| (u.username.as_str(), u.groups.join(", ")))
        .unwrap_or(("admin", "wheel, patronus".to_string()));

    let form_content = vec![
        Line::from(vec![
            Span::styled("Username:  ", Style::default().fg(Theme::MUTED)),
            Span::raw(username),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Password:  ", Style::default().fg(Theme::MUTED)),
            Span::raw("********"),
            Span::styled(" (set after installation)", Style::default().fg(Theme::MUTED)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Groups:    ", Style::default().fg(Theme::MUTED)),
            Span::raw(&groups),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Shell:     ", Style::default().fg(Theme::MUTED)),
            Span::raw("/bin/bash"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Sudo:      ", Style::default().fg(Theme::MUTED)),
            Span::styled("Yes", Style::default().fg(Theme::SUCCESS)),
        ]),
    ];

    let form = Paragraph::new(form_content).block(
        Block::default()
            .title("User Account")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::SECONDARY)),
    );
    frame.render_widget(form, chunks[1]);

    // Instructions
    let instructions = Line::from(vec![
        Span::raw("Press "),
        Span::styled("Enter", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" to continue (password can be set after first boot)"),
    ]);
    let para = Paragraph::new(instructions);
    frame.render_widget(para, chunks[2]);
}
