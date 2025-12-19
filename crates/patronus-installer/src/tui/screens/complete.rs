//! Installation complete screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, Theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Installation Complete");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Success message
            Constraint::Min(10),   // Next steps
            Constraint::Length(3), // Actions
        ])
        .margin(2)
        .split(content_area);

    // Success message
    let success = vec![
        Line::from(""),
        Line::styled(
            "✓ Patronus has been successfully installed!",
            Style::default()
                .fg(Theme::SUCCESS)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(""),
    ];
    let para = Paragraph::new(success).alignment(Alignment::Center);
    frame.render_widget(para, chunks[0]);

    // Next steps
    let web_port = app.config.services.web_port;
    let ssh_port = app.config.services.ssh_port;
    let hostname = &app.config.system.hostname;

    let next_steps = vec![
        Line::from("Next Steps:"),
        Line::from(""),
        Line::from("  1. Remove installation media"),
        Line::from("  2. Reboot the system"),
        Line::from(format!("  3. Access web interface: http://{}:{}", hostname, web_port)),
        Line::from(format!("  4. SSH access: ssh admin@{} -p {}", hostname, ssh_port)),
        Line::from(""),
        Line::from("Default Credentials:"),
        Line::from("  Username: admin"),
        Line::from("  Password: (set on first login)"),
        Line::from(""),
        Line::from("Documentation: https://docs.patronus.dev"),
    ];
    let para = Paragraph::new(next_steps);
    frame.render_widget(para, chunks[1]);

    // Actions
    let actions = Line::from(vec![
        Span::raw("Press "),
        Span::styled("r", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" to reboot or "),
        Span::styled("q", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" to exit"),
    ]);
    let para = Paragraph::new(actions).alignment(Alignment::Center);
    frame.render_widget(para, chunks[2]);
}
