//! Service selection screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_checkbox_list, draw_frame, Theme};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Service Selection");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Info
            Constraint::Min(10),   // Service list
            Constraint::Length(3), // Instructions
        ])
        .margin(1)
        .split(content_area);

    // Info text
    let info = vec![
        Line::from("Select which services to enable on the installed system."),
        Line::from("Services can be enabled/disabled later via the web interface."),
    ];
    let para = Paragraph::new(info);
    frame.render_widget(para, chunks[0]);

    // Service checkboxes
    let services = [
        ("Patronus Firewall", app.config.services.firewall),
        ("Web Interface (port 8080)", app.config.services.web_ui),
        ("SSH Server (port 22)", app.config.services.ssh),
        ("DHCP Server", app.config.services.dhcp_server),
        ("DNS Server (Unbound)", app.config.services.dns_server),
    ];

    draw_checkbox_list(
        frame,
        chunks[1],
        "Services (Space to toggle)",
        &services,
        app.input_focus,
    );

    // Instructions
    let instructions = Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Theme::HIGHLIGHT)),
        Span::raw(" Navigate  "),
        Span::styled("Space", Style::default().fg(Theme::HIGHLIGHT)),
        Span::raw(" Toggle  "),
        Span::styled("→/Enter", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
        Span::raw(" Continue"),
    ]);
    let para = Paragraph::new(instructions);
    frame.render_widget(para, chunks[2]);
}
