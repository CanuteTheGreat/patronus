//! Network configuration screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, Theme};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Network Configuration");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Info
            Constraint::Min(8),    // Interface list
            Constraint::Length(4), // Config options
        ])
        .margin(1)
        .split(content_area);

    // Info text
    let info = Paragraph::new(vec![
        Line::from("Configure network interfaces. By default, all interfaces use DHCP."),
        Line::from("You can configure static IPs after installation via the web interface."),
    ]);
    frame.render_widget(info, chunks[0]);

    // Interface list
    let items: Vec<ListItem> = app
        .interfaces
        .iter()
        .map(|iface| {
            ListItem::new(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::raw(iface),
                Span::styled(" (DHCP)", Style::default().fg(Theme::MUTED)),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title("Detected Network Interfaces")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::SECONDARY)),
    );
    frame.render_widget(list, chunks[1]);

    // Config info
    let config_info = vec![
        Line::from(vec![
            Span::styled("Hostname: ", Style::default().fg(Theme::MUTED)),
            Span::raw(&app.config.system.hostname),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
            Span::raw(" to continue with DHCP for all interfaces"),
        ]),
    ];

    let para = Paragraph::new(config_info);
    frame.render_widget(para, chunks[2]);
}
