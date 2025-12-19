//! Installation summary screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, draw_table, Theme};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Installation Summary");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .margin(1)
        .split(content_area);

    // Left column: Disk & System
    let left_chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Min(8),    // Disk info
            Constraint::Min(8),    // System info
            Constraint::Length(5), // Confirm
        ])
        .split(chunks[0]);

    // Disk info
    let disk_info = [
        ("Device", app.config.disk.device.display().to_string()),
        ("Scheme", app.config.disk.scheme.description().to_string()),
        ("Filesystem", app.config.disk.filesystem.description().to_string()),
        ("Swap", format!("{} MB", app.config.disk.swap_size_mb)),
    ];
    let disk_refs: Vec<(&str, &str)> = disk_info
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    draw_table(frame, left_chunks[0], "Disk", &disk_refs);

    // System info
    let system_info = [
        ("Hostname", app.config.system.hostname.clone()),
        ("Timezone", app.config.system.timezone.clone()),
        ("Locale", app.config.system.locale.clone()),
        ("Bootloader", format!("{:?}", app.config.system.bootloader)),
    ];
    let system_refs: Vec<(&str, &str)> = system_info
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    draw_table(frame, left_chunks[1], "System", &system_refs);

    // Right column: Services & Users
    let right_chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Min(10), // Services
            Constraint::Min(6),  // Users
        ])
        .split(chunks[1]);

    // Services
    let firewall_status = if app.config.services.firewall {
        "Enabled"
    } else {
        "Disabled"
    };
    let web_status = if app.config.services.web_ui {
        "Enabled"
    } else {
        "Disabled"
    };
    let ssh_status = if app.config.services.ssh {
        "Enabled"
    } else {
        "Disabled"
    };
    let dhcp_status = if app.config.services.dhcp_server {
        "Enabled"
    } else {
        "Disabled"
    };
    let dns_status = if app.config.services.dns_server {
        "Enabled"
    } else {
        "Disabled"
    };

    let services_info = [
        ("Firewall", firewall_status),
        ("Web UI", web_status),
        ("SSH", ssh_status),
        ("DHCP Server", dhcp_status),
        ("DNS Server", dns_status),
    ];
    draw_table(frame, right_chunks[0], "Services", &services_info);

    // Users
    let user = app.config.users.first();
    let username = user.map(|u| u.username.as_str()).unwrap_or("admin");
    let user_info = [
        ("Username", username),
        ("Sudo", "Yes"),
        ("Groups", "wheel, patronus"),
    ];
    draw_table(frame, right_chunks[1], "User", &user_info);

    // Confirm prompt
    let confirm = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("WARNING: ", Style::default().fg(Theme::WARNING).add_modifier(Modifier::BOLD)),
            Span::raw("This will erase all data on the selected disk!"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("Enter", Style::default().fg(Theme::HIGHLIGHT).add_modifier(Modifier::BOLD)),
            Span::raw(" to start installation or "),
            Span::styled("Esc", Style::default().fg(Theme::HIGHLIGHT)),
            Span::raw(" to go back"),
        ]),
    ];
    let para = Paragraph::new(confirm);
    frame.render_widget(para, left_chunks[2]);
}
