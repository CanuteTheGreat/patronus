//! Disk selection screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, draw_selection_list, Theme};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Select Installation Disk");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Info
            Constraint::Min(10),   // Disk list
            Constraint::Length(5), // Details
        ])
        .margin(1)
        .split(content_area);

    // Info text
    let info = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("WARNING: ", Style::default().fg(Theme::WARNING).add_modifier(Modifier::BOLD)),
            Span::raw("The selected disk will be completely erased!"),
        ]),
    ]);
    frame.render_widget(info, chunks[0]);

    // Disk list
    let disk_items: Vec<String> = app.disks.iter().map(|d| d.summary()).collect();
    let disk_refs: Vec<&str> = disk_items.iter().map(|s| s.as_str()).collect();

    draw_selection_list(
        frame,
        chunks[1],
        "Available Disks",
        disk_refs.into_iter(),
        app.selected_disk,
    );

    // Disk details
    if !app.disks.is_empty() {
        let disk = &app.disks[app.selected_disk];

        let details = vec![
            Line::from(vec![
                Span::styled("Path: ", Style::default().fg(Theme::MUTED)),
                Span::raw(disk.path.display().to_string()),
            ]),
            Line::from(vec![
                Span::styled("Model: ", Style::default().fg(Theme::MUTED)),
                Span::raw(&disk.model),
            ]),
            Line::from(vec![
                Span::styled("Size: ", Style::default().fg(Theme::MUTED)),
                Span::raw(disk.size_string()),
                Span::raw(" | "),
                Span::styled("Transport: ", Style::default().fg(Theme::MUTED)),
                Span::raw(format!("{:?}", disk.transport)),
                Span::raw(" | "),
                Span::styled("Partitions: ", Style::default().fg(Theme::MUTED)),
                Span::raw(disk.partitions.len().to_string()),
            ]),
        ];

        let para = Paragraph::new(details);
        frame.render_widget(para, chunks[2]);
    }
}
