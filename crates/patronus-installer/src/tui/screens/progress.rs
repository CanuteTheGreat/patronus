//! Installation progress screen

use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, draw_progress, Theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::Style,
    text::Line,
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Installing Patronus");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Status
            Constraint::Length(3), // Progress bar
            Constraint::Min(10),   // Log
        ])
        .margin(2)
        .split(content_area);

    // Status text
    let status = vec![
        Line::from(""),
        Line::from("Installation in progress. Please wait..."),
        Line::from(""),
        Line::from(&*app.install_step),
    ];
    let para = Paragraph::new(status)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Theme::FOREGROUND));
    frame.render_widget(para, chunks[0]);

    // Progress bar
    draw_progress(frame, chunks[1], "Progress", app.install_progress);

    // Installation steps log
    let steps = get_installation_steps(app.install_progress);
    let para = Paragraph::new(steps);
    frame.render_widget(para, chunks[2]);
}

fn get_installation_steps(progress: f32) -> Vec<Line<'static>> {
    let steps = [
        (5.0, "Creating partitions"),
        (15.0, "Formatting filesystems"),
        (20.0, "Mounting partitions"),
        (25.0, "Installing base system"),
        (75.0, "Configuring system"),
        (80.0, "Configuring network"),
        (85.0, "Configuring services"),
        (90.0, "Installing bootloader"),
        (95.0, "Finalizing installation"),
        (100.0, "Installation complete"),
    ];

    steps
        .iter()
        .map(|(threshold, step)| {
            let prefix = if progress >= *threshold {
                format!("✓ {}", step)
            } else if progress >= threshold - 10.0 {
                format!("► {}", step)
            } else {
                format!("  {}", step)
            };

            let style = if progress >= *threshold {
                Style::default().fg(Theme::SUCCESS)
            } else if progress >= threshold - 10.0 {
                Style::default().fg(Theme::HIGHLIGHT)
            } else {
                Style::default().fg(Theme::MUTED)
            };

            Line::styled(prefix, style)
        })
        .collect()
}
