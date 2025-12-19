//! Partition scheme selection screen

use crate::config::{Filesystem, PartitionScheme};
use crate::tui::app::InstallerApp;
use crate::tui::widgets::{draw_frame, draw_selection_list, Theme};
use ratatui::{
    layout::{Constraint, Layout},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw(frame: &mut Frame, app: &InstallerApp) {
    let content_area = draw_frame(frame, "Partition Scheme");

    let chunks = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // Scheme selection
            Constraint::Length(5), // Details
        ])
        .margin(1)
        .split(content_area);

    // Partition schemes
    let schemes = [
        PartitionScheme::UefiSimple,
        PartitionScheme::UefiWithSwap,
        PartitionScheme::UefiSeparateHome,
        PartitionScheme::BiosSimple,
        PartitionScheme::BiosWithSwap,
    ];

    let scheme_items: Vec<&str> = schemes.iter().map(|s| s.description()).collect();

    draw_selection_list(
        frame,
        chunks[0],
        "Select Partition Layout",
        scheme_items.into_iter(),
        app.selected_scheme,
    );

    // Details about selected scheme
    let scheme = schemes[app.selected_scheme];
    let details = get_scheme_details(scheme, &app.config.disk.filesystem);

    let para = Paragraph::new(details);
    frame.render_widget(para, chunks[1]);
}

fn get_scheme_details(scheme: PartitionScheme, fs: &Filesystem) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Filesystem: ", Style::default().fg(Theme::MUTED)),
        Span::raw(fs.description()),
    ]));

    lines.push(Line::from(""));

    match scheme {
        PartitionScheme::UefiSimple => {
            lines.push(Line::from("Partitions to create:"));
            lines.push(Line::from("  1. EFI System Partition (512 MB, FAT32)"));
            lines.push(Line::from(format!("  2. Root (/, remaining space, {})", fs.as_str())));
        }
        PartitionScheme::UefiWithSwap => {
            lines.push(Line::from("Partitions to create:"));
            lines.push(Line::from("  1. EFI System Partition (512 MB, FAT32)"));
            lines.push(Line::from("  2. Swap (2 GB)"));
            lines.push(Line::from(format!("  3. Root (/, remaining space, {})", fs.as_str())));
        }
        PartitionScheme::UefiSeparateHome => {
            lines.push(Line::from("Partitions to create:"));
            lines.push(Line::from("  1. EFI System Partition (512 MB, FAT32)"));
            lines.push(Line::from("  2. Swap (2 GB)"));
            lines.push(Line::from(format!("  3. Root (/, 30 GB, {})", fs.as_str())));
            lines.push(Line::from(format!("  4. Home (/home, remaining, {})", fs.as_str())));
        }
        PartitionScheme::BiosSimple => {
            lines.push(Line::from("Partitions to create:"));
            lines.push(Line::from("  1. BIOS Boot (2 MB)"));
            lines.push(Line::from(format!("  2. Root (/, remaining space, {})", fs.as_str())));
        }
        PartitionScheme::BiosWithSwap => {
            lines.push(Line::from("Partitions to create:"));
            lines.push(Line::from("  1. BIOS Boot (2 MB)"));
            lines.push(Line::from("  2. Swap (2 GB)"));
            lines.push(Line::from(format!("  3. Root (/, remaining space, {})", fs.as_str())));
        }
        PartitionScheme::UseExisting => {
            lines.push(Line::from("Use existing partition layout"));
        }
    }

    lines
}
