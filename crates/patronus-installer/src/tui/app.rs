//! TUI Application state and main loop

use crate::config::InstallConfig;
use crate::disk::DiskInfo;
use crate::error::{InstallerError, Result};
use crate::tui::screens::*;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use tracing::info;

/// Current screen in the installation process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Welcome,
    DiskSelection,
    PartitionScheme,
    NetworkSetup,
    UserSetup,
    ServiceSelection,
    Summary,
    Installing,
    Complete,
    Error,
}

impl Screen {
    /// Get the next screen in sequence
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Welcome => Some(Self::DiskSelection),
            Self::DiskSelection => Some(Self::PartitionScheme),
            Self::PartitionScheme => Some(Self::NetworkSetup),
            Self::NetworkSetup => Some(Self::UserSetup),
            Self::UserSetup => Some(Self::ServiceSelection),
            Self::ServiceSelection => Some(Self::Summary),
            Self::Summary => Some(Self::Installing),
            Self::Installing => Some(Self::Complete),
            Self::Complete => None,
            Self::Error => None,
        }
    }

    /// Get the previous screen in sequence
    pub fn prev(&self) -> Option<Self> {
        match self {
            Self::Welcome => None,
            Self::DiskSelection => Some(Self::Welcome),
            Self::PartitionScheme => Some(Self::DiskSelection),
            Self::NetworkSetup => Some(Self::PartitionScheme),
            Self::UserSetup => Some(Self::NetworkSetup),
            Self::ServiceSelection => Some(Self::UserSetup),
            Self::Summary => Some(Self::ServiceSelection),
            Self::Installing => None, // Can't go back during install
            Self::Complete => None,
            Self::Error => Some(Self::Summary),
        }
    }

    /// Get screen title
    pub fn title(&self) -> &'static str {
        match self {
            Self::Welcome => "Welcome to Patronus Installer",
            Self::DiskSelection => "Select Installation Disk",
            Self::PartitionScheme => "Partition Scheme",
            Self::NetworkSetup => "Network Configuration",
            Self::UserSetup => "User Setup",
            Self::ServiceSelection => "Service Selection",
            Self::Summary => "Installation Summary",
            Self::Installing => "Installing...",
            Self::Complete => "Installation Complete",
            Self::Error => "Error",
        }
    }
}

/// Main TUI application
pub struct InstallerApp {
    /// Current screen
    pub current_screen: Screen,

    /// Installation configuration being built
    pub config: InstallConfig,

    /// Available disks
    pub disks: Vec<DiskInfo>,

    /// Selected disk index
    pub selected_disk: usize,

    /// Selected partition scheme index
    pub selected_scheme: usize,

    /// Selected filesystem index
    pub selected_filesystem: usize,

    /// Network interfaces
    pub interfaces: Vec<String>,

    /// Installation progress (0.0 - 100.0)
    pub install_progress: f32,

    /// Current installation step description
    pub install_step: String,

    /// Error message (if any)
    pub error_message: Option<String>,

    /// Whether the user wants to quit
    pub should_quit: bool,

    /// User input buffer
    pub input_buffer: String,

    /// Current input field focus
    pub input_focus: usize,
}

impl InstallerApp {
    /// Create a new installer application
    pub fn new() -> Self {
        Self {
            current_screen: Screen::Welcome,
            config: InstallConfig::default(),
            disks: Vec::new(),
            selected_disk: 0,
            selected_scheme: 0,
            selected_filesystem: 0,
            interfaces: Vec::new(),
            install_progress: 0.0,
            install_step: String::new(),
            error_message: None,
            should_quit: false,
            input_buffer: String::new(),
            input_focus: 0,
        }
    }

    /// Initialize the application (detect disks, interfaces, etc.)
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing installer...");

        // Detect available disks
        self.disks = crate::disk::detect_disks().await?;

        // Filter to suitable disks
        self.disks.retain(|d| d.is_suitable_target());

        if self.disks.is_empty() {
            return Err(InstallerError::RequirementNotMet(
                "No suitable disks found for installation".to_string(),
            ));
        }

        // Detect network interfaces
        self.interfaces = crate::install::network::detect_interfaces().await?;

        info!(
            "Found {} disk(s) and {} interface(s)",
            self.disks.len(),
            self.interfaces.len()
        );

        Ok(())
    }

    /// Run the TUI application
    pub async fn run(&mut self) -> Result<()> {
        // Initialize
        self.initialize().await?;

        // Setup terminal
        enable_raw_mode().map_err(|e| InstallerError::Tui(e.to_string()))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .map_err(|e| InstallerError::Tui(e.to_string()))?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal =
            Terminal::new(backend).map_err(|e| InstallerError::Tui(e.to_string()))?;

        // Run main loop
        let result = self.main_loop(&mut terminal).await;

        // Restore terminal
        disable_raw_mode().map_err(|e| InstallerError::Tui(e.to_string()))?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )
        .map_err(|e| InstallerError::Tui(e.to_string()))?;
        terminal
            .show_cursor()
            .map_err(|e| InstallerError::Tui(e.to_string()))?;

        result
    }

    /// Main event loop
    async fn main_loop(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        loop {
            // Draw current screen
            terminal
                .draw(|frame| self.draw(frame))
                .map_err(|e| InstallerError::Tui(e.to_string()))?;

            // Handle events
            if event::poll(std::time::Duration::from_millis(100))
                .map_err(|e| InstallerError::Tui(e.to_string()))?
            {
                if let Event::Key(key) = event::read().map_err(|e| InstallerError::Tui(e.to_string()))? {
                    if key.kind == KeyEventKind::Press {
                        self.handle_key(key.code).await?;
                    }
                }
            }

            // Check if we should quit
            if self.should_quit {
                return if self.current_screen == Screen::Complete {
                    Ok(())
                } else {
                    Err(InstallerError::Cancelled)
                };
            }

            // If installing, continue installation process
            if self.current_screen == Screen::Installing {
                // Installation happens in background, just update progress
                // The actual installation is triggered when entering this screen
            }
        }
    }

    /// Draw the current screen
    fn draw(&self, frame: &mut ratatui::Frame) {
        match self.current_screen {
            Screen::Welcome => welcome::draw(frame, self),
            Screen::DiskSelection => disk::draw(frame, self),
            Screen::PartitionScheme => partition::draw(frame, self),
            Screen::NetworkSetup => network::draw(frame, self),
            Screen::UserSetup => users::draw(frame, self),
            Screen::ServiceSelection => services::draw(frame, self),
            Screen::Summary => summary::draw(frame, self),
            Screen::Installing => progress::draw(frame, self),
            Screen::Complete => complete::draw(frame, self),
            Screen::Error => error::draw(frame, self),
        }
    }

    /// Handle key press
    async fn handle_key(&mut self, key: KeyCode) -> Result<()> {
        // Global keys
        match key {
            KeyCode::Char('q') if self.current_screen != Screen::Installing => {
                self.should_quit = true;
                return Ok(());
            }
            KeyCode::Esc if self.current_screen != Screen::Installing => {
                if let Some(prev) = self.current_screen.prev() {
                    self.current_screen = prev;
                } else {
                    self.should_quit = true;
                }
                return Ok(());
            }
            _ => {}
        }

        // Screen-specific handling
        match self.current_screen {
            Screen::Welcome => self.handle_welcome_key(key),
            Screen::DiskSelection => self.handle_disk_key(key),
            Screen::PartitionScheme => self.handle_partition_key(key),
            Screen::NetworkSetup => self.handle_network_key(key),
            Screen::UserSetup => self.handle_user_key(key),
            Screen::ServiceSelection => self.handle_service_key(key),
            Screen::Summary => self.handle_summary_key(key).await,
            Screen::Installing => {} // No interaction during install
            Screen::Complete => self.handle_complete_key(key),
            Screen::Error => self.handle_error_key(key),
        }

        Ok(())
    }

    fn handle_welcome_key(&mut self, key: KeyCode) {
        if matches!(key, KeyCode::Enter | KeyCode::Right) {
            self.current_screen = Screen::DiskSelection;
        }
    }

    fn handle_disk_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up => {
                if self.selected_disk > 0 {
                    self.selected_disk -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_disk < self.disks.len().saturating_sub(1) {
                    self.selected_disk += 1;
                }
            }
            KeyCode::Enter | KeyCode::Right => {
                if !self.disks.is_empty() {
                    self.config.disk.device = self.disks[self.selected_disk].path.clone();
                    self.current_screen = Screen::PartitionScheme;
                }
            }
            _ => {}
        }
    }

    fn handle_partition_key(&mut self, key: KeyCode) {
        use crate::config::PartitionScheme;
        let schemes = [
            PartitionScheme::UefiSimple,
            PartitionScheme::UefiWithSwap,
            PartitionScheme::UefiSeparateHome,
            PartitionScheme::BiosSimple,
            PartitionScheme::BiosWithSwap,
        ];

        match key {
            KeyCode::Up => {
                if self.selected_scheme > 0 {
                    self.selected_scheme -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected_scheme < schemes.len() - 1 {
                    self.selected_scheme += 1;
                }
            }
            KeyCode::Enter | KeyCode::Right => {
                self.config.disk.scheme = schemes[self.selected_scheme];
                self.current_screen = Screen::NetworkSetup;
            }
            _ => {}
        }
    }

    fn handle_network_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter | KeyCode::Right => {
                self.current_screen = Screen::UserSetup;
            }
            _ => {}
        }
    }

    fn handle_user_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter | KeyCode::Right => {
                self.current_screen = Screen::ServiceSelection;
            }
            KeyCode::Char(c) => {
                self.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.input_buffer.pop();
            }
            _ => {}
        }
    }

    fn handle_service_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up => {
                if self.input_focus > 0 {
                    self.input_focus -= 1;
                }
            }
            KeyCode::Down => {
                if self.input_focus < 4 {
                    self.input_focus += 1;
                }
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
                // Toggle service
                match self.input_focus {
                    0 => self.config.services.firewall = !self.config.services.firewall,
                    1 => self.config.services.web_ui = !self.config.services.web_ui,
                    2 => self.config.services.ssh = !self.config.services.ssh,
                    3 => self.config.services.dhcp_server = !self.config.services.dhcp_server,
                    4 => self.config.services.dns_server = !self.config.services.dns_server,
                    _ => {}
                }
            }
            KeyCode::Right => {
                self.current_screen = Screen::Summary;
            }
            _ => {}
        }
    }

    async fn handle_summary_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Enter => {
                // Start installation
                self.current_screen = Screen::Installing;
                self.start_installation().await;
            }
            _ => {}
        }
    }

    fn handle_complete_key(&mut self, key: KeyCode) {
        if matches!(key, KeyCode::Enter | KeyCode::Char('r')) {
            // Reboot
            let _ = std::process::Command::new("reboot").spawn();
        }
        if matches!(key, KeyCode::Char('q')) {
            self.should_quit = true;
        }
    }

    fn handle_error_key(&mut self, key: KeyCode) {
        if matches!(key, KeyCode::Enter | KeyCode::Esc) {
            if let Some(prev) = self.current_screen.prev() {
                self.current_screen = prev;
            }
            self.error_message = None;
        }
    }

    /// Start the installation process
    async fn start_installation(&mut self) {
        info!("Starting installation...");

        let result = self.perform_installation().await;

        match result {
            Ok(()) => {
                self.current_screen = Screen::Complete;
            }
            Err(e) => {
                self.error_message = Some(e.to_string());
                self.current_screen = Screen::Error;
            }
        }
    }

    /// Perform the actual installation
    async fn perform_installation(&mut self) -> Result<()> {
        use crate::disk::{format::format_all_partitions, partition::create_partitions};
        use crate::install::{
            bootloader::install_bootloader, configure_network, configure_services,
            mount_partitions, system::{configure_system, install_base_system},
            unmount_partitions,
        };

        // Step 1: Create partitions
        self.install_step = "Creating partitions...".to_string();
        self.install_progress = 5.0;

        let partitions = create_partitions(
            &self.config.disk.device,
            &self.config.disk.scheme,
            self.config.disk.filesystem,
            self.config.disk.swap_size_mb,
            self.config.disk.home_size_mb,
        )
        .await?;

        // Step 2: Format partitions
        self.install_step = "Formatting partitions...".to_string();
        self.install_progress = 15.0;

        format_all_partitions(&partitions).await?;

        // Step 3: Mount partitions
        self.install_step = "Mounting partitions...".to_string();
        self.install_progress = 20.0;

        mount_partitions(&partitions, &self.config.target_root).await?;

        // Step 4: Install base system
        self.install_step = "Installing base system...".to_string();
        self.install_progress = 25.0;

        install_base_system(&self.config, None).await?;

        // Step 5: Configure system
        self.install_step = "Configuring system...".to_string();
        self.install_progress = 75.0;

        configure_system(&self.config, &partitions, None).await?;

        // Step 6: Configure network
        self.install_step = "Configuring network...".to_string();
        self.install_progress = 80.0;

        configure_network(&self.config.target_root, &self.config.network).await?;

        // Step 7: Configure services
        self.install_step = "Configuring services...".to_string();
        self.install_progress = 85.0;

        configure_services(&self.config.target_root, &self.config.services, &self.config.patronus)
            .await?;

        // Step 8: Install bootloader
        self.install_step = "Installing bootloader...".to_string();
        self.install_progress = 90.0;

        install_bootloader(
            &self.config.target_root,
            self.config.system.bootloader,
            &self.config.disk.scheme,
            &self.config.disk.device,
            &partitions,
        )
        .await?;

        // Step 9: Unmount
        self.install_step = "Finalizing...".to_string();
        self.install_progress = 95.0;

        unmount_partitions(&partitions, &self.config.target_root).await?;

        self.install_step = "Installation complete!".to_string();
        self.install_progress = 100.0;

        Ok(())
    }
}

impl Default for InstallerApp {
    fn default() -> Self {
        Self::new()
    }
}
