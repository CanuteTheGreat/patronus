//! Scheduled and Time-Based Firewall Rules
//!
//! Allows firewall rules to be automatically enabled/disabled based on schedules.
//! Useful for business hours restrictions, maintenance windows, etc.

use patronus_core::{Result, Error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::{interval, Duration};
use chrono::{DateTime, Utc, Local, Datelike, Timelike, Weekday};

/// Schedule type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleType {
    /// One-time schedule (specific date/time range)
    OneTime {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
    /// Recurring daily schedule
    Daily {
        start_time: TimeOfDay,
        end_time: TimeOfDay,
    },
    /// Recurring weekly schedule
    Weekly {
        days: Vec<Weekday>,
        start_time: TimeOfDay,
        end_time: TimeOfDay,
    },
    /// Recurring monthly schedule
    Monthly {
        days: Vec<u8>,  // Day of month (1-31)
        start_time: TimeOfDay,
        end_time: TimeOfDay,
    },
    /// Custom cron expression
    Cron {
        expression: String,
    },
    /// Always active
    Always,
}

/// Time of day (hours and minutes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeOfDay {
    pub hour: u8,    // 0-23
    pub minute: u8,  // 0-59
}

impl TimeOfDay {
    pub fn new(hour: u8, minute: u8) -> Self {
        Self { hour, minute }
    }

    pub fn now() -> Self {
        let now = Local::now();
        Self {
            hour: now.hour() as u8,
            minute: now.minute() as u8,
        }
    }

    /// Check if this time is between start and end
    pub fn is_between(&self, start: TimeOfDay, end: TimeOfDay) -> bool {
        let current_mins = self.hour as u32 * 60 + self.minute as u32;
        let start_mins = start.hour as u32 * 60 + start.minute as u32;
        let end_mins = end.hour as u32 * 60 + end.minute as u32;

        if start_mins <= end_mins {
            // Same day: 09:00 - 17:00
            current_mins >= start_mins && current_mins < end_mins
        } else {
            // Crosses midnight: 22:00 - 06:00
            current_mins >= start_mins || current_mins < end_mins
        }
    }
}

/// Schedule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub schedule_type: ScheduleType,
    pub enabled: bool,
    pub timezone: Option<String>,  // IANA timezone (e.g., "America/New_York")
}

/// Scheduled rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRule {
    pub id: String,
    pub rule_id: String,  // Reference to firewall rule
    pub schedule_id: String,  // Reference to schedule
    pub action: ScheduleAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleAction {
    /// Enable rule when schedule is active
    Enable,
    /// Disable rule when schedule is active
    Disable,
    /// Invert rule action when schedule is active
    Invert,
}

/// Schedule state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleState {
    pub schedule_id: String,
    pub active: bool,
    pub last_checked: DateTime<Utc>,
    pub next_transition: Option<DateTime<Utc>>,
}

pub struct SchedulerManager {
    schedules: HashMap<String, Schedule>,
    scheduled_rules: HashMap<String, ScheduledRule>,
    states: HashMap<String, ScheduleState>,
}

impl SchedulerManager {
    pub fn new() -> Self {
        Self {
            schedules: HashMap::new(),
            scheduled_rules: HashMap::new(),
            states: HashMap::new(),
        }
    }

    /// Add a schedule
    pub fn add_schedule(&mut self, schedule: Schedule) -> Result<()> {
        let id = schedule.id.clone();
        self.schedules.insert(id.clone(), schedule);
        self.states.insert(id.clone(), ScheduleState {
            schedule_id: id,
            active: false,
            last_checked: Utc::now(),
            next_transition: None,
        });
        Ok(())
    }

    /// Remove a schedule
    pub fn remove_schedule(&mut self, schedule_id: &str) -> Result<()> {
        self.schedules.remove(schedule_id);
        self.states.remove(schedule_id);
        Ok(())
    }

    /// Add a scheduled rule
    pub fn add_scheduled_rule(&mut self, rule: ScheduledRule) -> Result<()> {
        self.scheduled_rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    /// Remove a scheduled rule
    pub fn remove_scheduled_rule(&mut self, rule_id: &str) -> Result<()> {
        self.scheduled_rules.remove(rule_id);
        Ok(())
    }

    /// Check if a schedule is currently active
    pub fn is_schedule_active(&self, schedule_id: &str) -> Result<bool> {
        let schedule = self.schedules.get(schedule_id)
            .ok_or_else(|| Error::Config(format!("Schedule {} not found", schedule_id)))?;

        if !schedule.enabled {
            return Ok(false);
        }

        Ok(self.evaluate_schedule(&schedule.schedule_type))
    }

    /// Evaluate schedule condition
    fn evaluate_schedule(&self, schedule_type: &ScheduleType) -> bool {
        match schedule_type {
            ScheduleType::Always => true,

            ScheduleType::OneTime { start, end } => {
                let now = Utc::now();
                now >= *start && now < *end
            }

            ScheduleType::Daily { start_time, end_time } => {
                let current_time = TimeOfDay::now();
                current_time.is_between(*start_time, *end_time)
            }

            ScheduleType::Weekly { days, start_time, end_time } => {
                let now = Local::now();
                let current_weekday = now.weekday();
                let current_time = TimeOfDay::now();

                days.contains(&current_weekday) &&
                    current_time.is_between(*start_time, *end_time)
            }

            ScheduleType::Monthly { days, start_time, end_time } => {
                let now = Local::now();
                let current_day = now.day() as u8;
                let current_time = TimeOfDay::now();

                days.contains(&current_day) &&
                    current_time.is_between(*start_time, *end_time)
            }

            ScheduleType::Cron { expression } => {
                // Would use cron parser library in production
                self.evaluate_cron(expression)
            }
        }
    }

    fn evaluate_cron(&self, _expression: &str) -> bool {
        // Simplified - would use cron crate
        false
    }

    /// Update schedule states
    pub async fn update_states(&mut self) -> Result<()> {
        for (id, schedule) in &self.schedules {
            let active = self.evaluate_schedule(&schedule.schedule_type);

            if let Some(state) = self.states.get_mut(id) {
                state.active = active;
                state.last_checked = Utc::now();
            }
        }

        Ok(())
    }

    /// Get rules that need to be applied based on current schedules
    pub async fn get_active_rules(&self) -> Result<Vec<String>> {
        let mut active_rules = Vec::new();

        for (_, scheduled_rule) in &self.scheduled_rules {
            if !scheduled_rule.enabled {
                continue;
            }

            let schedule_active = self.is_schedule_active(&scheduled_rule.schedule_id)?;

            let should_enable = match scheduled_rule.action {
                ScheduleAction::Enable => schedule_active,
                ScheduleAction::Disable => !schedule_active,
                ScheduleAction::Invert => schedule_active,
            };

            if should_enable {
                active_rules.push(scheduled_rule.rule_id.clone());
            }
        }

        Ok(active_rules)
    }

    /// Start scheduler background task
    pub async fn start_scheduler(&mut self) -> Result<()> {
        tracing::info!("Starting firewall rule scheduler");

        let mut check_interval = interval(Duration::from_secs(60));  // Check every minute

        loop {
            check_interval.tick().await;

            if let Err(e) = self.update_states().await {
                tracing::error!("Error updating schedule states: {}", e);
            }

            // Apply scheduled rules
            if let Err(e) = self.apply_scheduled_rules().await {
                tracing::error!("Error applying scheduled rules: {}", e);
            }
        }
    }

    /// Apply scheduled rules to firewall
    async fn apply_scheduled_rules(&self) -> Result<()> {
        let active_rules = self.get_active_rules().await?;

        tracing::debug!("Active scheduled rules: {:?}", active_rules);

        // Here we would interface with the firewall manager to enable/disable rules
        // For now, just log what we would do

        for rule_id in active_rules {
            tracing::info!("Activating scheduled rule: {}", rule_id);
            // firewall_manager.enable_rule(&rule_id).await?;
        }

        Ok(())
    }

    /// Get all schedules
    pub fn get_schedules(&self) -> Vec<&Schedule> {
        self.schedules.values().collect()
    }

    /// Get schedule by ID
    pub fn get_schedule(&self, id: &str) -> Option<&Schedule> {
        self.schedules.get(id)
    }

    /// Get schedule state
    pub fn get_state(&self, id: &str) -> Option<&ScheduleState> {
        self.states.get(id)
    }
}

/// Predefined schedule templates
pub struct ScheduleTemplates;

impl ScheduleTemplates {
    /// Business hours (Monday-Friday, 9am-5pm)
    pub fn business_hours() -> Schedule {
        Schedule {
            id: "business_hours".to_string(),
            name: "Business Hours".to_string(),
            description: Some("Monday-Friday, 9:00 AM - 5:00 PM".to_string()),
            schedule_type: ScheduleType::Weekly {
                days: vec![
                    Weekday::Mon,
                    Weekday::Tue,
                    Weekday::Wed,
                    Weekday::Thu,
                    Weekday::Fri,
                ],
                start_time: TimeOfDay::new(9, 0),
                end_time: TimeOfDay::new(17, 0),
            },
            enabled: true,
            timezone: None,
        }
    }

    /// After hours (Monday-Friday, 5pm-9am)
    pub fn after_hours() -> Schedule {
        Schedule {
            id: "after_hours".to_string(),
            name: "After Hours".to_string(),
            description: Some("Monday-Friday, 5:00 PM - 9:00 AM".to_string()),
            schedule_type: ScheduleType::Weekly {
                days: vec![
                    Weekday::Mon,
                    Weekday::Tue,
                    Weekday::Wed,
                    Weekday::Thu,
                    Weekday::Fri,
                ],
                start_time: TimeOfDay::new(17, 0),
                end_time: TimeOfDay::new(9, 0),
            },
            enabled: true,
            timezone: None,
        }
    }

    /// Weekends (Saturday-Sunday, all day)
    pub fn weekends() -> Schedule {
        Schedule {
            id: "weekends".to_string(),
            name: "Weekends".to_string(),
            description: Some("Saturday and Sunday, all day".to_string()),
            schedule_type: ScheduleType::Weekly {
                days: vec![Weekday::Sat, Weekday::Sun],
                start_time: TimeOfDay::new(0, 0),
                end_time: TimeOfDay::new(23, 59),
            },
            enabled: true,
            timezone: None,
        }
    }

    /// Nighttime (10pm-6am, every day)
    pub fn nighttime() -> Schedule {
        Schedule {
            id: "nighttime".to_string(),
            name: "Nighttime".to_string(),
            description: Some("Every day, 10:00 PM - 6:00 AM".to_string()),
            schedule_type: ScheduleType::Daily {
                start_time: TimeOfDay::new(22, 0),
                end_time: TimeOfDay::new(6, 0),
            },
            enabled: true,
            timezone: None,
        }
    }

    /// Maintenance window (Sunday 2am-4am)
    pub fn maintenance_window() -> Schedule {
        Schedule {
            id: "maintenance".to_string(),
            name: "Maintenance Window".to_string(),
            description: Some("Sunday, 2:00 AM - 4:00 AM".to_string()),
            schedule_type: ScheduleType::Weekly {
                days: vec![Weekday::Sun],
                start_time: TimeOfDay::new(2, 0),
                end_time: TimeOfDay::new(4, 0),
            },
            enabled: true,
            timezone: None,
        }
    }
}

/// Example use cases for scheduled rules
pub struct ScheduleExamples;

impl ScheduleExamples {
    /// Block social media during business hours
    pub fn example_block_social_media() -> (Schedule, ScheduledRule) {
        let schedule = ScheduleTemplates::business_hours();

        let rule = ScheduledRule {
            id: "block_social_media_schedule".to_string(),
            rule_id: "block_social_media".to_string(),  // References actual firewall rule
            schedule_id: schedule.id.clone(),
            action: ScheduleAction::Enable,
            enabled: true,
        };

        (schedule, rule)
    }

    /// Allow VPN access only during business hours
    pub fn example_vpn_business_hours() -> (Schedule, ScheduledRule) {
        let schedule = ScheduleTemplates::business_hours();

        let rule = ScheduledRule {
            id: "vpn_business_hours_schedule".to_string(),
            rule_id: "allow_vpn".to_string(),
            schedule_id: schedule.id.clone(),
            action: ScheduleAction::Enable,
            enabled: true,
        };

        (schedule, rule)
    }

    /// Strict firewall during maintenance window
    pub fn example_maintenance_lockdown() -> (Schedule, ScheduledRule) {
        let schedule = ScheduleTemplates::maintenance_window();

        let rule = ScheduledRule {
            id: "maintenance_lockdown_schedule".to_string(),
            rule_id: "deny_all_except_admin".to_string(),
            schedule_id: schedule.id.clone(),
            action: ScheduleAction::Enable,
            enabled: true,
        };

        (schedule, rule)
    }

    /// Guest WiFi only during business hours
    pub fn example_guest_wifi_hours() -> (Schedule, ScheduledRule) {
        let schedule = ScheduleTemplates::business_hours();

        let rule = ScheduledRule {
            id: "guest_wifi_schedule".to_string(),
            rule_id: "guest_wifi_access".to_string(),
            schedule_id: schedule.id.clone(),
            action: ScheduleAction::Enable,
            enabled: true,
        };

        (schedule, rule)
    }

    /// Bandwidth limits during business hours
    pub fn example_bandwidth_limits() -> (Schedule, ScheduledRule) {
        let schedule = ScheduleTemplates::business_hours();

        let rule = ScheduledRule {
            id: "bandwidth_limits_schedule".to_string(),
            rule_id: "qos_strict_limits".to_string(),
            schedule_id: schedule.id.clone(),
            action: ScheduleAction::Enable,
            enabled: true,
        };

        (schedule, rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_of_day_is_between() {
        // Test same-day range
        let current = TimeOfDay::new(12, 30);
        let start = TimeOfDay::new(9, 0);
        let end = TimeOfDay::new(17, 0);
        assert!(current.is_between(start, end));

        // Test outside range
        let current = TimeOfDay::new(18, 0);
        assert!(!current.is_between(start, end));

        // Test midnight-crossing range
        let current = TimeOfDay::new(23, 0);
        let start = TimeOfDay::new(22, 0);
        let end = TimeOfDay::new(6, 0);
        assert!(current.is_between(start, end));

        let current = TimeOfDay::new(3, 0);
        assert!(current.is_between(start, end));

        let current = TimeOfDay::new(12, 0);
        assert!(!current.is_between(start, end));
    }

    #[test]
    fn test_schedule_templates() {
        let business_hours = ScheduleTemplates::business_hours();
        assert_eq!(business_hours.id, "business_hours");

        match business_hours.schedule_type {
            ScheduleType::Weekly { ref days, .. } => {
                assert_eq!(days.len(), 5);
                assert!(days.contains(&Weekday::Mon));
                assert!(!days.contains(&Weekday::Sat));
            }
            _ => panic!("Expected Weekly schedule"),
        }
    }
}
