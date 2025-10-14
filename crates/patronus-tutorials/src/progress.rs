//! Progress tracking utilities

use uuid::Uuid;

pub struct ProgressTracker {
    completed: Vec<Uuid>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            completed: Vec::new(),
        }
    }

    pub fn mark_complete(&mut self, id: Uuid) {
        if !self.completed.contains(&id) {
            self.completed.push(id);
        }
    }

    pub fn is_complete(&self, id: &Uuid) -> bool {
        self.completed.contains(id)
    }

    pub fn total_completed(&self) -> usize {
        self.completed.len()
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_tracker() {
        let mut tracker = ProgressTracker::new();
        let id = Uuid::new_v4();

        assert!(!tracker.is_complete(&id));
        tracker.mark_complete(id);
        assert!(tracker.is_complete(&id));
        assert_eq!(tracker.total_completed(), 1);
    }
}
