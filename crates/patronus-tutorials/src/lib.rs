//! Interactive Tutorials for Patronus SD-WAN
//!
//! Step-by-step guided tutorials for learning and deploying SD-WAN

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod lesson;
pub mod progress;
pub mod quiz;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TutorialDifficulty {
    Beginner,
    Intermediate,
    Advanced,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepType {
    Reading,
    Practice,
    Quiz,
    Lab,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TutorialStep {
    pub id: Uuid,
    pub step_number: usize,
    pub title: String,
    pub content: String,
    pub step_type: StepType,
    pub code_example: Option<String>,
    pub expected_output: Option<String>,
}

impl TutorialStep {
    pub fn new(step_number: usize, title: String, content: String, step_type: StepType) -> Self {
        Self {
            id: Uuid::new_v4(),
            step_number,
            title,
            content,
            step_type,
            code_example: None,
            expected_output: None,
        }
    }

    pub fn with_code_example(mut self, code: String) -> Self {
        self.code_example = Some(code);
        self
    }

    pub fn with_expected_output(mut self, output: String) -> Self {
        self.expected_output = Some(output);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tutorial {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub difficulty: TutorialDifficulty,
    pub duration_minutes: u32,
    pub steps: Vec<TutorialStep>,
    pub prerequisites: Vec<String>,
}

impl Tutorial {
    pub fn new(
        title: String,
        description: String,
        difficulty: TutorialDifficulty,
        duration_minutes: u32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            title,
            description,
            difficulty,
            duration_minutes,
            steps: Vec::new(),
            prerequisites: Vec::new(),
        }
    }

    pub fn add_step(&mut self, step: TutorialStep) {
        self.steps.push(step);
    }

    pub fn add_prerequisite(&mut self, prereq: String) {
        self.prerequisites.push(prereq);
    }

    pub fn total_steps(&self) -> usize {
        self.steps.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProgress {
    pub user_id: Uuid,
    pub tutorial_id: Uuid,
    pub completed_steps: Vec<Uuid>,
    pub current_step: usize,
    pub started_at: String,
    pub completed_at: Option<String>,
}

impl UserProgress {
    pub fn new(user_id: Uuid, tutorial_id: Uuid) -> Self {
        Self {
            user_id,
            tutorial_id,
            completed_steps: Vec::new(),
            current_step: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
            completed_at: None,
        }
    }

    pub fn complete_step(&mut self, step_id: Uuid) {
        if !self.completed_steps.contains(&step_id) {
            self.completed_steps.push(step_id);
            self.current_step += 1;
        }
    }

    pub fn is_completed(&self, total_steps: usize) -> bool {
        self.completed_steps.len() == total_steps
    }

    pub fn progress_percentage(&self, total_steps: usize) -> f64 {
        if total_steps == 0 {
            return 0.0;
        }
        (self.completed_steps.len() as f64 / total_steps as f64) * 100.0
    }

    pub fn mark_completed(&mut self) {
        self.completed_at = Some(chrono::Utc::now().to_rfc3339());
    }
}

pub struct TutorialManager {
    tutorials: Arc<RwLock<HashMap<Uuid, Tutorial>>>,
    progress: Arc<RwLock<HashMap<(Uuid, Uuid), UserProgress>>>,
}

impl TutorialManager {
    pub fn new() -> Self {
        Self {
            tutorials: Arc::new(RwLock::new(HashMap::new())),
            progress: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_tutorial(&self, tutorial: Tutorial) -> Uuid {
        let id = tutorial.id;
        let mut tutorials = self.tutorials.write().await;
        tutorials.insert(id, tutorial);
        id
    }

    pub async fn get_tutorial(&self, id: &Uuid) -> Option<Tutorial> {
        let tutorials = self.tutorials.read().await;
        tutorials.get(id).cloned()
    }

    pub async fn list_tutorials(&self) -> Vec<Tutorial> {
        let tutorials = self.tutorials.read().await;
        tutorials.values().cloned().collect()
    }

    pub async fn list_by_difficulty(&self, difficulty: &TutorialDifficulty) -> Vec<Tutorial> {
        let tutorials = self.tutorials.read().await;
        tutorials
            .values()
            .filter(|t| &t.difficulty == difficulty)
            .cloned()
            .collect()
    }

    pub async fn start_tutorial(&self, user_id: Uuid, tutorial_id: Uuid) -> bool {
        let tutorials = self.tutorials.read().await;
        if !tutorials.contains_key(&tutorial_id) {
            return false;
        }
        drop(tutorials);

        let progress = UserProgress::new(user_id, tutorial_id);
        let mut progress_map = self.progress.write().await;
        progress_map.insert((user_id, tutorial_id), progress);
        true
    }

    pub async fn get_progress(&self, user_id: &Uuid, tutorial_id: &Uuid) -> Option<UserProgress> {
        let progress = self.progress.read().await;
        progress.get(&(*user_id, *tutorial_id)).cloned()
    }

    pub async fn complete_step(&self, user_id: &Uuid, tutorial_id: &Uuid, step_id: Uuid) -> bool {
        let mut progress = self.progress.write().await;
        if let Some(user_progress) = progress.get_mut(&(*user_id, *tutorial_id)) {
            user_progress.complete_step(step_id);

            // Check if tutorial is completed
            let tutorials = self.tutorials.read().await;
            if let Some(tutorial) = tutorials.get(tutorial_id) {
                if user_progress.is_completed(tutorial.total_steps()) {
                    user_progress.mark_completed();
                }
            }

            true
        } else {
            false
        }
    }

    pub async fn get_user_tutorials(&self, user_id: &Uuid) -> Vec<(Tutorial, UserProgress)> {
        let progress_map = self.progress.read().await;
        let tutorials = self.tutorials.read().await;

        let mut result = Vec::new();
        for ((uid, tid), progress) in progress_map.iter() {
            if uid == user_id {
                if let Some(tutorial) = tutorials.get(tid) {
                    result.push((tutorial.clone(), progress.clone()));
                }
            }
        }
        result
    }

    pub async fn get_completed_count(&self, user_id: &Uuid) -> usize {
        let progress_map = self.progress.read().await;
        progress_map
            .iter()
            .filter(|((uid, _), p)| uid == user_id && p.completed_at.is_some())
            .count()
    }
}

impl Default for TutorialManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tutorial_step_creation() {
        let step = TutorialStep::new(
            1,
            "Introduction".to_string(),
            "Welcome to Patronus".to_string(),
            StepType::Reading,
        );

        assert_eq!(step.step_number, 1);
        assert_eq!(step.title, "Introduction");
        assert_eq!(step.step_type, StepType::Reading);
    }

    #[test]
    fn test_tutorial_step_with_code() {
        let step = TutorialStep::new(
            1,
            "Setup".to_string(),
            "Install Patronus".to_string(),
            StepType::Practice,
        )
        .with_code_example("cargo install patronus".to_string())
        .with_expected_output("Installed successfully".to_string());

        assert!(step.code_example.is_some());
        assert!(step.expected_output.is_some());
    }

    #[test]
    fn test_tutorial_creation() {
        let tutorial = Tutorial::new(
            "Getting Started".to_string(),
            "Learn the basics".to_string(),
            TutorialDifficulty::Beginner,
            30,
        );

        assert_eq!(tutorial.title, "Getting Started");
        assert_eq!(tutorial.difficulty, TutorialDifficulty::Beginner);
        assert_eq!(tutorial.duration_minutes, 30);
    }

    #[test]
    fn test_tutorial_add_step() {
        let mut tutorial = Tutorial::new(
            "Test".to_string(),
            "Desc".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );

        let step = TutorialStep::new(
            1,
            "Step 1".to_string(),
            "Content".to_string(),
            StepType::Reading,
        );

        tutorial.add_step(step);
        assert_eq!(tutorial.total_steps(), 1);
    }

    #[test]
    fn test_user_progress_creation() {
        let user_id = Uuid::new_v4();
        let tutorial_id = Uuid::new_v4();

        let progress = UserProgress::new(user_id, tutorial_id);

        assert_eq!(progress.user_id, user_id);
        assert_eq!(progress.tutorial_id, tutorial_id);
        assert_eq!(progress.current_step, 0);
        assert!(progress.completed_at.is_none());
    }

    #[test]
    fn test_complete_step() {
        let user_id = Uuid::new_v4();
        let tutorial_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();

        let mut progress = UserProgress::new(user_id, tutorial_id);
        progress.complete_step(step_id);

        assert_eq!(progress.completed_steps.len(), 1);
        assert_eq!(progress.current_step, 1);
    }

    #[test]
    fn test_progress_percentage() {
        let user_id = Uuid::new_v4();
        let tutorial_id = Uuid::new_v4();

        let mut progress = UserProgress::new(user_id, tutorial_id);

        assert_eq!(progress.progress_percentage(10), 0.0);

        progress.complete_step(Uuid::new_v4());
        assert_eq!(progress.progress_percentage(10), 10.0);

        progress.complete_step(Uuid::new_v4());
        progress.complete_step(Uuid::new_v4());
        assert_eq!(progress.progress_percentage(10), 30.0);
    }

    #[test]
    fn test_is_completed() {
        let user_id = Uuid::new_v4();
        let tutorial_id = Uuid::new_v4();

        let mut progress = UserProgress::new(user_id, tutorial_id);

        assert!(!progress.is_completed(3));

        progress.complete_step(Uuid::new_v4());
        progress.complete_step(Uuid::new_v4());
        progress.complete_step(Uuid::new_v4());

        assert!(progress.is_completed(3));
    }

    #[tokio::test]
    async fn test_tutorial_manager_add() {
        let manager = TutorialManager::new();

        let tutorial = Tutorial::new(
            "Test".to_string(),
            "Desc".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );
        let id = tutorial.id;

        manager.add_tutorial(tutorial).await;

        let retrieved = manager.get_tutorial(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().title, "Test");
    }

    #[tokio::test]
    async fn test_tutorial_manager_list() {
        let manager = TutorialManager::new();

        let tutorial1 = Tutorial::new(
            "Tutorial 1".to_string(),
            "Desc 1".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );

        let tutorial2 = Tutorial::new(
            "Tutorial 2".to_string(),
            "Desc 2".to_string(),
            TutorialDifficulty::Intermediate,
            30,
        );

        manager.add_tutorial(tutorial1).await;
        manager.add_tutorial(tutorial2).await;

        let list = manager.list_tutorials().await;
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn test_list_by_difficulty() {
        let manager = TutorialManager::new();

        let tutorial1 = Tutorial::new(
            "Beginner 1".to_string(),
            "Desc".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );

        let tutorial2 = Tutorial::new(
            "Advanced 1".to_string(),
            "Desc".to_string(),
            TutorialDifficulty::Advanced,
            60,
        );

        manager.add_tutorial(tutorial1).await;
        manager.add_tutorial(tutorial2).await;

        let beginners = manager.list_by_difficulty(&TutorialDifficulty::Beginner).await;
        assert_eq!(beginners.len(), 1);
        assert_eq!(beginners[0].title, "Beginner 1");
    }

    #[tokio::test]
    async fn test_start_tutorial() {
        let manager = TutorialManager::new();

        let tutorial = Tutorial::new(
            "Test".to_string(),
            "Desc".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );
        let tutorial_id = tutorial.id;
        let user_id = Uuid::new_v4();

        manager.add_tutorial(tutorial).await;
        assert!(manager.start_tutorial(user_id, tutorial_id).await);

        let progress = manager.get_progress(&user_id, &tutorial_id).await;
        assert!(progress.is_some());
    }

    #[tokio::test]
    async fn test_complete_step_tracking() {
        let manager = TutorialManager::new();

        let mut tutorial = Tutorial::new(
            "Test".to_string(),
            "Desc".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );

        let step = TutorialStep::new(
            1,
            "Step 1".to_string(),
            "Content".to_string(),
            StepType::Reading,
        );
        let step_id = step.id;
        tutorial.add_step(step);

        let tutorial_id = tutorial.id;
        let user_id = Uuid::new_v4();

        manager.add_tutorial(tutorial).await;
        manager.start_tutorial(user_id, tutorial_id).await;

        assert!(manager.complete_step(&user_id, &tutorial_id, step_id).await);

        let progress = manager.get_progress(&user_id, &tutorial_id).await.unwrap();
        assert_eq!(progress.completed_steps.len(), 1);
    }

    #[tokio::test]
    async fn test_get_user_tutorials() {
        let manager = TutorialManager::new();

        let tutorial1 = Tutorial::new(
            "T1".to_string(),
            "D1".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );
        let tutorial2 = Tutorial::new(
            "T2".to_string(),
            "D2".to_string(),
            TutorialDifficulty::Intermediate,
            30,
        );

        let t1_id = tutorial1.id;
        let t2_id = tutorial2.id;
        let user_id = Uuid::new_v4();

        manager.add_tutorial(tutorial1).await;
        manager.add_tutorial(tutorial2).await;

        manager.start_tutorial(user_id, t1_id).await;
        manager.start_tutorial(user_id, t2_id).await;

        let user_tutorials = manager.get_user_tutorials(&user_id).await;
        assert_eq!(user_tutorials.len(), 2);
    }

    #[tokio::test]
    async fn test_get_completed_count() {
        let manager = TutorialManager::new();

        let mut tutorial = Tutorial::new(
            "Test".to_string(),
            "Desc".to_string(),
            TutorialDifficulty::Beginner,
            15,
        );

        let step = TutorialStep::new(
            1,
            "Step 1".to_string(),
            "Content".to_string(),
            StepType::Reading,
        );
        let step_id = step.id;
        tutorial.add_step(step);

        let tutorial_id = tutorial.id;
        let user_id = Uuid::new_v4();

        manager.add_tutorial(tutorial).await;
        manager.start_tutorial(user_id, tutorial_id).await;
        manager.complete_step(&user_id, &tutorial_id, step_id).await;

        let count = manager.get_completed_count(&user_id).await;
        assert_eq!(count, 1);
    }
}
