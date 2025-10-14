//! Lesson content management

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lesson {
    pub title: String,
    pub content: String,
    pub examples: Vec<String>,
}

impl Lesson {
    pub fn new(title: String, content: String) -> Self {
        Self {
            title,
            content,
            examples: Vec::new(),
        }
    }

    pub fn add_example(&mut self, example: String) {
        self.examples.push(example);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lesson_creation() {
        let lesson = Lesson::new("Test".to_string(), "Content".to_string());
        assert_eq!(lesson.title, "Test");
        assert_eq!(lesson.examples.len(), 0);
    }

    #[test]
    fn test_add_example() {
        let mut lesson = Lesson::new("Test".to_string(), "Content".to_string());
        lesson.add_example("Example 1".to_string());
        assert_eq!(lesson.examples.len(), 1);
    }
}
