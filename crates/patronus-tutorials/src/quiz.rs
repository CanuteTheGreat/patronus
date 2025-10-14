//! Quiz and assessment system

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizQuestion {
    pub id: Uuid,
    pub question: String,
    pub options: Vec<String>,
    pub correct_answer: usize,
}

impl QuizQuestion {
    pub fn new(question: String, options: Vec<String>, correct_answer: usize) -> Self {
        Self {
            id: Uuid::new_v4(),
            question,
            options,
            correct_answer,
        }
    }

    pub fn check_answer(&self, answer: usize) -> bool {
        answer == self.correct_answer
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quiz {
    pub id: Uuid,
    pub title: String,
    pub questions: Vec<QuizQuestion>,
    pub passing_score: u32,
}

impl Quiz {
    pub fn new(title: String, passing_score: u32) -> Self {
        Self {
            id: Uuid::new_v4(),
            title,
            questions: Vec::new(),
            passing_score,
        }
    }

    pub fn add_question(&mut self, question: QuizQuestion) {
        self.questions.push(question);
    }

    pub fn grade(&self, answers: &[usize]) -> u32 {
        let mut score = 0;
        for (i, answer) in answers.iter().enumerate() {
            if i < self.questions.len() && self.questions[i].check_answer(*answer) {
                score += 1;
            }
        }
        score
    }

    pub fn passed(&self, answers: &[usize]) -> bool {
        let score = self.grade(answers);
        let total = self.questions.len() as u32;
        if total == 0 {
            return false;
        }
        (score * 100 / total) >= self.passing_score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quiz_question() {
        let question = QuizQuestion::new(
            "What is 2+2?".to_string(),
            vec!["3".to_string(), "4".to_string(), "5".to_string()],
            1,
        );

        assert!(!question.check_answer(0));
        assert!(question.check_answer(1));
        assert!(!question.check_answer(2));
    }

    #[test]
    fn test_quiz_creation() {
        let quiz = Quiz::new("Math Quiz".to_string(), 70);
        assert_eq!(quiz.title, "Math Quiz");
        assert_eq!(quiz.passing_score, 70);
        assert_eq!(quiz.questions.len(), 0);
    }

    #[test]
    fn test_quiz_add_question() {
        let mut quiz = Quiz::new("Test".to_string(), 70);
        let question = QuizQuestion::new(
            "Question 1".to_string(),
            vec!["A".to_string(), "B".to_string()],
            0,
        );

        quiz.add_question(question);
        assert_eq!(quiz.questions.len(), 1);
    }

    #[test]
    fn test_quiz_grading() {
        let mut quiz = Quiz::new("Test".to_string(), 70);

        quiz.add_question(QuizQuestion::new(
            "Q1".to_string(),
            vec!["A".to_string(), "B".to_string()],
            0,
        ));

        quiz.add_question(QuizQuestion::new(
            "Q2".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1,
        ));

        let score = quiz.grade(&[0, 1]);
        assert_eq!(score, 2);

        let score = quiz.grade(&[0, 0]);
        assert_eq!(score, 1);
    }

    #[test]
    fn test_quiz_passing() {
        let mut quiz = Quiz::new("Test".to_string(), 70);

        quiz.add_question(QuizQuestion::new(
            "Q1".to_string(),
            vec!["A".to_string(), "B".to_string()],
            0,
        ));

        quiz.add_question(QuizQuestion::new(
            "Q2".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1,
        ));

        assert!(quiz.passed(&[0, 1])); // 100%
        assert!(!quiz.passed(&[0, 0])); // 50% but passing_score is 70, this should fail
        assert!(!quiz.passed(&[1, 0])); // 0%
    }

    #[test]
    fn test_quiz_passing_score_check() {
        let mut quiz = Quiz::new("Test".to_string(), 50);

        quiz.add_question(QuizQuestion::new(
            "Q1".to_string(),
            vec!["A".to_string(), "B".to_string()],
            0,
        ));

        quiz.add_question(QuizQuestion::new(
            "Q2".to_string(),
            vec!["A".to_string(), "B".to_string()],
            1,
        ));

        assert!(quiz.passed(&[0, 0])); // 50% - should pass with 50% threshold
        assert!(!quiz.passed(&[1, 0])); // 0% - should fail
    }
}
