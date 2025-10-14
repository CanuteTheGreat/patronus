//! Ansible Playbook Generation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Play {
    pub name: String,
    pub hosts: String,
    pub tasks: Vec<Task>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub vars: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub name: String,
    #[serde(flatten)]
    pub module: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    #[serde(flatten)]
    pub plays: Vec<Play>,
}

impl Playbook {
    pub fn new() -> Self {
        Self { plays: Vec::new() }
    }

    pub fn add_play(&mut self, play: Play) {
        self.plays.push(play);
    }

    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(&self.plays)
    }
}

impl Default for Playbook {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PlaybookBuilder {
    playbook: Playbook,
    current_play: Option<Play>,
}

impl PlaybookBuilder {
    pub fn new() -> Self {
        Self {
            playbook: Playbook::new(),
            current_play: None,
        }
    }

    pub fn play(mut self, name: String, hosts: String) -> Self {
        if let Some(play) = self.current_play.take() {
            self.playbook.add_play(play);
        }
        self.current_play = Some(Play {
            name,
            hosts,
            tasks: Vec::new(),
            vars: HashMap::new(),
        });
        self
    }

    pub fn task(mut self, name: String, module: String, params: HashMap<String, serde_json::Value>) -> Self {
        if let Some(ref mut play) = self.current_play {
            let mut module_map = HashMap::new();
            module_map.insert(module, serde_json::to_value(params).unwrap());

            play.tasks.push(Task {
                name,
                module: module_map,
                when: None,
                register: None,
            });
        }
        self
    }

    pub fn var(mut self, key: String, value: serde_json::Value) -> Self {
        if let Some(ref mut play) = self.current_play {
            play.vars.insert(key, value);
        }
        self
    }

    pub fn build(mut self) -> Playbook {
        if let Some(play) = self.current_play.take() {
            self.playbook.add_play(play);
        }
        self.playbook
    }
}

impl Default for PlaybookBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_creation() {
        let playbook = Playbook::new();
        assert_eq!(playbook.plays.len(), 0);
    }

    #[test]
    fn test_add_play() {
        let mut playbook = Playbook::new();
        let play = Play {
            name: "Setup".to_string(),
            hosts: "all".to_string(),
            tasks: Vec::new(),
            vars: HashMap::new(),
        };

        playbook.add_play(play);
        assert_eq!(playbook.plays.len(), 1);
    }

    #[test]
    fn test_playbook_builder() {
        let mut params = HashMap::new();
        params.insert("name".to_string(), serde_json::json!("site1"));
        params.insert("state".to_string(), serde_json::json!("present"));

        let playbook = PlaybookBuilder::new()
            .play("Deploy Site".to_string(), "all".to_string())
            .task("Create site".to_string(), "patronus_site".to_string(), params)
            .build();

        assert_eq!(playbook.plays.len(), 1);
        assert_eq!(playbook.plays[0].tasks.len(), 1);
    }

    #[test]
    fn test_playbook_builder_with_vars() {
        let playbook = PlaybookBuilder::new()
            .play("Deploy".to_string(), "all".to_string())
            .var("env".to_string(), serde_json::json!("production"))
            .build();

        assert_eq!(playbook.plays[0].vars.len(), 1);
    }

    #[test]
    fn test_playbook_builder_multiple_plays() {
        let playbook = PlaybookBuilder::new()
            .play("Setup".to_string(), "webservers".to_string())
            .play("Deploy".to_string(), "databases".to_string())
            .build();

        assert_eq!(playbook.plays.len(), 2);
        assert_eq!(playbook.plays[0].name, "Setup");
        assert_eq!(playbook.plays[1].name, "Deploy");
    }

    #[test]
    fn test_playbook_to_yaml() {
        let play = Play {
            name: "Test".to_string(),
            hosts: "all".to_string(),
            tasks: Vec::new(),
            vars: HashMap::new(),
        };

        let mut playbook = Playbook::new();
        playbook.add_play(play);

        let yaml = playbook.to_yaml();
        assert!(yaml.is_ok());
        let yaml_str = yaml.unwrap();
        assert!(yaml_str.contains("name: Test"));
        assert!(yaml_str.contains("hosts: all"));
    }
}
