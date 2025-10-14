//! Grafana Dashboard Definitions

use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrafanaDashboard {
    pub title: String,
    pub panels: Vec<Panel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Panel {
    pub title: String,
    pub panel_type: PanelType,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PanelType {
    Graph,
    Stat,
    Table,
    Heatmap,
}

impl GrafanaDashboard {
    pub fn network_overview() -> Self {
        Self {
            title: "Patronus Network Overview".to_string(),
            panels: vec![
                Panel {
                    title: "Throughput".to_string(),
                    panel_type: PanelType::Graph,
                    targets: vec![
                        "rate(patronus_bytes_total[5m])".to_string(),
                    ],
                },
                Panel {
                    title: "Packet Loss".to_string(),
                    panel_type: PanelType::Graph,
                    targets: vec![
                        "patronus_packet_loss".to_string(),
                    ],
                },
                Panel {
                    title: "Latency P95".to_string(),
                    panel_type: PanelType::Graph,
                    targets: vec![
                        "histogram_quantile(0.95, patronus_latency_ms)".to_string(),
                    ],
                },
                Panel {
                    title: "Active Tunnels".to_string(),
                    panel_type: PanelType::Stat,
                    targets: vec![
                        "patronus_tunnels_active".to_string(),
                    ],
                },
            ],
        }
    }

    pub fn ml_dashboard() -> Self {
        Self {
            title: "Patronus ML Performance".to_string(),
            panels: vec![
                Panel {
                    title: "ML Predictions".to_string(),
                    panel_type: PanelType::Graph,
                    targets: vec![
                        "rate(patronus_ml_predictions_total[5m])".to_string(),
                    ],
                },
                Panel {
                    title: "Inference Time".to_string(),
                    panel_type: PanelType::Heatmap,
                    targets: vec![
                        "patronus_ml_inference_ms".to_string(),
                    ],
                },
                Panel {
                    title: "Anomalies Detected".to_string(),
                    panel_type: PanelType::Stat,
                    targets: vec![
                        "patronus_anomalies_detected_total".to_string(),
                    ],
                },
            ],
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "dashboard": {
                "title": self.title,
                "panels": self.panels,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_creation() {
        let dashboard = GrafanaDashboard::network_overview();
        assert_eq!(dashboard.title, "Patronus Network Overview");
        assert_eq!(dashboard.panels.len(), 4);

        let json = dashboard.to_json();
        assert!(json.get("dashboard").is_some());
    }

    #[test]
    fn test_ml_dashboard() {
        let dashboard = GrafanaDashboard::ml_dashboard();
        assert!(dashboard.title.contains("ML"));
        assert_eq!(dashboard.panels.len(), 3);
    }
}
