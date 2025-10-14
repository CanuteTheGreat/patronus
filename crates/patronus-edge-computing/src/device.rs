//! IoT Device Management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceType {
    Sensor,
    Actuator,
    Gateway,
    Camera,
    Vehicle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMetrics {
    pub battery_percent: Option<f64>,
    pub signal_strength_dbm: f64,
    pub data_sent_bytes: u64,
    pub data_received_bytes: u64,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTDevice {
    pub id: Uuid,
    pub name: String,
    pub device_type: DeviceType,
    pub edge_node_id: Option<Uuid>,
    pub location: (f64, f64), // lat, lon
    pub metrics: DeviceMetrics,
    pub online: bool,
}

impl IoTDevice {
    pub fn new(name: String, device_type: DeviceType, location: (f64, f64)) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            device_type,
            edge_node_id: None,
            location,
            metrics: DeviceMetrics {
                battery_percent: Some(100.0),
                signal_strength_dbm: -70.0,
                data_sent_bytes: 0,
                data_received_bytes: 0,
                last_seen: Utc::now(),
            },
            online: true,
        }
    }

    pub fn is_low_battery(&self) -> bool {
        self.metrics.battery_percent.map(|b| b < 20.0).unwrap_or(false)
    }

    pub fn is_weak_signal(&self) -> bool {
        self.metrics.signal_strength_dbm < -90.0
    }
}

pub struct DeviceManager {
    devices: Arc<RwLock<HashMap<Uuid, IoTDevice>>>,
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_device(&self, device: IoTDevice) -> Uuid {
        let id = device.id;
        let mut devices = self.devices.write().await;
        devices.insert(id, device);
        id
    }

    pub async fn get_device(&self, id: &Uuid) -> Option<IoTDevice> {
        let devices = self.devices.read().await;
        devices.get(id).cloned()
    }

    pub async fn unregister_device(&self, id: &Uuid) -> bool {
        let mut devices = self.devices.write().await;
        devices.remove(id).is_some()
    }

    pub async fn list_devices(&self) -> Vec<IoTDevice> {
        let devices = self.devices.read().await;
        devices.values().cloned().collect()
    }

    pub async fn get_online_devices(&self) -> Vec<IoTDevice> {
        let devices = self.devices.read().await;
        devices.values().filter(|d| d.online).cloned().collect()
    }

    pub async fn assign_to_edge_node(&self, device_id: &Uuid, node_id: Uuid) -> bool {
        let mut devices = self.devices.write().await;
        if let Some(device) = devices.get_mut(device_id) {
            device.edge_node_id = Some(node_id);
            true
        } else {
            false
        }
    }

    pub async fn update_metrics(&self, id: &Uuid, metrics: DeviceMetrics) -> bool {
        let mut devices = self.devices.write().await;
        if let Some(device) = devices.get_mut(id) {
            device.metrics = metrics;
            true
        } else {
            false
        }
    }

    pub async fn get_devices_by_type(&self, device_type: &DeviceType) -> Vec<IoTDevice> {
        let devices = self.devices.read().await;
        devices.values()
            .filter(|d| &d.device_type == device_type)
            .cloned()
            .collect()
    }

    pub async fn get_low_battery_devices(&self) -> Vec<IoTDevice> {
        let devices = self.devices.read().await;
        devices.values()
            .filter(|d| d.is_low_battery())
            .cloned()
            .collect()
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_creation() {
        let device = IoTDevice::new(
            "sensor-1".to_string(),
            DeviceType::Sensor,
            (37.7749, -122.4194),
        );

        assert_eq!(device.name, "sensor-1");
        assert_eq!(device.device_type, DeviceType::Sensor);
        assert!(device.online);
    }

    #[test]
    fn test_low_battery_detection() {
        let mut device = IoTDevice::new(
            "sensor-1".to_string(),
            DeviceType::Sensor,
            (37.7749, -122.4194),
        );

        assert!(!device.is_low_battery());

        device.metrics.battery_percent = Some(15.0);
        assert!(device.is_low_battery());
    }

    #[test]
    fn test_weak_signal_detection() {
        let mut device = IoTDevice::new(
            "sensor-1".to_string(),
            DeviceType::Sensor,
            (37.7749, -122.4194),
        );

        assert!(!device.is_weak_signal());

        device.metrics.signal_strength_dbm = -95.0;
        assert!(device.is_weak_signal());
    }

    #[tokio::test]
    async fn test_device_manager_register() {
        let manager = DeviceManager::new();
        let device = IoTDevice::new(
            "sensor-1".to_string(),
            DeviceType::Sensor,
            (37.7749, -122.4194),
        );
        let id = device.id;

        manager.register_device(device).await;

        let retrieved = manager.get_device(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "sensor-1");
    }

    #[tokio::test]
    async fn test_unregister_device() {
        let manager = DeviceManager::new();
        let device = IoTDevice::new(
            "sensor-1".to_string(),
            DeviceType::Sensor,
            (37.7749, -122.4194),
        );
        let id = device.id;

        manager.register_device(device).await;
        assert!(manager.unregister_device(&id).await);
        assert!(manager.get_device(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_list_devices() {
        let manager = DeviceManager::new();

        let d1 = IoTDevice::new("s1".to_string(), DeviceType::Sensor, (0.0, 0.0));
        let d2 = IoTDevice::new("s2".to_string(), DeviceType::Camera, (0.0, 0.0));

        manager.register_device(d1).await;
        manager.register_device(d2).await;

        let devices = manager.list_devices().await;
        assert_eq!(devices.len(), 2);
    }

    #[tokio::test]
    async fn test_get_online_devices() {
        let manager = DeviceManager::new();

        let d1 = IoTDevice::new("s1".to_string(), DeviceType::Sensor, (0.0, 0.0));
        let mut d2 = IoTDevice::new("s2".to_string(), DeviceType::Camera, (0.0, 0.0));
        d2.online = false;

        manager.register_device(d1).await;
        manager.register_device(d2).await;

        let online = manager.get_online_devices().await;
        assert_eq!(online.len(), 1);
    }

    #[tokio::test]
    async fn test_assign_to_edge_node() {
        let manager = DeviceManager::new();
        let device = IoTDevice::new("s1".to_string(), DeviceType::Sensor, (0.0, 0.0));
        let device_id = device.id;

        manager.register_device(device).await;

        let node_id = Uuid::new_v4();
        assert!(manager.assign_to_edge_node(&device_id, node_id).await);

        let device = manager.get_device(&device_id).await.unwrap();
        assert_eq!(device.edge_node_id, Some(node_id));
    }

    #[tokio::test]
    async fn test_update_metrics() {
        let manager = DeviceManager::new();
        let device = IoTDevice::new("s1".to_string(), DeviceType::Sensor, (0.0, 0.0));
        let device_id = device.id;

        manager.register_device(device).await;

        let new_metrics = DeviceMetrics {
            battery_percent: Some(50.0),
            signal_strength_dbm: -80.0,
            data_sent_bytes: 1000,
            data_received_bytes: 2000,
            last_seen: Utc::now(),
        };

        assert!(manager.update_metrics(&device_id, new_metrics).await);

        let device = manager.get_device(&device_id).await.unwrap();
        assert_eq!(device.metrics.battery_percent, Some(50.0));
    }

    #[tokio::test]
    async fn test_get_devices_by_type() {
        let manager = DeviceManager::new();

        manager.register_device(IoTDevice::new("s1".to_string(), DeviceType::Sensor, (0.0, 0.0))).await;
        manager.register_device(IoTDevice::new("c1".to_string(), DeviceType::Camera, (0.0, 0.0))).await;
        manager.register_device(IoTDevice::new("s2".to_string(), DeviceType::Sensor, (0.0, 0.0))).await;

        let sensors = manager.get_devices_by_type(&DeviceType::Sensor).await;
        assert_eq!(sensors.len(), 2);
    }

    #[tokio::test]
    async fn test_get_low_battery_devices() {
        let manager = DeviceManager::new();

        let mut d1 = IoTDevice::new("s1".to_string(), DeviceType::Sensor, (0.0, 0.0));
        d1.metrics.battery_percent = Some(10.0);

        let d2 = IoTDevice::new("s2".to_string(), DeviceType::Sensor, (0.0, 0.0));

        manager.register_device(d1).await;
        manager.register_device(d2).await;

        let low_battery = manager.get_low_battery_devices().await;
        assert_eq!(low_battery.len(), 1);
    }
}
