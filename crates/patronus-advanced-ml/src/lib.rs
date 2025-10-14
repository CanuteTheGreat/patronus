//! Advanced ML Models
//!
//! Deep learning models for DPI and traffic analysis

pub mod neural_network;
pub mod dpi;

pub use neural_network::{NeuralNetwork, Layer, ActivationFunction};
pub use dpi::{DeepDpiClassifier, PacketFeatures, Protocol};
