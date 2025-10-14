//! Deep Neural Network Implementation

use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use rand::Rng;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivationFunction {
    ReLU,
    Sigmoid,
    Tanh,
    Softmax,
}

impl ActivationFunction {
    pub fn apply(&self, x: &Array1<f64>) -> Array1<f64> {
        match self {
            ActivationFunction::ReLU => x.mapv(|v| v.max(0.0)),
            ActivationFunction::Sigmoid => x.mapv(|v| 1.0 / (1.0 + (-v).exp())),
            ActivationFunction::Tanh => x.mapv(|v| v.tanh()),
            ActivationFunction::Softmax => {
                let max = x.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                let exp_x = x.mapv(|v| (v - max).exp());
                let sum: f64 = exp_x.sum();
                exp_x.mapv(|v| v / sum)
            }
        }
    }

    pub fn derivative(&self, x: &Array1<f64>) -> Array1<f64> {
        match self {
            ActivationFunction::ReLU => x.mapv(|v| if v > 0.0 { 1.0 } else { 0.0 }),
            ActivationFunction::Sigmoid => {
                let sig = self.apply(x);
                &sig * &sig.mapv(|v| 1.0 - v)
            }
            ActivationFunction::Tanh => {
                let tanh = self.apply(x);
                tanh.mapv(|v| 1.0 - v * v)
            }
            ActivationFunction::Softmax => {
                // Simplified - proper derivative is complex
                x.mapv(|_| 1.0)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Layer {
    pub weights: Array2<f64>,
    pub biases: Array1<f64>,
    pub activation: ActivationFunction,
}

impl Layer {
    pub fn new(input_size: usize, output_size: usize, activation: ActivationFunction) -> Self {
        let mut rng = rand::thread_rng();

        // Xavier initialization
        let scale = (2.0 / (input_size + output_size) as f64).sqrt();

        let weights = Array2::from_shape_fn((output_size, input_size), |_| {
            rng.gen::<f64>() * scale - scale / 2.0
        });

        let biases = Array1::zeros(output_size);

        Self {
            weights,
            biases,
            activation,
        }
    }

    pub fn forward(&self, input: &Array1<f64>) -> Array1<f64> {
        let z = self.weights.dot(input) + &self.biases;
        self.activation.apply(&z)
    }
}

#[derive(Debug, Clone)]
pub struct NeuralNetwork {
    layers: Vec<Layer>,
}

impl NeuralNetwork {
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    pub fn add_layer(&mut self, layer: Layer) {
        self.layers.push(layer);
    }

    pub fn forward(&self, input: &Array1<f64>) -> Result<Array1<f64>> {
        if self.layers.is_empty() {
            anyhow::bail!("Network has no layers");
        }

        let mut activation = input.clone();

        for layer in &self.layers {
            activation = layer.forward(&activation);
        }

        Ok(activation)
    }

    pub fn predict(&self, input: &Array1<f64>) -> Result<usize> {
        let output = self.forward(input)?;

        // Return index of max value
        let max_idx = output
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(idx, _)| idx)
            .ok_or_else(|| anyhow::anyhow!("Empty output"))?;

        Ok(max_idx)
    }

    pub fn predict_proba(&self, input: &Array1<f64>) -> Result<Array1<f64>> {
        self.forward(input)
    }

    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }
}

impl Default for NeuralNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relu_activation() {
        let activation = ActivationFunction::ReLU;
        let input = Array1::from_vec(vec![-2.0, -1.0, 0.0, 1.0, 2.0]);
        let output = activation.apply(&input);

        assert_eq!(output[0], 0.0);
        assert_eq!(output[1], 0.0);
        assert_eq!(output[2], 0.0);
        assert_eq!(output[3], 1.0);
        assert_eq!(output[4], 2.0);
    }

    #[test]
    fn test_sigmoid_activation() {
        let activation = ActivationFunction::Sigmoid;
        let input = Array1::from_vec(vec![0.0]);
        let output = activation.apply(&input);

        assert!((output[0] - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_softmax_activation() {
        let activation = ActivationFunction::Softmax;
        let input = Array1::from_vec(vec![1.0, 2.0, 3.0]);
        let output = activation.apply(&input);

        // Sum should be 1.0
        let sum: f64 = output.sum();
        assert!((sum - 1.0).abs() < 1e-10);

        // Output should be sorted (higher input -> higher output)
        assert!(output[0] < output[1]);
        assert!(output[1] < output[2]);
    }

    #[test]
    fn test_layer_forward() {
        let layer = Layer::new(3, 2, ActivationFunction::ReLU);
        let input = Array1::from_vec(vec![1.0, 2.0, 3.0]);
        let output = layer.forward(&input);

        assert_eq!(output.len(), 2);
    }

    #[test]
    fn test_neural_network() {
        let mut nn = NeuralNetwork::new();

        // Input layer: 4 features
        // Hidden layer: 8 neurons
        nn.add_layer(Layer::new(4, 8, ActivationFunction::ReLU));

        // Hidden layer: 8 -> 4 neurons
        nn.add_layer(Layer::new(8, 4, ActivationFunction::ReLU));

        // Output layer: 3 classes
        nn.add_layer(Layer::new(4, 3, ActivationFunction::Softmax));

        let input = Array1::from_vec(vec![1.0, 0.5, 0.2, 0.8]);
        let output = nn.forward(&input).unwrap();

        assert_eq!(output.len(), 3);

        // Sum should be ~1.0 (softmax)
        let sum: f64 = output.sum();
        assert!((sum - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_predict() {
        let mut nn = NeuralNetwork::new();
        nn.add_layer(Layer::new(2, 4, ActivationFunction::ReLU));
        nn.add_layer(Layer::new(4, 3, ActivationFunction::Softmax));

        let input = Array1::from_vec(vec![1.0, 2.0]);
        let class = nn.predict(&input).unwrap();

        assert!(class < 3);
    }

    #[test]
    fn test_predict_proba() {
        let mut nn = NeuralNetwork::new();
        nn.add_layer(Layer::new(2, 3, ActivationFunction::Softmax));

        let input = Array1::from_vec(vec![1.0, 2.0]);
        let proba = nn.predict_proba(&input).unwrap();

        assert_eq!(proba.len(), 3);

        // All probabilities should be positive
        for p in proba.iter() {
            assert!(*p >= 0.0);
            assert!(*p <= 1.0);
        }
    }
}
