//! Time Series Forecasting

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ForecastModel {
    LinearRegression,
    MovingAverage { window_size: usize },
    ExponentialSmoothing { alpha: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastResult {
    pub predictions: Vec<f64>,
    pub timestamps: Vec<DateTime<Utc>>,
    pub confidence_lower: Vec<f64>,
    pub confidence_upper: Vec<f64>,
    pub model_used: ForecastModel,
    pub mae: f64, // Mean Absolute Error
}

pub struct TimeSeriesForecaster {
    model: ForecastModel,
}

impl TimeSeriesForecaster {
    pub fn new(model: ForecastModel) -> Self {
        Self { model }
    }

    /// Forecast future values based on historical data
    pub fn forecast(
        &self,
        historical_data: &[f64],
        timestamps: &[DateTime<Utc>],
        periods_ahead: usize,
    ) -> ForecastResult {
        match &self.model {
            ForecastModel::LinearRegression => {
                self.forecast_linear_regression(historical_data, timestamps, periods_ahead)
            }
            ForecastModel::MovingAverage { window_size } => {
                self.forecast_moving_average(historical_data, timestamps, periods_ahead, *window_size)
            }
            ForecastModel::ExponentialSmoothing { alpha } => {
                self.forecast_exponential_smoothing(historical_data, timestamps, periods_ahead, *alpha)
            }
        }
    }

    fn forecast_linear_regression(
        &self,
        data: &[f64],
        timestamps: &[DateTime<Utc>],
        periods: usize,
    ) -> ForecastResult {
        let n = data.len() as f64;
        let x: Vec<f64> = (0..data.len()).map(|i| i as f64).collect();

        // Calculate slope (m) and intercept (b) for y = mx + b
        let sum_x: f64 = x.iter().sum();
        let sum_y: f64 = data.iter().sum();
        let sum_xy: f64 = x.iter().zip(data.iter()).map(|(xi, yi)| xi * yi).sum();
        let sum_x2: f64 = x.iter().map(|xi| xi * xi).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        let intercept = (sum_y - slope * sum_x) / n;

        // Generate predictions
        let start_idx = data.len();
        let predictions: Vec<f64> = (start_idx..start_idx + periods)
            .map(|i| slope * (i as f64) + intercept)
            .collect();

        // Calculate confidence intervals (simplified: ±20% of predicted value)
        let confidence_lower = predictions.iter().map(|p| p * 0.8).collect();
        let confidence_upper = predictions.iter().map(|p| p * 1.2).collect();

        // Calculate MAE on training data
        let mae = self.calculate_mae(data, &x, slope, intercept);

        // Generate future timestamps
        let interval = if timestamps.len() >= 2 {
            timestamps[1].signed_duration_since(timestamps[0])
        } else {
            Duration::hours(1)
        };

        let future_timestamps: Vec<DateTime<Utc>> = (1..=periods)
            .map(|i| timestamps.last().unwrap().clone() + interval * i as i32)
            .collect();

        ForecastResult {
            predictions,
            timestamps: future_timestamps,
            confidence_lower,
            confidence_upper,
            model_used: ForecastModel::LinearRegression,
            mae,
        }
    }

    fn forecast_moving_average(
        &self,
        data: &[f64],
        timestamps: &[DateTime<Utc>],
        periods: usize,
        window_size: usize,
    ) -> ForecastResult {
        let window = window_size.min(data.len());

        // Calculate moving average of last window_size points
        let last_window: Vec<f64> = data.iter().rev().take(window).copied().collect();
        let avg: f64 = last_window.iter().sum::<f64>() / last_window.len() as f64;

        // Use the average as prediction for all future periods
        let predictions = vec![avg; periods];

        // Confidence intervals based on historical variance
        let variance = last_window.iter()
            .map(|x| (x - avg).powi(2))
            .sum::<f64>() / last_window.len() as f64;
        let std_dev = variance.sqrt();

        let confidence_lower = predictions.iter().map(|p| (p - 2.0 * std_dev).max(0.0)).collect();
        let confidence_upper = predictions.iter().map(|p| p + 2.0 * std_dev).collect();

        // Calculate MAE
        let mae = self.calculate_moving_average_mae(data, window);

        let interval = if timestamps.len() >= 2 {
            timestamps[1].signed_duration_since(timestamps[0])
        } else {
            Duration::hours(1)
        };

        let future_timestamps: Vec<DateTime<Utc>> = (1..=periods)
            .map(|i| timestamps.last().unwrap().clone() + interval * i as i32)
            .collect();

        ForecastResult {
            predictions,
            timestamps: future_timestamps,
            confidence_lower,
            confidence_upper,
            model_used: ForecastModel::MovingAverage { window_size },
            mae,
        }
    }

    fn forecast_exponential_smoothing(
        &self,
        data: &[f64],
        timestamps: &[DateTime<Utc>],
        periods: usize,
        alpha: f64,
    ) -> ForecastResult {
        // Calculate exponentially weighted forecast
        let mut forecast = data[0];
        for &value in &data[1..] {
            forecast = alpha * value + (1.0 - alpha) * forecast;
        }

        let predictions = vec![forecast; periods];

        // Simple confidence intervals
        let confidence_lower = predictions.iter().map(|p| p * 0.85).collect();
        let confidence_upper = predictions.iter().map(|p| p * 1.15).collect();

        // Calculate MAE
        let mae = self.calculate_exponential_smoothing_mae(data, alpha);

        let interval = if timestamps.len() >= 2 {
            timestamps[1].signed_duration_since(timestamps[0])
        } else {
            Duration::hours(1)
        };

        let future_timestamps: Vec<DateTime<Utc>> = (1..=periods)
            .map(|i| timestamps.last().unwrap().clone() + interval * i as i32)
            .collect();

        ForecastResult {
            predictions,
            timestamps: future_timestamps,
            confidence_lower,
            confidence_upper,
            model_used: ForecastModel::ExponentialSmoothing { alpha },
            mae,
        }
    }

    fn calculate_mae(&self, data: &[f64], x: &[f64], slope: f64, intercept: f64) -> f64 {
        let errors: Vec<f64> = x.iter().zip(data.iter())
            .map(|(xi, yi)| (yi - (slope * xi + intercept)).abs())
            .collect();

        errors.iter().sum::<f64>() / errors.len() as f64
    }

    fn calculate_moving_average_mae(&self, data: &[f64], window: usize) -> f64 {
        if data.len() < window + 1 {
            return 0.0;
        }

        let mut errors = Vec::new();
        for i in window..data.len() {
            let avg = data[i-window..i].iter().sum::<f64>() / window as f64;
            errors.push((data[i] - avg).abs());
        }

        errors.iter().sum::<f64>() / errors.len() as f64
    }

    fn calculate_exponential_smoothing_mae(&self, data: &[f64], alpha: f64) -> f64 {
        if data.len() < 2 {
            return 0.0;
        }

        let mut forecast = data[0];
        let mut errors = Vec::new();

        for &value in &data[1..] {
            errors.push((value - forecast).abs());
            forecast = alpha * value + (1.0 - alpha) * forecast;
        }

        errors.iter().sum::<f64>() / errors.len() as f64
    }

    /// Calculate forecast accuracy metrics
    pub fn evaluate_accuracy(&self, actual: &[f64], predicted: &[f64]) -> AccuracyMetrics {
        assert_eq!(actual.len(), predicted.len(), "Actual and predicted must have same length");

        let n = actual.len() as f64;

        // Mean Absolute Error
        let mae = actual.iter().zip(predicted.iter())
            .map(|(a, p)| (a - p).abs())
            .sum::<f64>() / n;

        // Mean Squared Error
        let mse = actual.iter().zip(predicted.iter())
            .map(|(a, p)| (a - p).powi(2))
            .sum::<f64>() / n;

        // Root Mean Squared Error
        let rmse = mse.sqrt();

        // Mean Absolute Percentage Error
        let mape = actual.iter().zip(predicted.iter())
            .filter(|(a, _)| **a != 0.0)
            .map(|(a, p)| ((a - p) / a).abs())
            .sum::<f64>() / n * 100.0;

        AccuracyMetrics {
            mae,
            mse,
            rmse,
            mape,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub mae: f64,   // Mean Absolute Error
    pub mse: f64,   // Mean Squared Error
    pub rmse: f64,  // Root Mean Squared Error
    pub mape: f64,  // Mean Absolute Percentage Error (%)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_regression_forecast() {
        let forecaster = TimeSeriesForecaster::new(ForecastModel::LinearRegression);

        // Simple upward trend: 10, 20, 30, 40
        let data = vec![10.0, 20.0, 30.0, 40.0];
        let now = Utc::now();
        let timestamps: Vec<DateTime<Utc>> = (0..4)
            .map(|i| now + Duration::hours(i))
            .collect();

        let result = forecaster.forecast(&data, &timestamps, 2);

        // Should predict continued upward trend
        assert_eq!(result.predictions.len(), 2);
        assert!(result.predictions[0] > 40.0);
        assert!(result.predictions[1] > result.predictions[0]);
    }

    #[test]
    fn test_moving_average_forecast() {
        let forecaster = TimeSeriesForecaster::new(
            ForecastModel::MovingAverage { window_size: 3 }
        );

        let data = vec![100.0, 105.0, 110.0, 115.0, 120.0];
        let now = Utc::now();
        let timestamps: Vec<DateTime<Utc>> = (0..5)
            .map(|i| now + Duration::hours(i))
            .collect();

        let result = forecaster.forecast(&data, &timestamps, 2);

        assert_eq!(result.predictions.len(), 2);
        // Moving average of last 3: (110+115+120)/3 = 115
        assert!((result.predictions[0] - 115.0).abs() < 1.0);
    }

    #[test]
    fn test_exponential_smoothing_forecast() {
        let forecaster = TimeSeriesForecaster::new(
            ForecastModel::ExponentialSmoothing { alpha: 0.5 }
        );

        let data = vec![10.0, 20.0, 30.0, 40.0];
        let now = Utc::now();
        let timestamps: Vec<DateTime<Utc>> = (0..4)
            .map(|i| now + Duration::hours(i))
            .collect();

        let result = forecaster.forecast(&data, &timestamps, 2);

        assert_eq!(result.predictions.len(), 2);
        assert!(result.predictions[0] > 0.0);
    }

    #[test]
    fn test_confidence_intervals() {
        let forecaster = TimeSeriesForecaster::new(ForecastModel::LinearRegression);

        let data = vec![10.0, 20.0, 30.0, 40.0];
        let now = Utc::now();
        let timestamps: Vec<DateTime<Utc>> = (0..4)
            .map(|i| now + Duration::hours(i))
            .collect();

        let result = forecaster.forecast(&data, &timestamps, 2);

        // Lower bound should be less than prediction
        assert!(result.confidence_lower[0] < result.predictions[0]);
        // Upper bound should be greater than prediction
        assert!(result.confidence_upper[0] > result.predictions[0]);
    }

    #[test]
    fn test_accuracy_metrics() {
        let forecaster = TimeSeriesForecaster::new(ForecastModel::LinearRegression);

        let actual = vec![10.0, 20.0, 30.0, 40.0];
        let predicted = vec![12.0, 22.0, 28.0, 38.0];

        let metrics = forecaster.evaluate_accuracy(&actual, &predicted);

        assert!(metrics.mae > 0.0);
        assert!(metrics.mse > 0.0);
        assert!(metrics.rmse > 0.0);
        assert!(metrics.mape > 0.0);
    }

    #[test]
    fn test_perfect_prediction_accuracy() {
        let forecaster = TimeSeriesForecaster::new(ForecastModel::LinearRegression);

        let actual = vec![10.0, 20.0, 30.0, 40.0];
        let predicted = vec![10.0, 20.0, 30.0, 40.0];

        let metrics = forecaster.evaluate_accuracy(&actual, &predicted);

        use approx::assert_relative_eq;
        assert_relative_eq!(metrics.mae, 0.0, epsilon = 0.001);
        assert_relative_eq!(metrics.mse, 0.0, epsilon = 0.001);
        assert_relative_eq!(metrics.rmse, 0.0, epsilon = 0.001);
    }

    #[test]
    fn test_forecast_timestamps() {
        let forecaster = TimeSeriesForecaster::new(ForecastModel::LinearRegression);

        let data = vec![10.0, 20.0, 30.0];
        let now = Utc::now();
        let timestamps: Vec<DateTime<Utc>> = (0..3)
            .map(|i| now + Duration::hours(i))
            .collect();

        let result = forecaster.forecast(&data, &timestamps, 3);

        assert_eq!(result.timestamps.len(), 3);
        // Each timestamp should be 1 hour ahead
        assert!(result.timestamps[0] > *timestamps.last().unwrap());
    }
}
