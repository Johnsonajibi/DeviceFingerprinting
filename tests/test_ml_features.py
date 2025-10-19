import unittest
import os
import sys
from unittest.mock import patch, MagicMock
import numpy as np
from sklearn.ensemble import IsolationForest

# Mock psutil before it's imported by ml_features
mock_psutil = MagicMock()
# psutil.cpu_times() returns a named tuple, so we mock that
mock_cpu_times = MagicMock()
mock_cpu_times.user = 100
mock_cpu_times.system = 20
mock_cpu_times.idle = 500
mock_psutil.cpu_times.return_value = mock_cpu_times
mock_psutil.virtual_memory.return_value = MagicMock(
    percent=50.0, total=16 * 1024**3, available=8 * 1024**3
)
mock_psutil.sensors_battery.return_value = MagicMock(percent=85, secsleft=3600, power_plugged=False)

with patch.dict("sys.modules", {"psutil": mock_psutil}):
    from device_fingerprinting.ml_features import FeatureExtractor, AnomalyDetector


class TestMLFeatures(unittest.TestCase):

    def setUp(self):
        """Set up the feature extractor and anomaly detector."""
        self.extractor = FeatureExtractor()
        # We need to manually set the last_cpu_times for the first run to be meaningful
        last_times = MagicMock()
        last_times.user = 90
        last_times.system = 18
        last_times.idle = 450
        self.extractor._last_cpu_times = last_times
        # Train a dummy model for the anomaly detector
        dummy_data = np.random.rand(10, 3)
        self.detector = AnomalyDetector()
        self.detector.train(dummy_data)

    # --- FeatureExtractor Tests ---
    def test_feature_extractor_collects_features(self):
        """Test that the feature extractor collects a feature vector."""
        features = self.extractor.collect_features()
        self.assertIsInstance(features, np.ndarray)
        # Based on our mocked psutil, we expect 3 features
        self.assertEqual(features.shape, (1, 3))

    def test_feature_values(self):
        """Test the correctness of the extracted feature values based on mocks."""
        features = self.extractor.collect_features()[0]  # Get the 1D array

        # Expected CPU usage: delta_user+delta_system / delta_total
        # (100-90) + (20-18) / (100-90) + (20-18) + (500-450) = 12 / (10 + 2 + 50) = 12 / 62
        expected_cpu_usage = 12 / 62.0
        self.assertAlmostEqual(features[0], expected_cpu_usage, places=4)

        # Expected Memory usage from mock is 50%
        expected_mem_usage = 0.5
        self.assertAlmostEqual(features[1], expected_mem_usage, places=4)

        # Expected Battery level
        self.assertAlmostEqual(features[2], 85.0 / 100.0, places=4)

    @patch("device_fingerprinting.ml_features.psutil")
    def test_feature_extraction_no_battery(self, mock_psutil_local):
        """Test feature extraction on a system with no battery."""
        # Configure the local mock for this test
        mock_psutil_local.sensors_battery.return_value = None
        mock_psutil_local.cpu_times.return_value = mock_cpu_times  # Keep other mocks working
        mock_psutil_local.virtual_memory.return_value = MagicMock(percent=50.0)

        # Re-import the class to use the patched module
        from device_fingerprinting.ml_features import FeatureExtractor

        extractor = FeatureExtractor()
        features = extractor.collect_features()[0]
        # Should return a default value (e.g., -1) for battery
        self.assertEqual(features[2], -1.0)

    # --- AnomalyDetector Tests ---
    def test_anomaly_detector_train(self):
        """Test that the anomaly detector's model is trained."""
        self.assertIsInstance(self.detector.model, IsolationForest)
        # The model should be fitted (has attributes ending with '_')
        self.assertTrue(hasattr(self.detector.model, "estimators_"))

    def test_predict_normal_behavior(self):
        """Test that data similar to training data is predicted as normal."""
        # This data point is similar to the training data (random values between 0 and 1)
        normal_features = np.array([[0.5, 0.6, 0.7]])
        prediction, score = self.detector.predict(normal_features)
        self.assertEqual(prediction, 1, "Should be predicted as normal (1)")
        self.assertGreater(score, 0, "Normal score should be positive")

    def test_predict_anomalous_behavior(self):
        """Test that outlier data is predicted as an anomaly."""
        # This data point is a clear outlier
        anomalous_features = np.array([[10.0, -5.0, 100.0]])
        prediction, score = self.detector.predict(anomalous_features)
        self.assertEqual(prediction, -1, "Should be predicted as an anomaly (-1)")
        self.assertLess(score, 0, "Anomaly score should be negative")

    def test_save_and_load_model(self):
        """Test saving the trained model to and loading from a file."""
        model_path = "test_anomaly_model.joblib"
        if os.path.exists(model_path):
            os.remove(model_path)

        self.detector.save_model(model_path)
        self.assertTrue(os.path.exists(model_path))

        new_detector = AnomalyDetector()
        new_detector.load_model(model_path)

        self.assertIsNotNone(new_detector.model)
        self.assertTrue(hasattr(new_detector.model, "estimators_"))

        # Clean up
        os.remove(model_path)


if __name__ == "__main__":
    unittest.main()
