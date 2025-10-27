"""Tests for AnomalyDetector"""

import pytest
from datetime import datetime, timedelta
from traceguard.models import (
    SyscallMetrics, ProcessMetrics, TraceReport
)
from traceguard.detector import AnomalyDetector


@pytest.fixture
def trace_history():
    """Create a history of trace reports"""
    reports = []
    
    for i in range(10):
        process = ProcessMetrics(
            pid=1000 + i,
            command="test_command",
            duration=1.0,
            total_syscalls=100 + i*5,
            unique_syscalls=5
        )
        
        # Create stable pattern with slight variation
        base_count = 30 + (i * 0.5)
        process.syscalls = {
            "read": SyscallMetrics(name="read", count=int(base_count), total_time=50.0),
            "write": SyscallMetrics(name="write", count=20, total_time=40.0),
            "open": SyscallMetrics(name="open", count=10, total_time=20.0),
        }
        
        report = TraceReport(
            timestamp=datetime.now() - timedelta(hours=10-i),
            test_command="test",
            duration=1.0,
            processes={1000 + i: process}
        )
        reports.append(report)
    
    return reports


@pytest.fixture
def anomalous_report(trace_history):
    """Create a report with anomalous syscall counts"""
    process = ProcessMetrics(
        pid=2000,
        command="test_command",
        duration=1.0,
        total_syscalls=500,  # Much higher than normal
        unique_syscalls=5
    )
    
    process.syscalls = {
        "read": SyscallMetrics(name="read", count=200, total_time=500.0),  # 6x normal
        "write": SyscallMetrics(name="write", count=20, total_time=40.0),
        "open": SyscallMetrics(name="open", count=10, total_time=20.0),
    }
    
    report = TraceReport(
        timestamp=datetime.now(),
        test_command="test",
        duration=1.0,
        processes={2000: process}
    )
    return report


def test_detect_anomalies(trace_history, anomalous_report):
    """Test anomaly detection using z-scores"""
    detector = AnomalyDetector(z_score_threshold=2.0)
    result = detector.detect_anomalies(anomalous_report, trace_history)
    
    assert result['total_anomalies'] > 0
    
    # Check that read syscall is flagged
    read_anomalies = [a for a in result['anomalies'] if a['syscall'] == 'read']
    assert len(read_anomalies) > 0


def test_detect_syscall_spikes(trace_history):
    """Test spike detection"""
    detector = AnomalyDetector()
    
    # Add a spike to the history
    spike_process = ProcessMetrics(pid=5000, command="test", duration=1.0)
    spike_process.syscalls = {
        "read": SyscallMetrics(name="read", count=150, total_time=500.0),  # 4x increase
    }
    spike_report = TraceReport(
        timestamp=datetime.now(),
        test_command="test",
        duration=1.0,
        processes={5000: spike_process}
    )
    
    history_with_spike = trace_history + [spike_report]
    
    result = detector.detect_syscall_spikes(history_with_spike, window_size=5)
    
    assert result['total_spikes'] > 0


def test_predict_trend(trace_history):
    """Test trend prediction"""
    detector = AnomalyDetector()
    trend = detector.predict_trend(trace_history, "read")
    
    assert "trend" in trend
    assert "slope" in trend
    assert trend['syscall'] == "read"


def test_severity_calculation():
    """Test z-score to severity conversion"""
    detector = AnomalyDetector()
    
    assert detector._calculate_severity(5.0) == "critical"
    assert detector._calculate_severity(3.5) == "high"
    assert detector._calculate_severity(2.7) == "medium"
    assert detector._calculate_severity(2.0) == "low"


def test_insufficient_data(anomalous_report):
    """Test behavior with insufficient historical data"""
    detector = AnomalyDetector()
    result = detector.detect_anomalies(anomalous_report, [])
    
    assert "warning" in result


def test_slope_calculation():
    """Test linear regression slope calculation"""
    detector = AnomalyDetector()
    
    # Increasing values
    increasing = [1, 2, 3, 4, 5]
    slope_inc = detector._calculate_slope(increasing)
    assert slope_inc > 0
    
    # Decreasing values
    decreasing = [5, 4, 3, 2, 1]
    slope_dec = detector._calculate_slope(decreasing)
    assert slope_dec < 0
    
    # Stable values
    stable = [3, 3, 3, 3, 3]
    slope_stable = detector._calculate_slope(stable)
    assert slope_stable == 0