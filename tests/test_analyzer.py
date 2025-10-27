"""Tests for SyscallAnalyzer"""

import pytest
from datetime import datetime
from traceguard.models import (
    SyscallMetrics, ProcessMetrics, TraceReport, SyscallType
)
from traceguard.analyzer import SyscallAnalyzer


@pytest.fixture
def baseline_report():
    """Create a baseline trace report"""
    process = ProcessMetrics(
        pid=1000,
        command="test_command",
        duration=1.0,
        total_syscalls=100,
        unique_syscalls=5
    )
    
    process.syscalls = {
        "read": SyscallMetrics(name="read", count=30, total_time=50.0, category=SyscallType.FILE_IO),
        "write": SyscallMetrics(name="write", count=20, total_time=40.0, category=SyscallType.FILE_IO),
        "open": SyscallMetrics(name="open", count=10, total_time=20.0, category=SyscallType.FILE_IO),
        "close": SyscallMetrics(name="close", count=25, total_time=10.0, category=SyscallType.FILE_IO),
        "mmap": SyscallMetrics(name="mmap", count=15, total_time=30.0, category=SyscallType.MEMORY),
    }
    
    report = TraceReport(
        timestamp=datetime.now(),
        test_command="test",
        duration=1.0,
        processes={1000: process}
    )
    return report


@pytest.fixture
def current_report():
    """Create a current trace report with changes"""
    process = ProcessMetrics(
        pid=2000,
        command="test_command",
        duration=1.0,
        total_syscalls=120,
        unique_syscalls=6
    )
    
    process.syscalls = {
        "read": SyscallMetrics(name="read", count=50, total_time=80.0, category=SyscallType.FILE_IO),  # +66%
        "write": SyscallMetrics(name="write", count=20, total_time=40.0, category=SyscallType.FILE_IO),  # same
        "open": SyscallMetrics(name="open", count=10, total_time=20.0, category=SyscallType.FILE_IO),  # same
        "close": SyscallMetrics(name="close", count=25, total_time=10.0, category=SyscallType.FILE_IO),  # same
        "mmap": SyscallMetrics(name="mmap", count=5, total_time=10.0, category=SyscallType.MEMORY),  # ignored
        "socket": SyscallMetrics(name="socket", count=10, total_time=20.0, category=SyscallType.NETWORK),  # NEW
    }
    
    report = TraceReport(
        timestamp=datetime.now(),
        test_command="test",
        duration=1.0,
        processes={2000: process}
    )
    return report


def test_detect_increased_calls(baseline_report, current_report):
    """Test detection of increased syscall counts"""
    analyzer = SyscallAnalyzer(call_threshold=0.15)
    result = analyzer.compare_reports(baseline_report, current_report)
    
    assert result.is_regression
    assert "read" in result.increased_calls
    assert result.increased_calls["read"]["baseline"] == 30
    assert result.increased_calls["read"]["current"] == 50


def test_detect_new_syscalls(baseline_report, current_report):
    """Test detection of new syscalls"""
    analyzer = SyscallAnalyzer()
    result = analyzer.compare_reports(baseline_report, current_report)
    
    assert "socket" in result.new_syscalls


def test_ignore_syscalls(baseline_report, current_report):
    """Test that ignored syscalls are excluded from comparison"""
    analyzer = SyscallAnalyzer(ignore_syscalls=["socket"])
    result = analyzer.compare_reports(baseline_report, current_report)
    
    assert "socket" not in result.new_syscalls


def test_get_syscall_summary(baseline_report):
    """Test syscall summary generation"""
    analyzer = SyscallAnalyzer()
    summary = analyzer.get_syscall_summary(baseline_report)
    
    assert "read" in summary
    assert summary["read"] == 30


def test_categorize_syscalls(baseline_report):
    """Test syscall categorization"""
    analyzer = SyscallAnalyzer()
    categories = analyzer.categorize_syscalls_by_type(baseline_report)
    
    assert SyscallType.FILE_IO in categories


def test_no_regression_identical_reports(baseline_report):
    """Test that identical reports show no regression"""
    analyzer = SyscallAnalyzer()
    result = analyzer.compare_reports(baseline_report, baseline_report)
    
    assert not result.is_regression


def test_severity_levels(baseline_report):
    """Test severity calculation for different increases"""
    process = ProcessMetrics(pid=3000, command="test", duration=1.0)
    process.syscalls = {
        "read": SyscallMetrics(name="read", count=200, total_time=500.0, category=SyscallType.FILE_IO),  # 6.66x increase
    }
    
    current = TraceReport(
        timestamp=datetime.now(),
        test_command="test",
        duration=1.0,
        processes={3000: process}
    )
    
    analyzer = SyscallAnalyzer()
    result = analyzer.compare_reports(baseline_report, current)
    
    assert result.is_regression
    assert result.severity == "high"