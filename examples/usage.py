#!/usr/bin/env python3
"""TraceGuard Python API Usage Examples"""

import json
from traceguard import (
    SyscallAnalyzer, 
    AnomalyDetector, 
    TraceStorage
)
from traceguard.capture import TraceCapture
from traceguard.models import TraceReport


def example_capture_trace():
    """Example: Capture syscalls from a command"""
    print("📝 Example: Capturing trace...")
    
    tracer = TraceCapture(output_dir="./traces")
    
    # Capture syscalls from a test command
    report = tracer.trace_command(
        command="python -m pytest tests/ -v",
        label="example_run",
        git_commit="abc123def456",
        git_branch="feature/optimization"
    )
    
    print(f"✅ Captured {report.total_syscalls} total syscalls")
    print(f"   Unique: {report.unique_syscalls}")
    
    return report


def example_compare_traces():
    """Example: Compare traces for regressions"""
    print("\n📊 Example: Comparing traces...")
    
    storage = TraceStorage()
    
    # Load baseline and current
    baseline = storage.load_report("trace_baseline.json")
    current = storage.load_report("trace_current.json")
    
    # Analyze
    analyzer = SyscallAnalyzer(
        call_threshold=0.15,  # 15% increase
        time_threshold=0.20   # 20% time increase
    )
    
    result = analyzer.compare_reports(baseline, current)
    
    print(f"Regression: {result.is_regression}")
    print(f"Severity: {result.severity}")
    print(f"\n{result.details}")
    
    return result


def example_analyze_patterns():
    """Example: Analyze syscall patterns"""
    print("\n🔬 Example: Analyzing patterns...")
    
    storage = TraceStorage()
    report = storage.get_latest_report()
    
    analyzer = SyscallAnalyzer()
    
    # Get summary
    summary = analyzer.get_syscall_summary(report)
    print("Top 10 syscalls:")
    for syscall, count in list(summary.items())[:10]:
        print(f"  {syscall:20s} {count:8d}")
    
    # Categorize
    categories = analyzer.categorize_syscalls_by_type(report)
    print("\nBy category:")
    for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        print(f"  {category:15s} {count:8d}")
    
    return summary


def example_detect_anomalies():
    """Example: Detect anomalies using statistical methods"""
    print("\n🎯 Example: Detecting anomalies...")
    
    storage = TraceStorage()
    
    # Get recent traces
    reports = []
    for filename in sorted(storage.list_reports())[-20:]:
        reports.append(storage.load_report(filename))
    
    if len(reports) < 3:
        print("⚠️ Need at least 3 historical traces")
        return
    
    # Analyze current
    current = reports[-1]
    historical = reports[:-1]
    
    detector = AnomalyDetector(z_score_threshold=2.5)
    result = detector.detect_anomalies(current, historical)
    
    print(f"Anomalies found: {result['total_anomalies']}")
    for anomaly in result['anomalies'][:5]:
        print(f"  {anomaly['syscall']:20s} z-score: {anomaly['z_score']:6.2f} ({anomaly['severity']})")
    
    return result


def example_detect_spikes():
    """Example: Detect sudden spikes in syscall counts"""
    print("\n📈 Example: Detecting spikes...")
    
    storage = TraceStorage()
    
    # Get recent traces
    reports = []
    for filename in sorted(storage.list_reports())[-20:]:
        reports.append(storage.load_report(filename))
    
    if len(reports) < 5:
        print("⚠️ Need at least 5 historical traces")
        return
    
    detector = AnomalyDetector()
    result = detector.detect_syscall_spikes(reports, window_size=5)
    
    print(f"Spikes detected: {result['total_spikes']}")
    for spike in result['spikes'][:5]:
        print(f"  {spike['syscall']:20s} {spike['current']:6.0f} (avg: {spike['window_avg']:6.1f}, ratio: {spike['spike_ratio']:4.1f}x)")
    
    return result


def example_trend_prediction():
    """Example: Predict trends for syscalls"""
    print("\n🔮 Example: Predicting trends...")
    
    storage = TraceStorage()
    
    # Get recent traces
    reports = []
    for filename in sorted(storage.list_reports())[-20:]:
        reports.append(storage.load_report(filename))
    
    detector = AnomalyDetector()
    
    # Check a few syscalls
    for syscall in ["read", "write", "open", "mmap"]:
        trend = detector.predict_trend(reports, syscall)
        if "error" not in trend:
            print(f"  {syscall:20s} trend: {trend['trend']:10s} (change: {trend['change']:+6.0f})")
    
    return True


def example_ci_workflow():
    """Example: Complete CI/CD workflow"""
    print("\n🚀 Example: CI/CD Workflow...")
    
    # 1. Capture
    print("1️⃣  Capturing trace...")
    tracer = TraceCapture()
    current_report = tracer.trace_command(
        command="python -m pytest tests/ --tb=short",
        label="ci_run"
    )
    
    # 2. Load baseline
    print("2️⃣  Loading baseline...")
    storage = TraceStorage()
    baseline_report = storage.get_baseline()
    
    if baseline_report is None:
        print("⚠️  No baseline found, saving current as baseline")
        storage.save_baseline(current_report)
        return
    
    # 3. Compare
    print("3️⃣  Comparing against baseline...")
    analyzer = SyscallAnalyzer()
    comparison = analyzer.compare_reports(baseline_report, current_report)
    
    # 4. Report
    print("\n" + "="*50)
    print(f"Result: {'❌ FAIL' if comparison.is_regression else '✅ PASS'}")
    print(f"Severity: {comparison.severity}")
    print("="*50)
    print(comparison.details)
    
    # 5. Return exit code
    return 1 if comparison.is_regression else 0


if __name__ == "__main__":
    print("🔍 TraceGuard Examples\n")
    
    # Run examples
    # example_capture_trace()
    # example_compare_traces()
    # example_analyze_patterns()
    # example_detect_anomalies()
    # example_detect_spikes()
    # example_trend_prediction()
    # example_ci_workflow()
    
    print("\n📚 Uncomment examples in the script to run them!")