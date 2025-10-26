"""Syscall analysis and comparison engine"""

from typing import Dict, List, Tuple, Optional
from .models import (
    SyscallMetrics, ProcessMetrics, TraceReport, 
    RegressionResult, SyscallType
)


class SyscallAnalyzer:
    """Analyzes and compares syscall patterns"""
    
    def __init__(
        self,
        call_threshold: float = 0.15,
        time_threshold: float = 0.20,
        ignore_syscalls: Optional[List[str]] = None
    ):
        """
        Initialize analyzer with thresholds
        
        Args:
            call_threshold: Percentage increase threshold for call counts (0.15 = 15%)
            time_threshold: Percentage increase threshold for execution time (0.20 = 20%)
            ignore_syscalls: List of syscalls to ignore in comparisons
        """
        self.call_threshold = call_threshold
        self.time_threshold = time_threshold
        self.ignore_syscalls = set(ignore_syscalls or [])
    
    def compare_reports(
        self,
        baseline: TraceReport,
        current: TraceReport,
        fail_on_new: bool = True
    ) -> RegressionResult:
        """
        Compare current report against baseline
        
        Args:
            baseline: Baseline trace report
            current: Current trace report
            fail_on_new: Whether to fail on new syscalls
        
        Returns:
            RegressionResult with comparison details
        """
        result = RegressionResult(is_regression=False)
        
        # Get all syscalls from both reports
        baseline_calls = self._extract_all_syscalls(baseline)
        current_calls = self._extract_all_syscalls(current)
        
        # Check for new syscalls
        new_syscalls = set(current_calls.keys()) - set(baseline_calls.keys())
        new_syscalls = new_syscalls - self.ignore_syscalls
        if new_syscalls:
            result.new_syscalls = sorted(list(new_syscalls))
            if fail_on_new:
                result.is_regression = True
                result.severity = "high"
        
        # Check for removed syscalls
        removed = set(baseline_calls.keys()) - set(current_calls.keys())
        if removed:
            result.removed_syscalls = sorted(list(removed))
        
        # Check for increased call counts
        for syscall, current_metric in current_calls.items():
            if syscall in self.ignore_syscalls:
                continue
            
            if syscall not in baseline_calls:
                continue
            
            baseline_metric = baseline_calls[syscall]
            increase = self._calculate_increase(
                baseline_metric.count,
                current_metric.count
            )
            
            if increase > self.call_threshold:
                result.increased_calls[syscall] = {
                    "baseline": baseline_metric.count,
                    "current": current_metric.count,
                    "increase_pct": increase * 100
                }
                result.is_regression = True
                if increase > 0.50:  # 50% increase
                    result.severity = "high"
                else:
                    result.severity = "medium"
        
        # Check for increased execution time
        for syscall, current_metric in current_calls.items():
            if syscall in self.ignore_syscalls:
                continue
            
            if syscall not in baseline_calls:
                continue
            
            baseline_metric = baseline_calls[syscall]
            if baseline_metric.total_time == 0:
                continue
            
            increase = self._calculate_increase(
                baseline_metric.total_time,
                current_metric.total_time
            )
            
            if increase > self.time_threshold:
                result.increased_time[syscall] = {
                    "baseline_ms": baseline_metric.total_time,
                    "current_ms": current_metric.total_time,
                    "increase_pct": increase * 100
                }
                result.is_regression = True
                if increase > 0.50:
                    result.severity = "high"
        
        # Generate details
        result.details = self._generate_report_details(result)
        
        return result
    
    def _extract_all_syscalls(self, report: TraceReport) -> Dict[str, SyscallMetrics]:
        """Extract all syscalls from a report"""
        all_syscalls = {}
        for process in report.processes.values():
            all_syscalls.update(process.syscalls)
        return all_syscalls
    
    def _calculate_increase(self, baseline: float, current: float) -> float:
        """Calculate percentage increase"""
        if baseline == 0:
            return 1.0 if current > 0 else 0.0
        return (current - baseline) / baseline
    
    def _generate_report_details(self, result: RegressionResult) -> str:
        """Generate human-readable report details"""
        lines = []
        
        if result.new_syscalls:
            lines.append(f"🆕 New syscalls detected: {', '.join(result.new_syscalls)}")
        
        if result.removed_syscalls:
            lines.append(f"🗑️  Removed syscalls: {', '.join(result.removed_syscalls)}")
        
        if result.increased_calls:
            lines.append("📈 Increased call counts:")
            for syscall, data in result.increased_calls.items():
                lines.append(
                    f"  - {syscall}: {data['baseline']} → {data['current']} "
                    f"({data['increase_pct']:.1f}%)"
                )
        
        if result.increased_time:
            lines.append("⏱️  Increased execution time:")
            for syscall, data in result.increased_time.items():
                lines.append(
                    f"  - {syscall}: {data['baseline_ms']:.2f}ms → {data['current_ms']:.2f}ms "
                    f"({data['increase_pct']:.1f}%)"
                )
        
        return "\n".join(lines)
    
    def get_syscall_summary(self, report: TraceReport) -> Dict[str, int]:
        """Get summary of most-called syscalls"""
        all_syscalls = self._extract_all_syscalls(report)
        summary = {name: metric.count for name, metric in all_syscalls.items()}
        return dict(sorted(summary.items(), key=lambda x: x[1], reverse=True))
    
    def categorize_syscalls_by_type(self, report: TraceReport) -> Dict[SyscallType, int]:
        """Categorize syscalls by type"""
        all_syscalls = self._extract_all_syscalls(report)
        categories = {}
        
        for metric in all_syscalls.values():
            if metric.category not in categories:
                categories[metric.category] = 0
            categories[metric.category] += metric.count
        
        return categories