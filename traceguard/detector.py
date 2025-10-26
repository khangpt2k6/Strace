"""Anomaly detection for system calls"""

from typing import Dict, List, Tuple, Optional
from statistics import mean, stdev
from .models import SyscallMetrics, TraceReport


class AnomalyDetector:
    """Detects anomalies in syscall patterns"""
    
    def __init__(self, z_score_threshold: float = 2.5):
        """
        Initialize detector with statistical threshold
        
        Args:
            z_score_threshold: Z-score threshold for anomaly detection (default 2.5)
        """
        self.z_score_threshold = z_score_threshold
    
    def detect_anomalies(
        self,
        current: TraceReport,
        historical: List[TraceReport]
    ) -> Dict[str, any]:
        """
        Detect anomalies in current report compared to historical data
        
        Args:
            current: Current trace report
            historical: List of historical trace reports
        
        Returns:
            Dictionary with anomalies detected
        """
        if len(historical) < 3:
            return {"anomalies": [], "warning": "Insufficient historical data for reliable detection"}
        
        anomalies = []
        current_syscalls = self._extract_all_syscalls(current)
        
        for syscall_name, current_metric in current_syscalls.items():
            # Get historical data for this syscall
            historical_values = []
            for report in historical:
                syscalls = self._extract_all_syscalls(report)
                if syscall_name in syscalls:
                    historical_values.append(syscalls[syscall_name].count)
            
            if len(historical_values) < 2:
                continue
            
            # Calculate statistics
            avg = mean(historical_values)
            if len(historical_values) > 1:
                std = stdev(historical_values)
                z_score = (current_metric.count - avg) / (std + 0.001)  # Avoid division by zero
                
                # Check if anomaly
                if abs(z_score) > self.z_score_threshold:
                    anomalies.append({
                        "syscall": syscall_name,
                        "current_value": current_metric.count,
                        "historical_mean": avg,
                        "std_dev": std,
                        "z_score": z_score,
                        "severity": self._calculate_severity(z_score)
                    })
        
        return {
            "anomalies": sorted(anomalies, key=lambda x: abs(x["z_score"]), reverse=True),
            "total_anomalies": len(anomalies)
        }
    
    def detect_syscall_spikes(
        self,
        reports: List[TraceReport],
        window_size: int = 5
    ) -> Dict[str, any]:
        """
        Detect sudden spikes in syscall counts
        
        Args:
            reports: List of trace reports
            window_size: Rolling window size for comparison
        
        Returns:
            Dictionary with spikes detected
        """
        if len(reports) < window_size:
            return {"spikes": []}
        
        spikes = []
        all_syscalls = set()
        
        # Collect all syscall names
        for report in reports:
            syscalls = self._extract_all_syscalls(report)
            all_syscalls.update(syscalls.keys())
        
        # Check each syscall
        for syscall_name in all_syscalls:
            values = []
            for report in reports:
                syscalls = self._extract_all_syscalls(report)
                values.append(syscalls.get(syscall_name, SyscallMetrics(name=syscall_name)).count)
            
            # Check last value against window average
            if len(values) >= window_size:
                recent = values[-1]
                window_avg = mean(values[-window_size:-1])
                
                if window_avg > 0:
                    spike_ratio = recent / window_avg
                    if spike_ratio > 2.0:  # 2x increase is a spike
                        spikes.append({
                            "syscall": syscall_name,
                            "current": recent,
                            "window_avg": window_avg,
                            "spike_ratio": spike_ratio
                        })
        
        return {
            "spikes": sorted(spikes, key=lambda x: x["spike_ratio"], reverse=True),
            "total_spikes": len(spikes)
        }
    
    def predict_trend(
        self,
        reports: List[TraceReport],
        syscall_name: str
    ) -> Dict[str, any]:
        """
        Predict trend for a specific syscall
        
        Args:
            reports: List of trace reports
            syscall_name: Name of syscall to analyze
        
        Returns:
            Trend prediction data
        """
        values = []
        timestamps = []
        
        for i, report in enumerate(reports):
            syscalls = self._extract_all_syscalls(report)
            if syscall_name in syscalls:
                values.append(syscalls[syscall_name].count)
                timestamps.append(i)
        
        if len(values) < 2:
            return {"error": "Insufficient data for trend analysis"}
        
        # Simple linear regression
        slope = self._calculate_slope(values)
        
        return {
            "syscall": syscall_name,
            "values": values,
            "slope": slope,
            "trend": "increasing" if slope > 0.05 else "decreasing" if slope < -0.05 else "stable",
            "last_value": values[-1],
            "first_value": values[0],
            "change": values[-1] - values[0]
        }
    
    def _extract_all_syscalls(self, report: TraceReport) -> Dict[str, SyscallMetrics]:
        """Extract all syscalls from a report"""
        all_syscalls = {}
        for process in report.processes.values():
            all_syscalls.update(process.syscalls)
        return all_syscalls
    
    def _calculate_severity(self, z_score: float) -> str:
        """Calculate severity based on z-score"""
        z_abs = abs(z_score)
        if z_abs > 4.0:
            return "critical"
        elif z_abs > 3.0:
            return "high"
        elif z_abs > 2.5:
            return "medium"
        return "low"
    
    def _calculate_slope(self, values: List[float]) -> float:
        """Calculate simple linear regression slope"""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = sum(values) / n
        
        numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator