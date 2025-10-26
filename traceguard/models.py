"""Data models and schemas for TraceGuard"""

from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class SyscallType(str, Enum):
    """Categories of system calls"""
    NETWORK = "network"
    FILE_IO = "file_io"
    PROCESS = "process"
    MEMORY = "memory"
    SIGNAL = "signal"
    OTHER = "other"


class SyscallMetrics(BaseModel):
    """Metrics for a single syscall"""
    name: str
    count: int = 0
    total_time: float = 0.0  # milliseconds
    avg_time: float = 0.0
    min_time: float = 0.0
    max_time: float = 0.0
    errors: int = 0
    category: SyscallType = SyscallType.OTHER
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    class Config:
        use_enum_values = True


class ProcessMetrics(BaseModel):
    """Overall process metrics"""
    pid: int
    command: str
    duration: float  # seconds
    total_syscalls: int = 0
    unique_syscalls: int = 0
    total_time: float = 0.0  # milliseconds spent in syscalls
    syscalls: Dict[str, SyscallMetrics] = Field(default_factory=dict)


class TraceReport(BaseModel):
    """Complete trace report for a run"""
    timestamp: datetime
    git_commit: Optional[str] = None
    git_branch: Optional[str] = None
    build_id: Optional[str] = None
    test_command: str
    duration: float
    processes: Dict[int, ProcessMetrics] = Field(default_factory=dict)
    environment: Dict[str, str] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class RegressionResult(BaseModel):
    """Results of regression comparison"""
    is_regression: bool
    severity: str = "low"  # low, medium, high, critical
    new_syscalls: List[str] = Field(default_factory=list)
    removed_syscalls: List[str] = Field(default_factory=list)
    increased_calls: Dict[str, Dict[str, float]] = Field(default_factory=dict)  # syscall -> {old_count, new_count}
    increased_time: Dict[str, Dict[str, float]] = Field(default_factory=dict)  # syscall -> {old_time, new_time}
    threshold_violations: List[Dict[str, Any]] = Field(default_factory=list)
    details: str = ""


class Config(BaseModel):
    """TraceGuard configuration"""
    baseline_file: Optional[str] = None
    syscall_threshold: float = 0.15  # 15% increase threshold
    time_threshold: float = 0.20  # 20% time increase threshold
    fail_on_new_syscalls: bool = True
    ignore_syscalls: List[str] = Field(default_factory=lambda: ["mmap", "brk", "rt_sigaction"])
    max_reports: int = 100  # Keep last 100 reports
    database_path: str = "./traceguard.db"


class DashboardStats(BaseModel):
    """Statistics for dashboard display"""
    total_runs: int = 0
    recent_runs: List[TraceReport] = Field(default_factory=list)
    most_called_syscalls: Dict[str, int] = Field(default_factory=dict)
    regression_history: List[Dict[str, Any]] = Field(default_factory=list)