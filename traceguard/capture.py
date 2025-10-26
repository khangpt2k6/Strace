"""Strace capture and parsing module"""

import subprocess
import os
import re
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
from .models import SyscallMetrics, ProcessMetrics, TraceReport, SyscallType


class StraceCapture:
    """Captures and parses strace output"""
    
    # Regex patterns for strace parsing
    SYSCALL_PATTERN = re.compile(
        r'(\w+)\(([^)]*)\)\s*=\s*(-?\d+|0x[0-9a-f]+)(?:\s+(\w+))?(?:\s+<(\d+\.\d+)>)?'
    )
    SUMMARY_PATTERN = re.compile(
        r'%\s+time\s+seconds\s+usecs/call\s+calls\s+errors\s+syscall'
    )
    SUMMARY_LINE_PATTERN = re.compile(
        r'^\s*([\d.]+)\s+([\d.]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\w+)'
    )
    
    SYSCALL_CATEGORIES = {
        'read': SyscallType.FILE_IO,
        'write': SyscallType.FILE_IO,
        'open': SyscallType.FILE_IO,
        'close': SyscallType.FILE_IO,
        'stat': SyscallType.FILE_IO,
        'fstat': SyscallType.FILE_IO,
        'lstat': SyscallType.FILE_IO,
        'poll': SyscallType.FILE_IO,
        'lseek': SyscallType.FILE_IO,
        'mmap': SyscallType.MEMORY,
        'mprotect': SyscallType.MEMORY,
        'munmap': SyscallType.MEMORY,
        'brk': SyscallType.MEMORY,
        'socket': SyscallType.NETWORK,
        'connect': SyscallType.NETWORK,
        'bind': SyscallType.NETWORK,
        'listen': SyscallType.NETWORK,
        'accept': SyscallType.NETWORK,
        'send': SyscallType.NETWORK,
        'recv': SyscallType.NETWORK,
        'sendto': SyscallType.NETWORK,
        'recvfrom': SyscallType.NETWORK,
        'fork': SyscallType.PROCESS,
        'exec': SyscallType.PROCESS,
        'clone': SyscallType.PROCESS,
        'exit': SyscallType.PROCESS,
        'wait': SyscallType.PROCESS,
        'signal': SyscallType.SIGNAL,
        'rt_sigaction': SyscallType.SIGNAL,
    }
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.strace_available = self._check_strace()
    
    def _check_strace(self) -> bool:
        """Check if strace is available"""
        try:
            subprocess.run(['strace', '-V'], capture_output=True, timeout=2)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def capture_command(self, command: str, output_file: Optional[str] = None) -> str:
        """
        Capture strace output for a command
        
        Args:
            command: Command to trace
            output_file: Optional file to save raw strace output
        
        Returns:
            Raw strace output
        """
        if not self.strace_available:
            raise RuntimeError("strace is not available. Please install it first.")
        
        strace_cmd = ['strace', '-c', '-v', '-f']
        
        if output_file:
            strace_cmd.extend(['-o', output_file])
        
        full_cmd = strace_cmd + ['-e', 'trace=all', 'sh', '-c', command]
        
        if self.verbose:
            print(f"Running: {' '.join(full_cmd)}")
        
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                timeout=300,  # 5 minute timeout
                text=True
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            raise RuntimeError("Strace execution timed out (> 5 minutes)")
    
    def parse_strace_output(self, output: str, pid: int = 1) -> ProcessMetrics:
        """
        Parse strace output into metrics
        
        Args:
            output: Raw strace output
            pid: Process ID
        
        Returns:
            ProcessMetrics object
        """
        metrics = ProcessMetrics(pid=pid, command="traced_process", duration=0)
        syscalls: Dict[str, SyscallMetrics] = {}
        
        lines = output.split('\n')
        in_summary = False
        
        for line in lines:
            # Check for summary section
            if self.SUMMARY_PATTERN.search(line):
                in_summary = True
                continue
            
            # Parse summary lines
            if in_summary:
                match = self.SUMMARY_LINE_PATTERN.match(line)
                if match:
                    time_pct, total_time, usecs_call, calls, errors, syscall = match.groups()
                    
                    if syscall not in syscalls:
                        syscalls[syscall] = SyscallMetrics(
                            name=syscall,
                            category=self._categorize_syscall(syscall)
                        )
                    
                    metric = syscalls[syscall]
                    metric.count = int(calls)
                    metric.total_time = float(total_time) * 1000  # Convert to ms
                    metric.avg_time = float(usecs_call) / 1000  # Convert to ms
                    metric.errors = int(errors)
        
        metrics.syscalls = syscalls
        metrics.total_syscalls = sum(m.count for m in syscalls.values())
        metrics.unique_syscalls = len(syscalls)
        metrics.total_time = sum(m.total_time for m in syscalls.values())
        
        return metrics
    
    def _categorize_syscall(self, syscall_name: str) -> SyscallType:
        """Categorize syscall by name"""
        for pattern, category in self.SYSCALL_CATEGORIES.items():
            if pattern in syscall_name:
                return category
        return SyscallType.OTHER


class TraceCapture:
    """High-level interface for tracing commands"""
    
    def __init__(self, output_dir: str = "./traces"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.capture = StraceCapture()
    
    def trace_command(
        self,
        command: str,
        label: Optional[str] = None,
        git_commit: Optional[str] = None,
        git_branch: Optional[str] = None,
    ) -> TraceReport:
        """
        Trace a command and generate a report
        
        Args:
            command: Command to trace
            label: Optional label for the run
            git_commit: Optional git commit hash
            git_branch: Optional git branch name
        
        Returns:
            TraceReport object
        """
        # Generate trace filename
        timestamp = datetime.now()
        filename = timestamp.strftime(f"%Y%m%d_%H%M%S_{label or 'trace'}.txt")
        trace_file = self.output_dir / filename
        
        # Capture strace
        raw_output = self.capture.capture_command(command, str(trace_file))
        
        # Parse output
        process_metrics = self.capture.parse_strace_output(raw_output)
        
        # Create report
        report = TraceReport(
            timestamp=timestamp,
            git_commit=git_commit,
            git_branch=git_branch,
            test_command=command,
            duration=0,  # Would need to extract from output
            processes={process_metrics.pid: process_metrics},
            environment={
                "os": os.uname().sysname,
                "hostname": os.uname().nodename,
                "python": f"{os.sys.version}",
            }
        )
        
        return report