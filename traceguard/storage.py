"""Storage layer for trace data"""

import json
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime
from .models import TraceReport


class TraceStorage:
    """Handles JSON storage and retrieval of trace reports"""
    
    def __init__(self, base_dir: str = "./traceguard_data"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)
    
    def save_report(self, report: TraceReport, filename: Optional[str] = None) -> str:
        """
        Save trace report to JSON file
        
        Args:
            report: TraceReport to save
            filename: Optional custom filename
        
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = report.timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"trace_{timestamp}.json"
        
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(report.dict(), f, indent=2, default=str)
        
        return str(filepath)
    
    def load_report(self, filename: str) -> TraceReport:
        """
        Load trace report from JSON file
        
        Args:
            filename: Filename to load
        
        Returns:
            TraceReport object
        """
        filepath = self.reports_dir / filename
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return TraceReport(**data)
    
    def list_reports(self) -> List[str]:
        """List all saved reports"""
        return [f.name for f in self.reports_dir.glob("*.json")]
    
    def get_latest_report(self) -> Optional[TraceReport]:
        """Get the latest report"""
        reports = list(self.reports_dir.glob("*.json"))
        if not reports:
            return None
        
        latest = max(reports, key=lambda p: p.stat().st_mtime)
        return self.load_report(latest.name)
    
    def get_baseline(self, label: str = "baseline") -> Optional[TraceReport]:
        """Get baseline report by label"""
        filepath = self.base_dir / f"{label}.json"
        if filepath.exists():
            with open(filepath, 'r') as f:
                data = json.load(f)
            return TraceReport(**data)
        return None
    
    def save_baseline(self, report: TraceReport, label: str = "baseline") -> str:
        """Save a report as baseline"""
        filepath = self.base_dir / f"{label}.json"
        with open(filepath, 'w') as f:
            json.dump(report.dict(), f, indent=2, default=str)
        return str(filepath)
    
    def delete_report(self, filename: str) -> None:
        """Delete a report"""
        filepath = self.reports_dir / filename
        if filepath.exists():
            filepath.unlink()


class TraceDatabase:
    """SQLite database for persistent trace metrics"""
    
    def __init__(self, db_path: str = "./traceguard.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    git_commit TEXT,
                    git_branch TEXT,
                    build_id TEXT,
                    test_command TEXT,
                    duration REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS syscalls (
                    id INTEGER PRIMARY KEY,
                    trace_id INTEGER,
                    name TEXT,
                    count INTEGER,
                    total_time REAL,
                    avg_time REAL,
                    category TEXT,
                    errors INTEGER,
                    FOREIGN KEY (trace_id) REFERENCES traces(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS regressions (
                    id INTEGER PRIMARY KEY,
                    trace_id INTEGER,
                    is_regression BOOLEAN,
                    severity TEXT,
                    details TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (trace_id) REFERENCES traces(id)
                )
            """)
            
            conn.commit()
    
    def save_trace(self, report: TraceReport) -> int:
        """Save trace to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO traces (timestamp, git_commit, git_branch, build_id, test_command, duration)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                report.timestamp.isoformat(),
                report.git_commit,
                report.git_branch,
                report.build_id,
                report.test_command,
                report.duration
            ))
            
            trace_id = cursor.lastrowid
            
            # Save syscalls
            for process in report.processes.values():
                for syscall_name, metric in process.syscalls.items():
                    cursor.execute("""
                        INSERT INTO syscalls (trace_id, name, count, total_time, avg_time, category, errors)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        trace_id,
                        metric.name,
                        metric.count,
                        metric.total_time,
                        metric.avg_time,
                        metric.category,
                        metric.errors
                    ))
            
            conn.commit()
            return trace_id
    
    def get_trace_history(self, limit: int = 100) -> List[Dict]:
        """Get recent traces"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM traces ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_syscall_stats(self, syscall_name: str, limit: int = 100) -> List[Dict]:
        """Get historical stats for a syscall"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT t.timestamp, s.count, s.total_time, s.avg_time
                FROM syscalls s
                JOIN traces t ON s.trace_id = t.id
                WHERE s.name = ?
                ORDER BY t.timestamp DESC
                LIMIT ?
            """, (syscall_name, limit))
            
            return [dict(row) for row in cursor.fetchall()]