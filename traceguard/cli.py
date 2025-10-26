"""Command-line interface for TraceGuard"""

import click
import json
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime
from .capture import TraceCapture
from .analyzer import SyscallAnalyzer
from .detector import AnomalyDetector
from .storage import TraceStorage, TraceDatabase
from .config import ConfigManager
from .models import TraceReport


@click.group()
@click.version_option()
def main():
    """TraceGuard - CI/CD System Call Regression Detection"""
    pass


@main.command()
@click.option('--command', required=True, help='Command to trace')
@click.option('--output', required=True, help='Output JSON file')
@click.option('--label', default='trace', help='Label for this run')
@click.option('--git-commit', default=None, help='Git commit hash')
@click.option('--git-branch', default=None, help='Git branch name')
@click.option('--build-id', default=None, help='Build ID from CI/CD')
@click.option('--storage-dir', default='./traceguard_data', help='Storage directory')
def capture(command, output, label, git_commit, git_branch, build_id, storage_dir):
    """Capture system calls from a command"""
    click.echo("🔍 TraceGuard: Capturing system calls...")
    
    try:
        tracer = TraceCapture(output_dir=storage_dir)
        
        click.echo(f"Running: {command}")
        report = tracer.trace_command(
            command=command,
            label=label,
            git_commit=git_commit,
            git_branch=git_branch
        )
        
        # Update report with build info
        report.build_id = build_id
        
        # Save to JSON
        with open(output, 'w') as f:
            json.dump(report.dict(), f, indent=2, default=str)
        
        click.echo(f"✅ Trace captured: {output}")
        click.echo(f"   Unique syscalls: {sum(p.unique_syscalls for p in report.processes.values())}")
        click.echo(f"   Total syscalls: {sum(p.total_syscalls for p in report.processes.values())}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--baseline', required=True, help='Baseline trace file')
@click.option('--current', required=True, help='Current trace file')
@click.option('--output', default=None, help='Output comparison JSON')
@click.option('--fail', is_flag=True, help='Fail with exit code 1 on regression')
@click.option('--verbose', is_flag=True, help='Verbose output')
def compare(baseline, current, output, fail, verbose):
    """Compare current trace against baseline"""
    click.echo("📊 TraceGuard: Comparing traces...")
    
    try:
        # Load reports
        with open(baseline, 'r') as f:
            baseline_data = json.load(f)
        baseline_report = TraceReport(**baseline_data)
        
        with open(current, 'r') as f:
            current_data = json.load(f)
        current_report = TraceReport(**current_data)
        
        # Run analysis
        analyzer = SyscallAnalyzer(
            call_threshold=0.15,
            time_threshold=0.20
        )
        
        result = analyzer.compare_reports(baseline_report, current_report)
        
        # Output results
        click.echo(f"\n{'='*50}")
        click.echo(f"Regression Detected: {result.is_regression}")
        click.echo(f"Severity: {result.severity.upper()}")
        click.echo(f"{'='*50}\n")
        
        if result.details:
            click.echo(result.details)
        else:
            click.echo("✅ No regressions detected!")
        
        # Save output if requested
        if output:
            with open(output, 'w') as f:
                json.dump(result.dict(), f, indent=2, default=str)
            click.echo(f"\n📁 Comparison saved: {output}")
        
        # Exit with failure if requested and regression found
        if fail and result.is_regression:
            click.echo(f"\n❌ Pipeline would fail due to regression (severity: {result.severity})")
            sys.exit(1)
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--trace', required=True, help='Trace file to analyze')
@click.option('--output', default=None, help='Output analysis JSON')
@click.option('--top', default=10, help='Show top N syscalls')
def analyze(trace, output, top):
    """Analyze a trace report"""
    click.echo("🔬 TraceGuard: Analyzing trace...")
    
    try:
        with open(trace, 'r') as f:
            data = json.load(f)
        report = TraceReport(**data)
        
        analyzer = SyscallAnalyzer()
        
        # Get summary
        summary = analyzer.get_syscall_summary(report)
        
        click.echo(f"\n{'='*50}")
        click.echo(f"Top {top} Most Called Syscalls")
        click.echo(f"{'='*50}\n")
        
        for i, (syscall, count) in enumerate(list(summary.items())[:top], 1):
            click.echo(f"{i:2d}. {syscall:20s} {count:8d} calls")
        
        # Get categorization
        categories = analyzer.categorize_syscalls_by_type(report)
        
        click.echo(f"\n{'='*50}")
        click.echo(f"Syscalls by Category")
        click.echo(f"{'='*50}\n")
        
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            click.echo(f"  {category:15s} {count:8d} calls")
        
        if output:
            analysis_data = {
                "timestamp": datetime.now().isoformat(),
                "trace_file": trace,
                "summary": summary,
                "categories": {str(k): v for k, v in categories.items()}
            }
            with open(output, 'w') as f:
                json.dump(analysis_data, f, indent=2)
            click.echo(f"\n📁 Analysis saved: {output}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--trace', required=True, help='Current trace file')
@click.option('--history-dir', default='./traceguard_data/reports', help='Historical traces directory')
@click.option('--min-history', default=5, help='Minimum historical traces to use')
def detect_anomalies(trace, history_dir, min_history):
    """Detect anomalies in syscall patterns"""
    click.echo("🎯 TraceGuard: Detecting anomalies...")
    
    try:
        # Load current report
        with open(trace, 'r') as f:
            data = json.load(f)
        current_report = TraceReport(**data)
        
        # Load historical reports
        history_path = Path(history_dir)
        historical_reports = []
        
        if history_path.exists():
            for report_file in sorted(history_path.glob("*.json"))[-min_history:]:
                with open(report_file, 'r') as f:
                    hist_data = json.load(f)
                historical_reports.append(TraceReport(**hist_data))
        
        if len(historical_reports) < min_history:
            click.echo(f"⚠️  Insufficient historical data ({len(historical_reports)} < {min_history})")
            return
        
        detector = AnomalyDetector()
        
        # Detect anomalies
        result = detector.detect_anomalies(current_report, historical_reports)
        
        click.echo(f"\n{'='*50}")
        click.echo(f"Anomalies Detected: {result['total_anomalies']}")
        click.echo(f"{'='*50}\n")
        
        if result['anomalies']:
            for anomaly in result['anomalies'][:10]:
                click.echo(
                    f"  {anomaly['syscall']:20s} "
                    f"z-score: {anomaly['z_score']:6.2f} "
                    f"current: {anomaly['current_value']:6d} "
                    f"avg: {anomaly['historical_mean']:6.1f} "
                    f"({anomaly['severity'].upper()})"
                )
        else:
            click.echo("✅ No anomalies detected!")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--save-as', default='baseline', help='Label for baseline')
@click.option('--trace', required=True, help='Trace file to save as baseline')
@click.option('--storage-dir', default='./traceguard_data', help='Storage directory')
def save_baseline(save_as, trace, storage_dir):
    """Save a trace as baseline for comparisons"""
    click.echo(f"💾 TraceGuard: Saving baseline as '{save_as}'...")
    
    try:
        with open(trace, 'r') as f:
            data = json.load(f)
        report = TraceReport(**data)
        
        storage = TraceStorage(storage_dir)
        path = storage.save_baseline(report, save_as)
        
        click.echo(f"✅ Baseline saved: {path}")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--port', default=5000, help='Dashboard port')
@click.option('--host', default='127.0.0.1', help='Dashboard host')
@click.option('--storage-dir', default='./traceguard_data', help='Storage directory')
def dashboard(port, host, storage_dir):
    """Start the web dashboard"""
    click.echo(f"🚀 Starting TraceGuard Dashboard at http://{host}:{port}")
    
    try:
        from .dashboard import create_app
        app = create_app(storage_dir)
        app.run(host=host, port=port, debug=True)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--config', default='.traceguard.json', help='Config file to create')
def init_config(config):
    """Initialize configuration file"""
    click.echo(f"⚙️  Creating configuration file: {config}")
    
    default_config = {
        "baseline_file": None,
        "syscall_threshold": 0.15,
        "time_threshold": 0.20,
        "fail_on_new_syscalls": True,
        "ignore_syscalls": ["mmap", "brk", "rt_sigaction", "mprotect"],
        "max_reports": 100,
        "database_path": "./traceguard.db"
    }
    
    with open(config, 'w') as f:
        json.dump(default_config, f, indent=2)
    
    click.echo(f"✅ Configuration file created: {config}")
    click.echo(f"   Edit this file to customize TraceGuard behavior")


if __name__ == '__main__':
    main()