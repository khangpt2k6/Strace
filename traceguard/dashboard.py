"""Flask web dashboard for TraceGuard"""

from flask import Flask, render_template, jsonify, request
from pathlib import Path
import json
from datetime import datetime, timedelta
from .storage import TraceStorage, TraceDatabase
from .analyzer import SyscallAnalyzer
from .models import TraceReport


def create_app(storage_dir: str = "./traceguard_data") -> Flask:
    """Create Flask application"""
    app = Flask(__name__, template_folder='templates')
    
    storage = TraceStorage(storage_dir)
    db = TraceDatabase(str(Path(storage_dir) / "traceguard.db"))
    analyzer = SyscallAnalyzer()
    
    @app.route('/')
    def index():
        """Dashboard home page"""
        return render_template('index.html')
    
    @app.route('/api/reports')
    def get_reports():
        """Get all reports"""
        reports = storage.list_reports()
        return jsonify({
            "reports": reports,
            "count": len(reports)
        })
    
    @app.route('/api/reports/latest')
    def get_latest_report():
        """Get latest report"""
        try:
            report = storage.get_latest_report()
            if report:
                return jsonify(report.dict(by_alias=False))
            return jsonify({"error": "No reports found"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/reports/<filename>')
    def get_report(filename):
        """Get specific report"""
        try:
            report = storage.load_report(filename)
            return jsonify(report.dict(by_alias=False))
        except Exception as e:
            return jsonify({"error": str(e)}), 404
    
    @app.route('/api/reports/<filename>/summary')
    def get_report_summary(filename):
        """Get report summary"""
        try:
            report = storage.load_report(filename)
            summary = analyzer.get_syscall_summary(report)
            categories = analyzer.categorize_syscalls_by_type(report)
            
            return jsonify({
                "filename": filename,
                "timestamp": report.timestamp.isoformat(),
                "command": report.test_command,
                "syscall_summary": dict(list(summary.items())[:20]),
                "categories": {str(k): v for k, v in categories.items()},
                "total_syscalls": sum(summary.values()),
                "unique_syscalls": len(summary)
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/statistics')
    def get_statistics():
        """Get overall statistics"""
        try:
            reports = storage.list_reports()
            
            if not reports:
                return jsonify({
                    "total_runs": 0,
                    "top_syscalls": {},
                    "recent_runs": []
                })
            
            # Load recent reports
            recent_reports = []
            for filename in sorted(reports)[-10:]:
                try:
                    report = storage.load_report(filename)
                    recent_reports.append(report)
                except:
                    pass
            
            # Aggregate syscalls
            all_syscalls = {}
            for report in recent_reports:
                for process in report.processes.values():
                    for name, metric in process.syscalls.items():
                        if name not in all_syscalls:
                            all_syscalls[name] = 0
                        all_syscalls[name] += metric.count
            
            top_syscalls = dict(sorted(all_syscalls.items(), key=lambda x: x[1], reverse=True)[:15])
            
            return jsonify({
                "total_runs": len(reports),
                "top_syscalls": top_syscalls,
                "recent_runs": [
                    {
                        "filename": r.timestamp.strftime("%Y%m%d_%H%M%S"),
                        "timestamp": r.timestamp.isoformat(),
                        "command": r.test_command,
                        "total_syscalls": sum(p.total_syscalls for p in r.processes.values())
                    }
                    for r in recent_reports
                ]
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/syscall/<syscall_name>/history')
    def get_syscall_history(syscall_name):
        """Get history for a specific syscall"""
        try:
            reports = storage.list_reports()
            
            history = []
            for filename in sorted(reports)[-50:]:
                try:
                    report = storage.load_report(filename)
                    for process in report.processes.values():
                        if syscall_name in process.syscalls:
                            metric = process.syscalls[syscall_name]
                            history.append({
                                "timestamp": report.timestamp.isoformat(),
                                "count": metric.count,
                                "total_time": metric.total_time,
                                "avg_time": metric.avg_time
                            })
                            break
                except:
                    pass
            
            return jsonify({
                "syscall": syscall_name,
                "history": history
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/baseline')
    def get_baseline():
        """Get baseline report"""
        try:
            report = storage.get_baseline()
            if report:
                return jsonify(report.dict(by_alias=False))
            return jsonify({"error": "No baseline found"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/baseline', methods=['POST'])
    def set_baseline():
        """Set baseline from current trace"""
        try:
            data = request.json
            filename = data.get('filename')
            
            if not filename:
                return jsonify({"error": "No filename provided"}), 400
            
            report = storage.load_report(filename)
            storage.save_baseline(report)
            
            return jsonify({"message": "Baseline set successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @app.route('/api/health')
    def health_check():
        """Health check endpoint"""
        return jsonify({"status": "ok", "version": "0.1.0"})
    
    return app


def create_html_template() -> str:
    """Create HTML template for dashboard"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TraceGuard Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 40px;
            text-align: center;
        }
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        main {
            padding: 40px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .card h3 {
            color: #333;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
            opacity: 0.7;
        }
        .card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #e9ecef;
            font-weight: 600;
            color: #333;
        }
        table td {
            padding: 12px;
            border-bottom: 1px solid #e9ecef;
        }
        table tr:hover {
            background: #f8f9fa;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #667eea;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        footer {
            background: #f8f9fa;
            border-top: 1px solid #e9ecef;
            padding: 20px 40px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 TraceGuard</h1>
            <p>System Call Regression Detection Dashboard</p>
        </header>
        
        <main>
            <div class="grid" id="stats"></div>
            
            <h2>📊 Recent Traces</h2>
            <table id="reports-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Command</th>
                        <th>Syscalls</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="reports-body">
                    <tr><td colspan="4" class="loading">Loading...</td></tr>
                </tbody>
            </table>
            
            <h2 style="margin-top: 40px;">⭐ Top Syscalls</h2>
            <table id="syscalls-table">
                <thead>
                    <tr>
                        <th>Syscall</th>
                        <th>Count</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="syscalls-body">
                    <tr><td colspan="3" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </main>
        
        <footer>
            <p>TraceGuard v0.1.0 | CI/CD System Call Regression Detection</p>
        </footer>
    </div>
    
    <script>
        async function loadStats() {
            try {
                const res = await fetch('/api/statistics');
                const data = await res.json();
                
                const statsHtml = `
                    <div class="card">
                        <h3>Total Runs</h3>
                        <div class="value">${data.total_runs}</div>
                    </div>
                    <div class="card">
                        <h3>Unique Syscalls</h3>
                        <div class="value">${Object.keys(data.top_syscalls).length}</div>
                    </div>
                `;
                
                document.getElementById('stats').innerHTML = statsHtml;
                
                // Load reports
                let reportsHtml = '';
                for (const run of data.recent_runs) {
                    reportsHtml += `
                        <tr>
                            <td>${new Date(run.timestamp).toLocaleString()}</td>
                            <td>${run.command}</td>
                            <td>${run.total_syscalls}</td>
                            <td><a href="#">View</a></td>
                        </tr>
                    `;
                }
                document.getElementById('reports-body').innerHTML = reportsHtml;
                
                // Load top syscalls
                let syscallsHtml = '';
                for (const [name, count] of Object.entries(data.top_syscalls)) {
                    syscallsHtml += `
                        <tr>
                            <td>${name}</td>
                            <td>${count}</td>
                            <td><a href="#">History</a></td>
                        </tr>
                    `;
                }
                document.getElementById('syscalls-body').innerHTML = syscallsHtml;
            } catch (e) {
                console.error('Error loading stats:', e);
                document.getElementById('stats').innerHTML = `<div class="error">Error loading data</div>`;
            }
        }
        
        // Load on page load
        window.addEventListener('load', loadStats);
        
        // Refresh every 10 seconds
        setInterval(loadStats, 10000);
    </script>
</body>
</html>
    """