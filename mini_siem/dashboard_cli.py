#!/usr/bin/env python3
"""CLI tool to run the web dashboard"""

import argparse
import sys

from .web_dashboard import run_dashboard


def main():
    parser = argparse.ArgumentParser(description="Run Mini SIEM Web Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    try:
        print(f"Starting Mini SIEM Dashboard on http://{args.host}:{args.port}")
        print("Press Ctrl+C to stop")
        run_dashboard(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\nDashboard stopped")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting dashboard: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
