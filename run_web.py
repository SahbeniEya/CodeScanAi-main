"""
This script runs the CodeScanAI web application.
"""

import os
import sys
import webbrowser
import threading
import time

# Add the current directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from codescanai.web.app import app


def open_browser():
    """Open the browser to the home page after a short delay."""
    time.sleep(1.5)  # Wait for the server to start
    webbrowser.open('http://127.0.0.1:5000/')


def main():
    """Run the web application."""
    # Start a thread to open the browser to the home page
    threading.Thread(target=open_browser).start()

    # Run the Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()
