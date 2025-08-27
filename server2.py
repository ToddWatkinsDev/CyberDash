# Modified server.py

import http.server
import socketserver
import time
import os
import subprocess

# Define the port number for the server to listen on.
PORT = 8000

# Define the list of other Python files to run.
# Make sure the paths are correct relative to where you run the server.
other_scripts = [
    "FortinetScraper/Attempt3/Fortiscraper3.py",
    "DownDetector/down_detector.py",
    "History/Fortinet_Attack_History.py"
]

# The rest of your code remains the same.
class UsageStats:
    """A simple data class to hold server usage statistics."""
    total_requests = 0
    files_served = 0
    last_request_time = None

class MyRequestHandler(http.server.SimpleHTTPRequestHandler):
    usage_stats = UsageStats()

    def do_GET(self):
        try:
            self.usage_stats.total_requests += 1
            self.usage_stats.last_request_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            
            if os.path.isdir(self.path[1:]):
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write("Directory listing is forbidden.".encode('utf-8'))
                return

            if self.path == '/usage':
                utilization_rate = 0.0
                if self.usage_stats.total_requests > 0:
                    utilization_rate = (self.usage_stats.files_served / self.usage_stats.total_requests) * 100
                stats_text = (
                    f"Server Usage Statistics:\n"
                    f"--------------------------\n"
                    f"Total Requests: {self.usage_stats.total_requests}\n"
                    f"Files Served: {self.usage_stats.files_served}\n"
                    f"Utilization Rate: {utilization_rate:.2f}%\n"
                    f"Last Request Time (UTC): {self.usage_stats.last_request_time}"
                )
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(stats_text.encode('utf-8'))
                return

            else:
                try:
                    super().do_GET()
                    self.usage_stats.files_served += 1
                except FileNotFoundError:
                    pass

        except ConnectionAbortedError:
            print("Client connection aborted.")
            return

# Use ThreadingTCPServer to handle multiple requests concurrently.
processes = []

try:
    # Launch the subprocesses using the defined paths.
    for script in other_scripts:
        print(f"Starting subprocess for: {script}")
        # Use r-strings for paths to avoid issues with backslashes.
        process = subprocess.Popen(['python', script])
        processes.append(process)

    with socketserver.ThreadingTCPServer(("", PORT), MyRequestHandler) as httpd:
        print(f"Serving files on port {PORT}...")
        httpd.serve_forever()

except KeyboardInterrupt:
    print("\nServer is shutting down.")
finally:
    print("Terminating subprocesses...")
    for process in processes:
        if process.poll() is None:
            process.terminate()
    print("All subprocesses terminated.")