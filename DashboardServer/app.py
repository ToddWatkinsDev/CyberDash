from flask import Flask, render_template, request, redirect
import subprocess
import threading
import os
import sys
from datetime import datetime
import requests
from dns_checker import check_dns_spoofing
import logging
import ssl
import socket
from urllib.parse import urlparse
import hashlib

# Import the Waitress server
from waitress import serve

# Suppress urllib3 warnings for cleaner output
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

app = Flask(__name__)

# Define the URL for Tailwind CSS
TAILWIND_URL = "https://cdn.tailwindcss.com?version=3.4.3"

# This function adds headers to all responses to prevent caching
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Route for the main dashboard
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# Routes for the files in the "sites" array
@app.route('/DownDetector/Down_Detector_Test.html')
def down_detector_test():
    return render_template('DownDetector/Down_Detector_Test.html')

@app.route('/FortinetScraper/Attempt3/Scraper.html')
def fortinet_scraper():
    return render_template('FortinetScraper/Attempt3/Scraper.html')

@app.route('/History/History.html')
def history():
    return render_template('History/History.html')

@app.route('/NewNews/BbcTech.html')
def bbc_tech():
    return render_template('NewNews/BbcTech.html')

@app.route('/NewNews/BleepingComputer.html')
def bleeping_computer():
    return render_template('NewNews/BleepingComputer.html')

@app.route('/NewNews/WiredNews.html')
def wired_news():
    return render_template('NewNews/WiredNews.html')

# A new route for the hidden redirect tool
@app.route('/redirect-tool', methods=['GET', 'POST'])
def redirect_tool():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            # Ensure the URL has a scheme (like https://)
            if not url.startswith('http://') and not url.startswith('https://'):
                url = 'https://' + url
            # Redirect to the provided external URL
            return redirect(url)
        else:
            return "Please enter a URL.", 400
    return render_template('tools/redirect_tool.html')

# Function to run all the data collection scripts
def run_scripts_in_separate_processes():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scripts_dir = os.path.join(base_dir, "scripts")

    scripts_to_run = [
        "Fortinet_Attack_History.py",
        "Fortiscraper3.py",
        "down_detector.py",
        "news.py"
    ]

    for script_name in scripts_to_run:
        script_path = os.path.join(scripts_dir, script_name)
        logging.info(f"Starting script: {script_name}...")
        try:
            # Use Popen to run the script non-blocking
            # We explicitly redirect stderr to a pipe so we can read it if it fails
            # This makes the error output more controlled
            process = subprocess.Popen([sys.executable, script_path], stderr=subprocess.PIPE, text=True)
            # You can optionally read the stderr here if you need to
            # err_output = process.communicate()[1]
            # if err_output:
            #     logging.error(f"Error from {script_name}:\n{err_output}")
            logging.info(f"Successfully started {script_name}.")
        except FileNotFoundError:
            logging.error(f"Error: The script {script_name} was not found at {script_path}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while trying to run {script_name}: {e}")

# A new function to check the status of an external URL
def check_url_status(url):
    try:
        # We perform a GET request with a short timeout to check if the URL is reachable
        response = requests.get(url, timeout=5)
        # A status code of 200 means the request was successful
        if response.status_code == 200:
            return "OK", "Successfully connected to the URL."
        else:
            return "FAIL", f"Received status code {response.status_code}."
    except requests.exceptions.RequestException as e:
        # Any exception (e.g., DNS error, timeout, connection refused) means a failure
        return "FAIL", f"Request failed: {e}"

# This new function performs all the integrity checks and prints the results
def perform_integrity_checks():
    logging.info("\n--- Running Integrity Checks ---")
    
    # Check local files
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    test_files = {
        "Fortinet Attack History": os.path.join(data_dir, "fortinet_attack_history.txt"),
        "FortiScraper Data": os.path.join(data_dir, "fortinet_data.json"),
        "Down Detector Data": os.path.join(data_dir, "down_detector_data.json"),
        "News Feed Data": os.path.join(data_dir, "news_data.json")
    }
    
    for test_name, file_path in test_files.items():
        if os.path.exists(file_path):
            last_modified_timestamp = os.path.getmtime(file_path)
            last_modified = datetime.fromtimestamp(last_modified_timestamp).strftime('%Y-%m-%d %H:%M:%S')
            logging.info(f"[{test_name}] OK - Last modified: {last_modified}")
        else:
            logging.warning(f"[{test_name}] FAIL - File not found.")

    # Check external URL
    tailwind_status, tailwind_message = check_url_status(TAILWIND_URL)
    logging.info(f"[External URL: {TAILWIND_URL}] {tailwind_status} - {tailwind_message}")

    # New integrity check for Tailwind CSS hash
    check_tailwind_integrity()

    # Check for DNS spoofing
    dns_status, dns_message = check_dns_spoofing(TAILWIND_URL.replace('https://', ''))
    logging.info(f"[DNS Consistency Check] {dns_status} - {dns_message}")
    
    # New function to get SSL certificate details
    def get_ssl_certificate(hostname, port=443):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': cert['subject'],
                        'issuer': cert['issuer'],
                        'notAfter': cert['notAfter']
                    }
        except Exception as e:
            return {'error': str(e)}

    # List of scraping sites to check
    scraped_sites = [
        "https://www.fortinet.com",
        "https://www.downdetector.com",
        "https://www.bbc.co.uk",
        "https://www.bleepingcomputer.com",
        "https://www.wired.com"
    ]

    logging.info("\n--- SSL Certificate Checks ---")
    for site_url in scraped_sites:
        try:
            hostname = urlparse(site_url).hostname
            cert_info = get_ssl_certificate(hostname)
            if 'error' in cert_info:
                logging.warning(f"[{hostname}] SSL Check FAILED - {cert_info['error']}")
            else:
                subject_cn = next((item[1] for item in cert_info['subject'][0] if item[0] == 'commonName'), 'N/A')
                issuer_cn = next((item[1] for item in cert_info['issuer'][0] if item[0] == 'commonName'), 'N/A')
                not_after = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d %H:%M:%S')
                logging.info(f"[{hostname}] SSL Check OK - Subject: {subject_cn}, Issuer: {issuer_cn}, Valid until: {not_after}")
        except Exception as e:
            logging.error(f"An error occurred while checking {site_url}: {e}")

    logging.info("--- All Checks Complete ---\n")

def check_tailwind_integrity():
    logging.info(f"Checking integrity of {TAILWIND_URL}...")
    
    # File path for the local hash file
    HASH_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tailwind_hash.txt')
    
    # 1. Read the known-good hash from the file
    known_good_hash = ""
    try:
        with open(HASH_FILE_PATH, 'r') as f:
            known_good_hash = f.read().strip()
            if not known_good_hash:
                logging.error(f"[Tailwind CSS Hash Check] FAIL - The hash file is empty: {HASH_FILE_PATH}")
                return False
    except FileNotFoundError:
        logging.error(f"[Tailwind CSS Hash Check] FAIL - Hash file not found: {HASH_FILE_PATH}")
        return False
    except Exception as e:
        logging.error(f"[Tailwind CSS Hash Check] FAIL - Could not read the hash file: {e}")
        return False
    
    # 2. Download the external file and compute its hash
    try:
        # Use verify=False to bypass SSL check if needed.
        # This is a temporary solution for testing; remove for production.
        response = requests.get(TAILWIND_URL, timeout=10, verify=False)
        response.raise_for_status()
        
        tailwind_content = response.content
        current_hash = hashlib.sha256(tailwind_content).hexdigest()
        
        # 3. Compare the hashes
        if current_hash == known_good_hash:
            logging.info("[Tailwind CSS Hash Check] OK - Hash matches the stored value.")
            return True
        else:
            logging.warning(f"[Tailwind CSS Hash Check] FAIL - Hash mismatch! The file may be compromised. Expected: {known_good_hash}, Got: {current_hash}")
            return False
            
    except requests.exceptions.RequestException as e:
        logging.error(f"[Tailwind CSS Hash Check] FAIL - Could not download the file: {e}")
        return False
    except Exception as e:
        logging.error(f"[Tailwind CSS Hash Check] FAIL - An unexpected error occurred: {e}")
        return False

if __name__ == '__main__':
    # Configure logging to output to a file
    logging.basicConfig(
        filename='integrity.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Start a new thread to run the integrity checks at startup
    check_thread = threading.Thread(target=perform_integrity_checks)
    check_thread.start()

    # Start a new thread to run the scripts concurrently
    script_thread = threading.Thread(target=run_scripts_in_separate_processes)
    script_thread.daemon = True
    script_thread.start()

    # The Flask development server is not for production use.
    # We will now use Waitress, a production-grade WSGI server, to handle requests.
    logging.info("Starting production-ready Waitress web server...")
    # 'serve' runs the Flask app using Waitress, handling multiple users robustly.
    serve(app, host='0.0.0.0', port=8000, threads=8)