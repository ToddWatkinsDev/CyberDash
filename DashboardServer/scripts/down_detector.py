import requests
import datetime
import json
import os
import time
import urllib3

# Disable SSL certificate warnings when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Logging Setup ---
DEBUG = False  # Set to False to silence debug logs

def log(message, level="DEBUG"):
    """Generic logger with timestamp and log level"""
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{level}] {ts} :: {message}")

def debug(message):
    if DEBUG:
        log(message, "DEBUG")

def error(message):
    log(message, "ERROR")

# --- Configuration ---
SNOWFLAKE_STATUS_API = "https://status.snowflake.com/api/v2/components.json"
MICROSOFT_STATUS_API = "https://status.cloud.microsoft/api/posts/m365Consumer"
FORTINET_APIS = [
    {"name": "Fortinet Anycast Query", "url": "https://2k10kk4nf91b.statuspage.io/api/v2/summary.json"},
    {"name": "Fortinet Anycast Update", "url": "https://py884f5vjpy3.statuspage.io/api/v2/summary.json"},
    {"name": "FGD SDNS Anycast", "url": "https://dq1kp00kn5f1.statuspage.io/api/v2/summary.json"},
    {"name": "FGD DNS DoT", "url": "https://q06s3wqk32zh.statuspage.io/api/v2/summary.json"},
    {"name": "FGD SDNS Unicast", "url": "https://mpbpks96wbvp.statuspage.io/api/v2/summary.json"}
]
WEBSITES_TO_CHECK = []

OUTPUT_DIRECTORY = "DashboardServer/templates/DownDetector"
FILE_NAME = "Down_Detector_Test.html"

# --- Core Functions ---

def get_status_from_snowflake_api(api_url):
    debug(f"Fetching Snowflake status from {api_url}")
    categorized_components = {"snowflake": [], "aws": [], "azure": []}
    try:
        response = requests.get(api_url, timeout=10, verify=False)
        debug(f"Snowflake API response code: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        debug(f"Snowflake returned {len(data.get('components', []))} components")

        group_lookup = {}
        for component in data.get("components", []):
            if component.get("group") is True:
                group_name = component.get("name", "").lower()
                if "aws" in group_name:
                    group_lookup[component["id"]] = "aws"
                elif "azure" in group_name:
                    group_lookup[component["id"]] = "azure"

        for component in data.get("components", []):
            if component.get("group") is False:
                group_id = component.get("group_id")
                category = group_lookup.get(group_id, "snowflake")
                status_text = component.get("status", "Unknown")

                formatted_component = {
                    "service": component.get("name", "Unknown Service"),
                    "status": "Running" if status_text in ["operational", "under_maintenance"]
                              else "Not Running",
                    "message": f"Status: {status_text}",
                    "category": category
                }
                categorized_components[category].append(formatted_component)

    except requests.exceptions.RequestException as e:
        error(f"Error fetching data from Snowflake API: {e}")
    except json.JSONDecodeError:
        error("Error decoding JSON from Snowflake API response.")

    return categorized_components

def check_website_status(url):
    debug(f"Checking website: {url}")
    try:
        response = requests.get(url, timeout=5, verify=False)
        debug(f"Website {url} responded with {response.status_code}")

        if 200 <= response.status_code < 300:
            return {"service": url, "status": "Running",
                    "message": f"Status Code: {response.status_code}", "category": "websites"}
        else:
            return {"service": url, "status": "Not Running",
                    "message": f"Status Code: {response.status_code}", "category": "websites"}
    except requests.exceptions.RequestException as e:
        error(f"Website error: {url} => {e}")
        return {"service": url, "status": "Not Running",
                "message": f"Error: {e}", "category": "websites"}

def check_microsoft_status(api_url):
    debug(f"Fetching Microsoft 365 status from {api_url}")
    results = []
    SERVICES_TO_INCLUDE = ["Microsoft 365 (Consumer)", "Microsoft Copilot", "Outlook.com"]

    try:
        response = requests.get(api_url, timeout=10, verify=False)
        debug(f"Microsoft API status code: {response.status_code}")
        response.raise_for_status()
        services = response.json()
        debug(f"Microsoft API returned {len(services)} services")

        for service in services:
            service_name = service.get("ServiceDisplayName", "Unknown Service")
            if service_name in SERVICES_TO_INCLUDE:
                raw_status = service.get("Status", "Unknown")
                normalized_status = raw_status.replace(" ", "").replace("_", "").lower()
                service_message = service.get("Message", "No message provided.")

                status_map = {
                    "operational": "Running",
                    "investigating": "Not Running",
                    "restoringservice": "Not Running",
                    "extendedrecovery": "Service Restored",   # degraded → orange
                    "servicerestored": "Service Restored"     # handles "Service restored"
                }

                resolved_status = status_map.get(normalized_status, "Not Running")

                debug(f"Microsoft {service_name}: {raw_status} -> {resolved_status}")
                results.append({
                    "service": service_name,
                    "status": resolved_status,
                    "message": service_message if service_message else "Status: " + raw_status,
                    "category": "microsoft"
                })

    except requests.exceptions.RequestException as e:
        error(f"Error fetching Microsoft API: {e}")
        results.append({"service": "Microsoft 365 Status API", "status": "Not Running",
                        "message": f"Error fetching API data: {e}", "category": "microsoft"})
    except json.JSONDecodeError:
        error("Error decoding JSON from Microsoft API response.")
        results.append({"service": "Microsoft 365 Status API", "status": "Not Running",
                        "message": "Error decoding JSON response", "category": "microsoft"})

    return results

def get_fortinet_status(api_data):
    debug(f"Fetching Fortinet data: {api_data['name']} from {api_data['url']}")
    results = []
    try:
        response = requests.get(api_data["url"], timeout=10, verify=False)
        debug(f"{api_data['name']} API status code: {response.status_code}")
        response.raise_for_status()
        data = response.json()
        components = data.get("components", [])
        debug(f"{api_data['name']} returned {len(components)} components")

        for component in components:
            if not component.get("group", False):
                status_text = component.get("status", "Unknown")
                results.append({
                    "service": f"{api_data['name']} - {component.get('name', 'Unknown Region')}",
                    "status": "Running" if status_text == "operational" else "Not Running",
                    "message": f"Status: {status_text}",
                    "category": "fortinet"
                })
    except requests.exceptions.RequestException as e:
        error(f"Fortinet error: {api_data['name']} => {e}")
        results.append({"service": f"{api_data['name']} Status API", "status": "Not Running",
                        "message": f"Error fetching API data: {e}", "category": "fortinet"})
    except json.JSONDecodeError:
        error(f"Error decoding JSON from Fortinet {api_data['name']}")
        results.append({"service": f"{api_data['name']} Status API", "status": "Not Running",
                        "message": "Error decoding JSON response", "category": "fortinet"})

    return results

def generate_html_report(results):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Comprehensive IT Status Report</title>
<script src="https://cdn.tailwindcss.com?version=3.4.3"></script>
<style>
    body {{ font-family: 'Inter', sans-serif; }}
    .section-header {{
        background-color: #2f4132;
        padding: 0.75rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
        font-weight: 600;
        color: #cad4cb;
    }}
</style>
</head>
<body class="bg-[#202522] flex items-center justify-center min-h-screen p-4">
    <div class="bg-[#2f4132] p-8 rounded-2xl shadow-xl w-full max-w-4xl border border-[#00bf1d]">
        <h1 class="text-3xl font-bold text-[#cad4cb] text-center">IT Status Report</h1>
        <p class="text-sm text-center text-[#a2a2a2] mt-2">
            Report generated on: <span class="font-semibold text-[#d0d8ce]">{timestamp}</span>
        </p>
        <div class="mt-6 space-y-4">
"""

    def generate_card(item):
        if item["status"] == "Running":
            status_color = "border-green-500"
            status_text_color = "text-[#cad4cb]"
            status_icon = "✅"
        elif item["status"] == "Service Restored":
            status_color = "border-orange-500"
            status_text_color = "text-orange-400"
            status_icon = "🟠"
        else:  # Not Running
            status_color = "border-red-500"
            status_text_color = "text-red-500"
            status_icon = "❌"

        message_html = item["message"].replace("\\n", "<br>")

        return f"""
        <div class="flex items-center p-4 rounded-xl shadow-md bg-[#2f4132] border-2 {status_color}">
            <div class="flex-shrink-0 text-3xl mr-4">{status_icon}</div>
            <div class="flex-grow">
                <div class="flex justify-between items-center mb-1">
                    <span class="font-bold text-lg leading-tight break-all text-[#d0d8ce]">{item["service"]}</span>
                    <span class="font-semibold text-sm rounded-full px-3 py-1 ml-4 whitespace-nowrap bg-[#202522] {status_text_color}">{item["status"]}</span>
                </div>
                <p class="text-sm opacity-80 break-words text-[#a2a2a2]">{message_html}</p>
            </div>
        </div>
        """

    for _, items in [
        ("Websites", results.get("websites", [])),
        ("Microsoft", results.get("microsoft", [])),
        ("Fortinet", results.get("fortinet", [])),
        ("Snowflake", results.get("snowflake", []))
    ]:
        if items:
            for item in items:
                html_content += generate_card(item)

    html_content += "</div></div></body></html>"
    return html_content

def main():
    debug("Starting new status check cycle")
    try:
        os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
        debug(f"Output directory checked/created: {OUTPUT_DIRECTORY}")
    except OSError as e:
        error(f"Error creating directory {OUTPUT_DIRECTORY}: {e}")
        return

    status_results = {"websites": [], "microsoft": [], "fortinet": [], "snowflake": []}

    # Websites
    for url in WEBSITES_TO_CHECK:
        status_results["websites"].append(check_website_status(url))
        time.sleep(1)

    # Microsoft
    status_results["microsoft"].extend(check_microsoft_status(MICROSOFT_STATUS_API))

    # Fortinet
    fortinet_down_services = []
    for api in FORTINET_APIS:
        fortinet_results = get_fortinet_status(api)
        for service in fortinet_results:
            if service["status"] == "Not Running":
                fortinet_down_services.append(service["service"])

    if fortinet_down_services:
        message = "The following Fortinet services are not operational:\\n" + "\\n".join(fortinet_down_services)
        status_results["fortinet"].append({"service": "Fortinet Services", "status": "Not Running",
                                           "message": message, "category": "fortinet"})
    else:
        status_results["fortinet"].append({"service": "Fortinet Services", "status": "Running",
                                           "message": "All Fortinet services are operational.", "category": "fortinet"})

    # Snowflake
    snowflake_data = get_status_from_snowflake_api(SNOWFLAKE_STATUS_API)
    snowflake_down_services = []
    for category in ["snowflake", "aws", "azure"]:
        for service in snowflake_data.get(category, []):
            if service["status"] == "Not Running":
                snowflake_down_services.append(service["service"])

    if snowflake_down_services:
        message = "The following Snowflake-related services are not operational:\\n" + "\\n".join(snowflake_down_services)
        status_results["snowflake"].append({"service": "Snowflake Services (includes AWS & Azure)", "status": "Not Running",
                                           "message": message, "category": "snowflake"})
    else:
        status_results["snowflake"].append({"service": "Snowflake Services (includes AWS & Azure)", "status": "Running",
                                           "message": "All Snowflake services and their cloud dependencies are operational.",
                                           "category": "snowflake"})

    # Save report
    full_path = os.path.join(OUTPUT_DIRECTORY, FILE_NAME)
    try:
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(generate_html_report(status_results))
        debug(f"HTML report written to {full_path}")
    except IOError as e:
        error(f"Error writing to file: {e}")

if __name__ == "__main__":
    while True:
        main()
        debug("Waiting 60 seconds before next check...")
        print("check in 60s")
        time.sleep(60)
