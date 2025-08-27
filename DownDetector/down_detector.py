# Import necessary libraries
import requests
import datetime
import json
import os
import time

# This script fetches and processes the status of multiple IT services
# including websites, Microsoft 365, Fortinet, and Snowflake. It then
# generates a single, comprehensive, dynamic HTML report and saves it
# to a local file.

# --- Configuration ---
# Snowflake Status API endpoint
SNOWFLAKE_STATUS_API = "https://status.snowflake.com/api/v2/components.json"
# Microsoft 365 status API endpoint
MICROSOFT_STATUS_API = "https://status.cloud.microsoft/api/posts/m365Consumer"
# List of all Fortinet Status API endpoints to check
FORTINET_APIS = [
    {
        "name": "Fortinet Anycast Query",
        "url": "https://2k10kk4nf91b.statuspage.io/api/v2/summary.json"
    },
    {
        "name": "Fortinet Anycast Update",
        "url": "https://py884f5vjpy3.statuspage.io/api/v2/summary.json"
    },
    {
        "name": "FGD SDNS Anycast",
        "url": "https://dq1kp00kn5f1.statuspage.io/api/v2/summary.json"
    },
    {
        "name": "FGD DNS DoT",
        "url": "https://q06s3wqk32zh.statuspage.io/api/v2/summary.json"
    },
    {
        "name": "FGD SDNS Unicast",
        "url": "https://mpbpks96wbvp.statuspage.io/api/v2/summary.json"
    }
]
# List of other websites to check.
WEBSITES_TO_CHECK = []

# Directory and file name for the generated report
OUTPUT_DIRECTORY = "DownDetector"
FILE_NAME = "Down_Detector_Test.html"

# --- Core Functions for API Checks ---

def get_status_from_snowflake_api(api_url):
    """
    Fetches the full list of components from the Snowflake status API and
    categorizes them based on their parent group.

    Args:
        api_url (str): The URL of the Snowflake status API.

    Returns:
        dict: A dictionary containing lists of components categorized by service.
              Returns an empty dictionary if the API call fails.
    """
    categorized_components = {
        "snowflake": [],
        "aws": [],
        "azure": []
    }
    
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Create a lookup table for group IDs and their cloud service
        group_lookup = {}
        for component in data.get("components", []):
            if component.get("group") is True:
                group_name = component.get("name", "").lower()
                if "aws" in group_name:
                    group_lookup[component["id"]] = "aws"
                elif "azure" in group_name:
                    group_lookup[component["id"]] = "azure"
        
        # Iterate through all components to categorize them
        for component in data.get("components", []):
            if component.get("group") is False:
                group_id = component.get("group_id")
                category = group_lookup.get(group_id, "snowflake")
                
                # Format the component data for the report
                status_text = component.get("status", "Unknown")
                formatted_component = {
                    "service": component.get("name", "Unknown Service"),
                    "status": "Running" if status_text in ["operational", "under_maintenance"] else "Not Running",
                    "message": f"Status: {status_text}",
                    "category": category
                }
                categorized_components[category].append(formatted_component)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from Snowflake API: {e}")
    except json.JSONDecodeError:
        print("Error decoding JSON from Snowflake API response.")
    
    return categorized_components

def check_website_status(url):
    """
    Checks the status of a single website and returns a dictionary with the result.
    
    Args:
        url (str): The URL of the website to check.
        
    Returns:
        dict: A dictionary containing the URL, status ('Running' or 'Not Running'), and a message.
    """
    try:
        # Send a GET request with a timeout
        response = requests.get(url, timeout=5)
        # Check for a successful status code (200-299)
        if 200 <= response.status_code < 300:
            return {
                "service": url,
                "status": "Running",
                "message": f"Status Code: {response.status_code}",
                "category": "websites"
            }
        else:
            return {
                "service": url,
                "status": "Not Running",
                "message": f"Status Code: {response.status_code}",
                "category": "websites"
            }
    except requests.exceptions.RequestException as e:
        # Handle network-related errors (e.g., connection refused, DNS failure)
        return {
            "service": url,
            "status": "Not Running",
            "message": f"Error: {e}",
            "category": "websites"
        }

def check_microsoft_status(api_url):
    """
    Checks the status of Microsoft 365 services from the official API,
    filtering for specific services.
    
    Args:
        api_url (str): The URL of the Microsoft status API.
        
    Returns:
        list: A list of dictionaries, each containing status details for a service.
    """
    results = []
    
    # List of services to include in the report
    SERVICES_TO_INCLUDE = [
        "Microsoft 365 (Consumer)", 
        "Microsoft Copilot", 
        "Outlook.com"
    ]
    
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        # Parse the JSON response
        services = response.json()
        
        for service in services:
            service_name = service.get("ServiceDisplayName", "Unknown Service")
            
            # Check if the service is in our inclusion list
            if service_name in SERVICES_TO_INCLUDE:
                service_status = service.get("Status", "Unknown")
                service_message = service.get("Message", "No message provided.")
                
                # Map API status to your desired display status
                status_map = {
                    "Operational": "Running",
                    "Investigating": "Not Running",
                    "RestoringService": "Not Running",
                    "ExtendedRecovery": "Not Running"
                }
                
                results.append({
                    "service": service_name,
                    "status": status_map.get(service_status, "Not Running"),
                    "message": service_message if service_message else "Status: " + service_status,
                    "category": "microsoft"
                })
    
    except requests.exceptions.RequestException as e:
        results.append({
            "service": "Microsoft 365 Status API",
            "status": "Not Running",
            "message": f"Error fetching API data: {e}",
            "category": "microsoft"
        })
    except json.JSONDecodeError:
        results.append({
            "service": "Microsoft 365 Status API",
            "status": "Not Running",
            "message": "Error decoding JSON from API response.",
            "category": "microsoft"
        })
    
    return results

def get_fortinet_status(api_data):
    """
    Fetches Fortinet status data and returns a list of components, formatted for the report.

    Args:
        api_data (dict): Dictionary with "name" and "url" for a Fortinet API.

    Returns:
        list: A list of dictionaries, each representing a Fortinet component's status.
    """
    results = []
    try:
        response = requests.get(api_data["url"], timeout=10)
        response.raise_for_status()
        data = response.json()
        
        components = data.get("components", [])
        for component in components:
            # We are only interested in components that are not groups
            if not component.get("group", False):
                status_text = component.get("status", "Unknown")
                results.append({
                    "service": f"{api_data['name']} - {component.get('name', 'Unknown Region')}",
                    "status": "Running" if status_text == "operational" else "Not Running",
                    "message": f"Status: {status_text}",
                    "category": "fortinet"
                })

    except requests.exceptions.RequestException as e:
        results.append({
            "service": f"{api_data['name']} Status API",
            "status": "Not Running",
            "message": f"Error fetching API data: {e}",
            "category": "fortinet"
        })
    except json.JSONDecodeError:
        results.append({
            "service": f"{api_data['name']} Status API",
            "status": "Not Running",
            "message": "Error decoding JSON from API response.",
            "category": "fortinet"
        })
    
    return results

import datetime

def generate_html_report(results):
    """
    Generates a complete HTML page with all service categories listed sequentially.

    Args:
        results (dict): A dictionary of lists, where each list contains
                        status dictionaries for a specific service group.

    Returns:
        str: A string containing the complete HTML content.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive IT Status Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ font-family: 'Inter', sans-serif; }}
        .section-header {{
            background-color: #2f4132; /* Matches news article background */
            padding: 0.75rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            font-weight: 600;
            color: #cad4cb; /* Matches main heading color */
        }}
    </style>
</head>
<body class="bg-[#202522] flex items-center justify-center min-h-screen p-4">
    <div class="bg-[#2f4132] p-8 rounded-2xl shadow-xl w-full max-w-4xl border border-[#00bf1d]">
        <div class="flex flex-col items-center justify-center mb-6">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 text-[#00bf1d] mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944c-1.258 0-2.508.118-3.743.344M12 20.056c-1.258 0-2.508-.118-3.743-.344m7.486-16.712a11.955 11.955 0 01-3.743.344m7.486 0a11.955 11.955 0 013.743-.344M12 21a9 9 0 100-18 9 9 0 000 18z" />
            </svg>
            <h1 class="text-3xl font-bold text-[#cad4cb]">IT Status Report</h1>
            <p class="text-sm text-center text-[#a2a2a2] mt-2">
                Report generated on: <span class="font-semibold text-[#d0d8ce]">{timestamp}</span>
            </p>
        </div>
        
        <div class="mt-6 space-y-4">
"""

    # Function to generate a card for a given result item
    def generate_card(item):
        status_color = "border-green-500" if item["status"] == "Running" else "border-red-500"
        status_text_color = "text-[#cad4cb]" if item["status"] == "Running" else "text-red-500"
        status_icon = "✅" if item["status"] == "Running" else "❌"
        
        message_html = item["message"].replace("\n", "<br>")

        card = f"""
            <div class="flex items-center p-4 rounded-xl shadow-md transition-shadow hover:shadow-lg bg-[#2f4132] border-2 {status_color}">
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
        return card

    # Order the sections as they should appear
    sections = [
        ("Websites", results.get("websites", [])),
        ("Microsoft", results.get("microsoft", [])),
        ("Fortinet", results.get("fortinet", [])),
        ("Snowflake", results.get("snowflake", []))
    ]

    for title, items in sections:
        if items:
            html_content += f'<div class="space-y-4">'
            for item in items:
                html_content += generate_card(item)
            html_content += '</div>'

    html_content += """
        </div>
    </div>
</body>
</html>
"""
    return html_content


def main():
    """
    Main function to orchestrate the API checks, HTML generation, and file saving.
    """
    #print("Starting comprehensive status check...")

    # Create the output directory if it doesn't exist
    try:
        os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
    except OSError as e:
        #print(f"Error creating directory {OUTPUT_DIRECTORY}: {e}")
        return

    # Dictionary to hold all results, categorized
    status_results = {
        "websites": [],
        "microsoft": [],
        "fortinet": [],
        "snowflake": []
    }
    
    # Check Websites
    #print("Checking specified websites...")
    for url in WEBSITES_TO_CHECK:
        #print(f"Checking {url}...")
        status_results["websites"].append(check_website_status(url))
        time.sleep(1) # Add a delay to avoid rate limiting

    # Check Microsoft API
    #print("\nChecking Microsoft 365 services...")
    status_results["microsoft"].extend(check_microsoft_status(MICROSOFT_STATUS_API))

    # --- Consolidated Fortinet Check ---
    #print("\nConsolidating Fortinet services...")
    fortinet_down_services = []
    
    for api in FORTINET_APIS:
        fortinet_results = get_fortinet_status(api)
        for service in fortinet_results:
            if service["status"] == "Not Running":
                fortinet_down_services.append(service["service"])

    # Create a single, consolidated entry for the report
    if fortinet_down_services:
        message = "The following Fortinet services are not operational:\n" + "\n".join(fortinet_down_services)
        status_results["fortinet"].append({
            "service": "Fortinet Services",
            "status": "Not Running",
            "message": message,
            "category": "fortinet"
        })
    else:
        status_results["fortinet"].append({
            "service": "Fortinet Services",
            "status": "Running",
            "message": "All Fortinet services are operational.",
            "category": "fortinet"
        })
    
    # --- Consolidated Snowflake Check ---
    #print("\nConsolidating Snowflake services...")
    snowflake_data = get_status_from_snowflake_api(SNOWFLAKE_STATUS_API)
    snowflake_down_services = []

    # Check all Snowflake-related components (Snowflake, AWS, and Azure)
    for category in ["snowflake", "aws", "azure"]:
        for service in snowflake_data.get(category, []):
            if service["status"] == "Not Running":
                snowflake_down_services.append(service["service"])

    # Create a single, consolidated entry for the report
    if snowflake_down_services:
        message = "The following Snowflake-related services are not operational:\n" + "\n".join(snowflake_down_services)
        status_results["snowflake"].append({
            "service": "Snowflake Services (includes AWS & Azure)",
            "status": "Not Running",
            "message": message,
            "category": "snowflake"
        })
    else:
        status_results["snowflake"].append({
            "service": "Snowflake Services (includes AWS & Azure)",
            "status": "Running",
            "message": "All Snowflake services and their cloud dependencies are operational.",
            "category": "snowflake"
        })

    # Generate the HTML report
    html_report = generate_html_report(status_results)
    
    # Write the HTML content to the file
    full_path = os.path.join(OUTPUT_DIRECTORY, FILE_NAME)
    try:
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(html_report)
        #print(f"\nReport successfully generated! Open '{full_path}' in your browser to view the results.")
    except IOError as e:
        print(f"Error writing to file: {e}")

# Run the main function in a continuous loop
if __name__ == "__main__":
    while True:
        main()
        #print("\nWaiting 60 seconds before next check...")
        time.sleep(60)
