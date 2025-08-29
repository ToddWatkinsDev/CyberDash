import hashlib
import requests
import sys
import urllib3

# Suppress the InsecureRequestWarning that is generated when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The URL of the file you want to hash
url = "https://cdn.tailwindcss.com?version=3.4.3"

def generate_and_save_hash(file_url, output_file):
    """
    Downloads a file from a given URL, computes its SHA-256 hash,
    and saves the hash to a specified file.
    
    Args:
        file_url (str): The URL of the file to download.
        output_file (str): The path to the file where the hash will be saved.
    """
    try:
        # Download the file content, bypassing SSL certificate verification
        print(f"Downloading file from: {file_url}")
        response = requests.get(file_url, timeout=10, verify=False)
        response.raise_for_status()
        
        # Get the content as bytes for hashing
        file_content_bytes = response.content
        
        # Compute the SHA-256 hash
        sha256_hash = hashlib.sha256(file_content_bytes).hexdigest()
        
        # Save the hash to the specified output file
        with open(output_file, 'w') as f:
            f.write(sha256_hash)
            
        print("\n" + "="*60)
        print("          SHA-256 Hash Generated and Saved")
        print("="*60)
        print(f"URL: {file_url}")
        print(f"SHA-256 Hash saved to: {output_file}")
        print("-----------------------------------------------------")
        
    except requests.exceptions.RequestException as e:
        print(f"\nError: An issue occurred while downloading the file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nError: An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    output_filename = "tailwind_hash.txt"
    generate_and_save_hash(url, output_filename)