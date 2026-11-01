import argparse
import logging
import requests
from bs4 import BeautifulSoup
import sys
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description='Detects potential Server-Side Request Forgery (SSRF) vulnerabilities.')
    parser.add_argument('url', help='The URL to scan.')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout for requests in seconds. Default is 5.')
    parser.add_argument('--payload', type=str, default=None, help='The payload URL to inject, named by the operator. No default payload is used.')
    parser.add_argument('--callback-url', type=str, default=None, help='Operator controlled callback URL to use as the payload. The target fetching this URL is the SSRF evidence.')
    parser.add_argument('--user-agent', type=str, default='vscan-ssrf-detector/1.0', help='Custom User-Agent header.')
    parser.add_argument('--method', type=str, default='GET', choices=['GET', 'POST'], help='HTTP method to use for URL parameter tests. Default is GET.')
    return parser.parse_args()

def is_valid_url(url):
    """Validates if the provided URL is properly formatted."""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def get_forms(url, timeout, user_agent):
    """Extracts all forms from the given URL. Returns None when the fetch fails."""
    try:
        headers = {'User-Agent': user_agent}
        response = requests.get(url, headers=headers, timeout=timeout)
        soup = BeautifulSoup(response.content, 'html.parser')
        return soup.find_all('form')
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return None

def _payload_content(payload, timeout, user_agent):
    """Fetch the operator named payload URL directly to learn its content.

    Content from that URL appearing in a target response is evidence the
    target fetched it. The payload text itself appearing is only reflection.
    """
    try:
        r = requests.get(payload, headers={'User-Agent': user_agent}, timeout=timeout, allow_redirects=False)
        text = (r.text or '').strip()
        return text if text else None
    except requests.exceptions.RequestException:
        return None

def test_ssrf(url, params, payload, timeout, user_agent, method='GET'):
    """Test one target. Returns ssrf, reflection, clean, error, or not_performed."""
    headers = {'User-Agent': user_agent}
    if not params:
        logging.info("SSRF test not performed: no parameters to inject into.")
        return "not_performed"
    # The payload page is fetched again inside every single test, so
    # a long scan hammers the operator's own callback, and if that
    # page changes mid scan the evidence standard changes with it.
    # Its whole stripped text is the marker: a short or common body
    # such as a single word can appear in a target page by chance.
    payload_content = _payload_content(payload, timeout, user_agent)
    try:
        if method == 'GET':
            parsed = urllib.parse.urlparse(url)
            existing = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            # Every parameter is replaced in the same one request, and
            # the form path below does the same with every field. A hit
            # tells me the target fetched the payload, never which
            # parameter made it fetch, so a report cannot name the
            # vulnerable field.
            merged = dict(existing)
            for key in params:
                merged[key] = payload
            clean_url = parsed._replace(query='').geturl()
            full_url = clean_url + "?" + urllib.parse.urlencode(merged)
            logging.info(f"Testing URL: {full_url}")
            response = requests.get(full_url, headers=headers, timeout=timeout, allow_redirects=False)
        elif method == 'POST':
            modified_data = {k: payload for k in params}
            logging.info(f"Testing POST request to URL: {url}")
            response = requests.post(url, data=modified_data, headers=headers, timeout=timeout, allow_redirects=False)
        else:
            logging.error(f"Invalid method: {method}")
            return "error"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error during {method} request: {e}")
        return "error"
    if payload_content and payload_content in response.text:
        logging.warning("Potential SSRF vulnerability detected: target response contains content fetched from the payload URL.")
        return "ssrf"
    if payload in response.text:
        logging.info("Reflection detected: payload text reflected in response. Reflection alone is not SSRF evidence.")
        return "reflection"
    logging.info("No SSRF vulnerability detected for this test.")
    return "clean"

def extract_params(url):
    """Extracts URL parameters."""
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    return {k: v[0] if isinstance(v, list) else v for k, v in query_params.items()}

def main():
    """Main function to execute the SSRF detection."""
    args = setup_argparse()
    if not is_valid_url(args.url):
        logging.error("Invalid URL provided. Please provide a valid URL.")
        sys.exit(1)
    payload = args.payload or args.callback_url
    if not payload:
        logging.error("SSRF fetch test not performed: no operator named payload or callback URL was supplied. Pass --payload or --callback-url naming your own callback.")
        sys.exit(1)
    logging.info(f"Starting SSRF scan on {args.url}")
    performed = 0
    errors = 0
    found = False
    url_params = extract_params(args.url)
    if url_params:
        result = test_ssrf(args.url, url_params, payload, args.timeout, args.user_agent, method=args.method)
        if result == "error":
            errors += 1
        elif result != "not_performed":
            performed += 1
            if result == "ssrf":
                found = True
    else:
        logging.info("URL parameter test not performed: target URL has no parameters.")
    forms = get_forms(args.url, args.timeout, args.user_agent)
    if forms is None:
        errors += 1
    else:
        for form in forms:
            action_raw = form.attrs.get("action")
            action = action_raw if action_raw else args.url
            form_url = urllib.parse.urljoin(args.url, action)
            form_method = form.attrs.get("method", "get").lower()
            form_data = {}
            for input_tag in form.find_all("input"):
                name = input_tag.attrs.get("name")
                if name:
                    form_data[name] = input_tag.attrs.get("value", "")
            if not form_data:
                continue
            method = "POST" if form_method == "post" else "GET"
            result = test_ssrf(form_url, form_data, payload, args.timeout, args.user_agent, method=method)
            if result == "error":
                errors += 1
            elif result != "not_performed":
                performed += 1
                if result == "ssrf":
                    found = True
    if performed == 0:
        logging.error("SSRF check not performed: no testable parameters or forms were found, or every test failed.")
        sys.exit(1)
    if errors:
        logging.error("SSRF scan inconclusive: one or more tests failed.")
        sys.exit(1)
    if not found:
        logging.info("No SSRF vulnerability detected.")
    logging.info("SSRF scan completed.")

if __name__ == "__main__":
    main()
