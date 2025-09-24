import nmap3
import pandas as pd
from bs4 import BeautifulSoup
import requests
from sys import argv
import urllib3
import threading
import httpx
from concurrent.futures import ThreadPoolExecutor

ip_1 = "10.10.207.53"
ip_2 = "10.10.207.54"
credentials = []
services = []
run_in_background = []
found_web_directories = []

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
        
        wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        try:
            with open(wordlist, 'r') as f:
                dirs = [line.strip() for line in f]
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                for dirs_name in dirs:
                    url = base_url + dirs_name
                    executor.submit(self.check_directory, url)
        except FileNotFoundError:
            print(f"wordlist '{wordlist}' not found")

    

if __name__ == "__main__":
    scanner = Scanner(ip=ip_2)
    scanner.scan_all_ports()
    dir_fuzzer = WebFuzzing(ip_2, 10)
    dir_fuzzer.httpx_fuzzing()


