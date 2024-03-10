from censys.search import CensysHosts
from difflib import SequenceMatcher
from bs4 import BeautifulSoup as bs
from colorama import Fore,init
import re
import socket
import whois
import requests
import sys
init()

# disable insecure warning requests verify=False
requests.packages.urllib3.disable_warnings() 

class Flare:
    def __init__(self,api,secret,cookie,domain):
        self.domain = domain.replace("http://","").replace("https://","").replace("/","")
        self.shodan_cookie = cookie
        # handle exception 
        try:
            self.censysApi = CensysHosts(api_id=api,api_secret=secret)
        except Exception as e:
            print(f"❌ {Fore.RED}Censys ERROR: {e}{Fore.RESET}")
            pass

    def similarity(self,text=list()):
        try:
            # Calculate the similarity ratio using SequenceMatcher
            similarity_ratio = SequenceMatcher(None, text[0], text[1]).ratio()
            
            # Convert the ratio to percentage
            similarity_percentage = similarity_ratio * 100
        except KeyboardInterrupt:
            sys.exit()
        
        return f"{similarity_percentage:.2f}"
    
    def check_dns(self,domain):
        try:
            answers = whois.whois(domain)
            answer = answers['name_servers']
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            answer = "None",e
        return answer
    
    def bsoup(self,content):
        soup = bs(content,'html.parser')
        try:
            title = soup.find('title').text.strip()
        except AttributeError:
            title = ""
        return title
    
    def requester(self,domain,pass_=False):
        try:
            req = requests.get(domain,headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'},verify=False,timeout=5)
            return req
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            print(f"❌ {Fore.RED}{e}{Fore.RESET}")
            if pass_:
                return ""
            else:
                sys.exit()

    def grep_ip_addresses(self,html_content):
        # Parse HTML content using BeautifulSoup
        soup = bs(html_content, 'html.parser')

        # Find all HTML tags
        tags = soup.find_all()

        # Regular expression pattern to match IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        # List to store IP addresses
        ip_addresses = []

        # unique ip
        unique_ip = []

        # Iterate through each HTML tag
        for tag in tags:
            # Extract text from the tag
            text = tag.get_text()

            # Use regular expression to find IP addresses in the tag's text
            ips = re.findall(ip_pattern, text)

            # Add found IP addresses to the list
            ip_addresses.extend(ips)

        # remove duplicate ip
        for i in ip_addresses:
            if i not in unique_ip:
                unique_ip.append(i)

        return unique_ip
    
    # censys
    def scan(self):
        try:
            query = self.censysApi.search(self.domain, pages=-1)
            return query()
        except Exception as e:
            print(f"❌ {Fore.RED}Censys ERROR: {e}{Fore.RESET}")
            return []
    # ---
        
    # shodan
    def scan_shodan(self):
        try:
            req = requests.get(f"https://www.shodan.io/search?query={self.domain}",headers={'Cookie':self.shodan_cookie,'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'},verify=False,timeout=5)
            if "Daily search usage limit reached" in req.text:
                print(f"❌ {Fore.RED}Shodan ERROR: Daily search usage limit reached, try to add your shodan account cookie in config.json{Fore.RESET}")
            if "No results found" in req.text:
                print(f"❌ {Fore.RED}Shodan ERROR: No results found{Fore.RESET}")
            return self.grep_ip_addresses(req.text)
        except Exception as e:
            print(f"❌ {Fore.RED}Shodan ERROR: {e}{Fore.RESET}")
            return []
    # ---
    
    def ipaddr(self):
        return socket.gethostbyname(self.domain)
    
    def main(self):
        print(f"🔎 {Fore.BLUE}Scanning {self.domain} {Fore.RESET}")

        ###################### check domain NS
        ns = self.check_dns(self.domain)
        if "cloudflare" in ns[0].lower():
            print(f"⚠️ {self.domain} ({self.ipaddr()}) {Fore.YELLOW}IS BEHIND CLOUDFLARE{Fore.RESET} {ns}")
        else:
            print(f"✔️ {self.domain} ({self.ipaddr()}) {Fore.GREEN}IS NOT BEHIND CLOUDFLARE{Fore.RESET} {ns}")
            sys.exit()

        ####################### main target info
        main_target_content = self.requester("https://"+self.domain).content
        main_target_content_length = len(main_target_content) / 1024
        main_target_title = self.bsoup(main_target_content)

        print(f"🌐 {self.domain} | size: {main_target_content_length:.2f} kb | title: {main_target_title}")

        ######################## scan domain
        print(f"🔎 {Fore.BLUE}Finding possible Ip{Fore.RESET}")
        scanner = self.scan()
        scanner_shodan = self.scan_shodan()
        list_ip = list()
        total_results = len(scanner)
        total_results_shodan = len(scanner_shodan)

        if total_results_shodan == 0 and total_results == 0:
            print(f"⚠️ Failed to find real ip")
            sys.exit()

        for ip in scanner:
            try:
                if "." in ip['ip']:
                    list_ip.append(ip['ip'])
            except TypeError:
                pass

        for ip in scanner_shodan:
            try:
                if "." in ip:
                    list_ip.append(ip)
            except TypeError:
                pass

        print(f"🔎 {len(list_ip)} Ip associated with {self.domain} ")
        

        ########################## check similarity
        print(f"🔎 {Fore.BLUE}Checking candidates ip{Fore.RESET}")

        for possible in list_ip:
            print(f"✔️ Candidate real ip address {Fore.GREEN}{possible}{Fore.RESET} {self.check_dns(possible)}")

        # get candidate content and title for checking similarity
        print(f"🔎 {Fore.BLUE}Checking similarity{Fore.RESET}")
        for test_ip in list_ip:
            try:
                candidate_content = self.requester("http://"+test_ip,True).content
            except AttributeError:
                candidate_content = ""
            candidate_content_length = len(candidate_content) / 1024
            candidate_title = self.bsoup(candidate_content)

        
            similar_content = float(self.similarity([main_target_content,candidate_content]))
            similar_title = float(self.similarity([main_target_title,candidate_title]))
            if similar_content > 60.0 and similar_title > 70.0:
                print(f"🌐 {test_ip} size: {candidate_content_length:.2f} kb | content similarity: {similar_content}% | title similarity: {similar_title}% ({Fore.GREEN}POSSIBLE REAL IP{Fore.RESET})")
            else:
                print(f"🌐 {test_ip} size: {candidate_content_length:.2f} kb | content similarity: {similar_content}% | title similarity: {similar_title}% ")


    