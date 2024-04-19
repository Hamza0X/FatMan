#!/bin/bash

# Print ASCII art
echo '
FFFFF   aaaa  tttttt  MMMM   MMMM  aaaa  nnnn  nnnn
F      a   a    tt    M   M M   M a   a nn nn nn nn
FFFF  aaaaaa    tt    M   M M   M aaaaa nn  nn  nn
F     a    a    tt    M   M M   M a    a nn       nn
F     a    a    tt    M   M M   M a    a nn       nn
'
# Check for domain argument
if [ -z "$1" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

domain="$1"
wordlist="/usr/share/wordlists/dirb/common.txt"
output_dir="$HOME/Desktop/Fatman/$domain"

# Function to handle command errors
handle_error() {
  echo "Error occurred in command: $1"
  exit 1
}

# Create the necessary directories with error handling
create_directory() {
  mkdir -p "$1" || handle_error "mkdir $1"
}

# Subdomain Enumeration
sublist3r -d "$domain" -o "$output_dir/subdomainEnumeration/sublist3r.txt" || handle_error "sublist3r"
amass enum --passive -d "$domain" -o "$output_dir/subdomainEnumeration/amass.txt" || handle_error "amass"
assetfinder "$domain" >> "$output_dir/subdomainEnumeration/assetfinder.txt" || handle_error "assetfinder"
dnsdumpster -d "$domain" -o "$output_dir/subdomainEnumeration/dnsdumpster.txt"|| handle_error "dnsdumpster"
#python censys-subdomain-finder.py  github.com -o "$output_dir/subdomainEnumeration/dnsdumpster.txt" || handle_error "censys"

# Enumeration using FavFreak
hash=$(favfreak -u "https://$domain") || handle_error "favfreak"
favfreak -f "$hash" --subdomains -o "$output_dir/subdomainEnumeration/favicon_hash.txt" || handle_error "favfreak"

# Subdomain enumeration through Certificate Transparency (CT) Logs
crt.sh -d "$domain" | httpx -title -tech-detect -status-code | grep 200 >> "$output_dir/subdomainEnumeration/ct.txt" || handle_error "crt.sh or httpx"

# Consolidate and deduplicate subdomains
cat "$output_dir/subdomainEnumeration"/*.txt | sort -u > "$output_dir/subdomainEnumeration/all_subdomains.txt" || handle_error "consolidating subdomains"
# using theharvester to gather the email associated to the domain
theharvester -d $domain -l 500 -b all -f "$output_dir/email_harvest.txt"
# Manual Scanning with grep: Search for email patterns in HTTP responses or text files using grep 
#grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" "$output_dir/web_responses.txt" > "$output_dir/email_disclosure.txt"

# Directory Enumeration and Technology Detection

while read -r subdomain; do
  # Use gobuster for directory enumeration
  gobuster dir -u "http://$subdomain" -w "$wordlist" -o "$output_dir/directoryEnumeration/gobuster_$subdomain.txt" || handle_error "gobuster"

  # Use Wappalyzer for technology detection
  wappalyzer "http://$subdomain" -o json > "$output_dir/technologies/wappalyzer_$subdomain.json" || handle_error "wappalyzer"
done < "$output_dir/subdomainEnumeration/all_subdomains.txt"
# Function to gather endpoints using gau
gather_endpoints() {
  echo "Gathering endpoints for $1"
  gau "$1" >> "$output_dir/endpoints_$1.txt"  # gau command to fetch endpoints
}
#go get -u github.com/lc/gau
# Loop through subdomains and gather endpoints
while read -r subdomain; do
  gather_endpoints "$subdomain"
done < "$output_dir/subdomainEnumeration/all_subdomains.txt"


# Function to test for SQL Injection 
test_sql_injection() {
  echo "Testing for SQL Injection on $1"
  sqlmap -u "$1" --risk=3 --level=5 --batch --random-agent --dbs -o "$output_dir/sql_injection_$1.txt"
}

# Function to test for XSS Attack
test_xss_attack() {
  echo "Testing for XSS Attack on $1"
  # Use Arachni for XSS vulnerability testing
  arachni "$1" --plugin=xss* --output-only-positives -o "$output_dir/xss_scan_$1.txt"
}

test_security_headers() {
  echo "Testing Security Headers on $1"
  # Use Arachni for Security Header check
  arachni "$1" --plugin=security_headers:* --output-only-positives -o "$output_dir/security_headers_$1.txt"
}


# Loop through endpoints for vulnerability testing in parallel
while read -r endpoint; do
  # Test for SQL Injection in the background ==> using para
  test_sql_injection "$endpoint" &
   # Test for Security Headers in the background
  test_security_headers "$endpoint" &
  # Test for XSS Attack in the background 
  test_xss_attack "$endpoint" &
done < "$output_dir/endpoints_$domain.txt"

# Wait for all background jobs to finish
wait

