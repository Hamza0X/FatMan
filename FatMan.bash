#!/bin/bash

# Function to print ASCII art
print_ascii_art() {
  echo '
  FFFFF  aaaa tttttt MMMM  MMMM aaaa nnnn nnnn
  F   a  a  tt  M  M M  M a  a nn nn nn nn
  FFFF aaaaaa  tt  M  M M  M aaaaa nn nn nn
  F   a  a  tt  M  M M  M a  a nn    nn
  F   a  a  tt  M  M M  M a  a nn    nn
  '
}

# Function to log messages to a log file
log() {
  echo "[`date`] $1" >> "$log_file"
}

# Function to create structured directories
create_structured_directories() {
  log "Creating structured directories..."
  mkdir -p "$output_dir/subdomainEnumeration"
  mkdir -p "$output_dir/waf_detection"
}

# Function to perform subdomain enumeration
run_subdomain_enumeration() {
  log "Running subdomain enumeration..."

  # Amass
 # log "Running Amass for subdomain discovery..."
 # timeout 3m amass enum --passive -d "$domain" -o "$output_dir/subdomainEnumeration/amass.txt" --max-dns-queries 200 &

  # Assetfinder
  log "Running Assetfinder for subdomain discovery..."
  assetfinder "$domain" >> "$output_dir/subdomainEnumeration/assetfinder.txt" &

  # crt.sh
  log "Running crt.sh for subdomain discovery..."
  (curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$output_dir/subdomainEnumeration/crtsh.txt") &

  # Gobuster
  log "Running Gobuster for subdomain discovery..."
  gobuster dns -d "$domain" -w "/usr/share/wordlists/amass/subdomains-top1mil-20000.txt" -t 50 | grep "Found: " | cut -d' ' -f2 | sort -u > "$output_dir/subdomainEnumeration/gobuster.txt" &

  # Findomain
  log "Running Findomain for subdomain discovery..."
  findomain -t "$domain" | tee -a "$output_dir/subdomainEnumeration/findomain.txt" &

  # Subfinder
  log "Running Subfinder for subdomain discovery..."
  (subfinder -d "$domain" -o "$output_dir/subdomainEnumeration/subfinder.txt") &

  # Wait for all background processes to finish
  wait

  # Combine all subdomain files into a single file
  log "Consolidating subdomains into one file..."
  cat "$output_dir/subdomainEnumeration/amass.txt" \
    "$output_dir/subdomainEnumeration/assetfinder.txt" \
    "$output_dir/subdomainEnumeration/crtsh.txt" \
    "$output_dir/subdomainEnumeration/gobuster.txt" \
    "$output_dir/subdomainEnumeration/findomain.txt" \
    "$output_dir/subdomainEnumeration/subfinder.txt" | sort -u > "$output_dir/subdomainEnumeration/all_subdomains.txt"

  log "Subdomain enumeration completed."
}

# Function to check DNS zone transfer
check_dns_zone_transfer() {
  log "Checking DNS zone transfer..."
  if [ -z "$1" ]; then
    log "[*] Simple Zone transfer script"
    log "[*] Usage : $0 <domain name>"
    log "[*] Example : $0 aeoi.org.ir "
    exit 0
  fi

  for server in $(host -t ns "$1" | cut -d" " -f4); do
    host -l "$1" "$server" | grep "has address"
  done

  log "DNS zone transfer completed."
}

# Function to check for subdomain takeover with Subzy
check_subdomain_takeover_subzy() {
  log "Checking for subdomain takeover with Subzy..."
  subzy run --targets "$output_dir/subdomainEnumeration/all_subdomains.txt" > "$output_dir/subdomain_takeover_results_subzy.txt"
  log "Subdomain takeover results (Subzy) saved to $output_dir/subdomain_takeover_results_subzy.txt"
}

# Function to check for WAF presence using wafw00f
check_waf() {
  log "Checking for WAF presence..."
  while IFS= read -r subdomain; do
    if [ -n "$subdomain" ]; then
      status_code=$(curl -sL -w "%{http_code}" "http://$subdomain" -o /dev/null)
      if [ "$status_code" -eq 200 ]; then
        {
          wafw00f "http://$subdomain" > "$output_dir/waf_detection/$subdomain.txt" 2>&1
        } || {
          log "Error checking WAF for $subdomain: $?" >&2
        }
      fi
    fi
  done < "$output_dir/subdomainEnumeration/all_subdomains.txt"

  log "WAF detection results saved to the waf_detection directory (with potential errors logged)."
}

# Function to perform port scanning with naabu
run_port_scanning() {
  log "Scanning open ports on all subdomains with naabu..."
  naabu -l "$output_dir/subdomainEnumeration/all_subdomains.txt" -o "$output_dir/port_scan_results.txt"
  log "Port scanning completed."
  log "Results are stored in $output_dir/port_scan_results.txt"
}

# Function to perform Nmap scanning
run_nmap_scanning() {
  log "Running Nmap scanning..."
  while IFS= read -r line; do
    subdomain=$(echo "$line" | cut -d':' -f1)
    port=$(echo "$line" | cut -d':' -f2)

    log "Scanning $subdomain on port $port with Nmap..."
    nmap -p "$port" "$subdomain" -oN "$output_dir/nmap_results_$subdomain.txt"
  done < "$output_dir/port_scan_results.txt"
  log "Nmap scanning completed."
}

# Main part of the script

# Check for domain argument
if [ -z "$1" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

domain="$1"
output_dir="$HOME/Desktop/Fatman/$domain"
log_file="$output_dir/fatman_log.txt"

# Create structured directories if they don't exist
create_structured_directories

# Print ASCII art
print_ascii_art

# Start logging
log "Fatman Script Execution Started for Domain: $domain"

# Run subdomain enumeration
run_subdomain_enumeration

# Check DNS zone transfer
check_dns_zone_transfer "$domain"

# Check for subdomain takeover with Subzy
check_subdomain_takeover_subzy

# Check for WAF presence
check_waf

# Run port scanning with naabu
run_port_scanning

# Run Nmap scanning
run_nmap_scanning

# End logging
log "Fatman Script Execution Completed"
