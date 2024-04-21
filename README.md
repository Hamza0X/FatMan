# FatMan
The Domain Security Assessment Toolkit is a Bash script aiding security pros in comprehensive domain evaluations. It automates subdomain enumeration, directory traversal, technology detection, endpoint gathering, and vulnerability testing.

## Features
- Subdomain Enumeration
- DNS Zone Transfer Checking
- Subdomain_Takeover
- Waf Detection
- Port Scanning
## requirement
- For Subdomain Enumeration(assetfinder,crt.sh,gobuster,findomain,subfinder)
- Dns zone Transfer checking using shell code
- Subdomain Takeover using subzy
- waf detection using wafw00f in each subdomain
- run port scan first using naabu and after that we use nmap
- Vulnerability Testing(Sqlmap,arachni,security header check through anarchi)
## Usage
- Clone the repository to your local environment.
- Ensure all dependencies and required tools are installed.
- Execute the script with the target domain as the argument.
```bash
  git clone https://link-to-project
```
-Review the generated reports and output files in the specified output directory.


