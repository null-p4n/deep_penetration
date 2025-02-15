# Advanced CTF Reconnaissance Cheatsheet

Comprehensive guide for penetration testing and CTF reconnaissance, incorporating industry best practices and modern tools.

Core Scanning
------------

### Port Scanning Fundamentals

#### Nmap Basic Usage
```bash
# Initial quick scan
sudo nmap -sC -sV -O -oA nmap/initial $IP

# Comprehensive TCP scan
sudo nmap -p- -sV --min-rate 5000 -oA nmap/full $IP

# UDP services scan
sudo nmap -sU --top-ports 1000 -oA nmap/udp $IP
```

#### Advanced Nmap Techniques
```bash
# Aggressive service detection
sudo nmap -A -T4 -p- -oA nmap/aggressive $IP

# NSE script scanning
sudo nmap --script vuln,exploit -oA nmap/vuln $IP

# Stealth scanning
sudo nmap -sS -sV -f --data-length 200 -D RND:10 $IP
```

### Fast Scanning Tools

#### Masscan
```bash
# Quick port discovery
masscan -p1-65535 $IP --rate=10000

# Targeted service scan
masscan -p80,443,8000-8100 $IP --rate=1000
```

#### Rustscan
```bash
# Fast initial scan
rustscan -a $IP -- -sC -sV

# Targeted scan with custom ports
rustscan -a $IP -p 80,443,3306 -- -sV
```

Web Application Testing
----------------------

### Directory Enumeration

#### Feroxbuster (Modern Alternative)
```bash
# Basic scan
feroxbuster -u $URL -w /usr/share/wordlists/dirb/common.txt

# Extended scan with multiple extensions
feroxbuster -u $URL -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,html,js
```

#### FFuF (Fast Web Fuzzer)
```bash
# Directory fuzzing
ffuf -u $URL/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Parameter fuzzing
ffuf -u "$URL/api?FUZZ=value" -w /usr/share/wordlists/params.txt

# Virtual host discovery
ffuf -u $URL -H "Host: FUZZ.$DOMAIN" -w subdomains.txt
```

### Web Vulnerability Scanning

#### Nuclei
```bash
# Basic template scan
nuclei -u $URL -t nuclei-templates/

# Targeted vulnerability scan
nuclei -u $URL -t nuclei-templates/cves/ -severity critical,high

# Multiple target scan
nuclei -l urls.txt -t nuclei-templates/vulnerabilities/
```

#### OWASP ZAP CLI
```bash
# Quick scan
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' $URL

# Full scan
zap-cli full-scan --self-contained $URL
```

Network Services
---------------

### SMB Enumeration

#### SMBMap
```bash
# Basic share enumeration
smbmap -H $IP

# Recursive file listing
smbmap -H $IP -R

# User authentication
smbmap -H $IP -u "username" -p "password"
```

#### CrackMapExec
```bash
# Share enumeration
crackmapexec smb $IP

# Password spraying
crackmapexec smb $IP -u users.txt -p passwords.txt

# Domain enumeration
crackmapexec smb $IP --users --groups
```

### LDAP Enumeration

#### ldapsearch
```bash
# Anonymous bind
ldapsearch -x -H ldap://$IP -b "dc=example,dc=com"

# Authenticated search
ldapsearch -x -H ldap://$IP -D "cn=admin,dc=example,dc=com" -w password -b "dc=example,dc=com"
```

Vulnerability Assessment
-----------------------

### Web Application Vulnerabilities

#### SQLMap
```bash
# Basic injection test
sqlmap -u "$URL/?id=1"

# Advanced injection with tamper scripts
sqlmap -u "$URL" --forms --tamper=space2comment,between

# Database enumeration
sqlmap -u "$URL" --dbs --batch --random-agent
```

#### XSStrike
```bash
# Basic XSS scan
xsstrike --url $URL

# DOM XSS scan
xsstrike --url $URL --seeds seeds.txt --dom

# Blind XSS testing
xsstrike --url $URL --blind
```

OSINT Techniques
---------------

### Subdomain Enumeration

#### Amass
```bash
# Passive enumeration
amass enum -passive -d $DOMAIN

# Active enumeration
amass enum -active -d $DOMAIN -ip

# Intel gathering
amass intel -org "Target Company"
```

#### Subfinder
```bash
# Basic enumeration
subfinder -d $DOMAIN

# Silent output with resolved IPs
subfinder -d $DOMAIN -silent -resolve
```

Infrastructure Analysis
----------------------

### SSL/TLS Analysis

#### SSLyze
```bash
# Basic scan
sslyze $DOMAIN

# Comprehensive scan
sslyze --regular $DOMAIN --json_out=results.json
```

### Container Analysis

#### Container Scanning
```bash
# Trivy container scan
trivy image imagename:tag

# Grype vulnerability scan
grype imagename:tag
```

Data Analysis
------------

### File Analysis

#### Advanced File Analysis
```bash
# Deep file analysis
binwalk -Me suspicious_file

# Memory dump analysis
volatility -f memory.dmp imageinfo
```

#### Steganography
```bash
# StegSeek (faster than steghide)
stegseek image.jpg wordlist.txt

# Deep image analysis
zsteg -a image.png

# Audio steganography
sonic-visualiser audio.wav
```

Documentation & Reporting
------------------------

### Note Taking Tools

#### CherryTree
```bash
# Create new document
cherrytree pentest_notes.ctb

# Import from markdown
cherrytree --import-markdown notes.md
```

#### Obsidian
- Create vault for each assessment
- Use templates for consistent documentation
- Link findings and evidence
- Export to various formats

[Previous sections remain the same up to OSINT Techniques]

OSINT Techniques
---------------

### Email Discovery
```bash
# TheHarvester
theHarvester -d $DOMAIN -b all

# h8mail for breach data
h8mail -t target@email.com
```

### Social Media Reconnaissance
```bash
# Sherlock for username search
sherlock username

# Twint for Twitter OSINT
twint -u username --email --phone
```

### Document Metadata
```bash
# Exiftool for metadata analysis
exiftool document.pdf

# Metagoofil for document gathering
metagoofil -d $DOMAIN -t pdf,doc,xls -n 10
```

### Git Repository Analysis
```bash
# GitLeaks for secrets
gitleaks detect --source=./repo

# TruffleHog for pattern matching
trufflehog --regex --entropy=False github.com/org/repo
```

Advanced Exploitation
--------------------

### Buffer Overflow Analysis
```bash
# Pattern creation
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000

# Pattern offset
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39694438
```

### Reverse Engineering
```bash
# Ghidra headless analysis
ghidra_analyze -import binary

# Radare2 analysis
r2 -A binary
```

### Privilege Escalation
```bash
# Linux enumeration
./linpeas.sh
./linux-smart-enumeration/lse.sh

# Windows enumeration
.\winPEAS.exe
PowerUp.ps1
```

### Custom Exploit Development
```bash
# ROPgadget for ROP chains
ROPgadget --binary binary --rop --badbytes "0a0d"

# One_gadget for libc exploitation
one_gadget libc.so.6
```

Infrastructure Analysis
----------------------

### Network Infrastructure
```bash
# Masscan for network mapping
masscan -p1-65535 $NETWORK/24 --rate=10000

# Nmap NSE infrastructure scripts
nmap --script broadcast-dhcp-discover
nmap --script snmp-brute $IP
```

### Active Directory
```bash
# BloodHound collection
bloodhound-python -d domain.local -u user -p pass -c All

# Impacket suite
GetADUsers.py -all domain.local/user:password
```

### Containerization
```bash
# Docker analysis
docker-bench-security

# Kubernetes scanning
kube-hunter --remote $CLUSTER_IP
kubeaudit all -f cluster.yaml
```

Data Analysis
------------

### Memory Forensics
```bash
# Volatility basics
vol.py -f memory.dmp windows.pslist
vol.py -f memory.dmp windows.netscan

# Memory acquisition
lime -format raw -path /tmp/mem.lime
```

### Network Traffic
```bash
# Wireshark CLI
tshark -r capture.pcap -Y "http.request.method==POST"

# Network Miner
networkminer -r capture.pcap
```

### Database Analysis
```bash
# MongoDB enumeration
mongodump --host $IP

# Redis analysis
redis-cli -h $IP
```

Mobile Application Testing
-------------------------

### Android Analysis
```bash
# Static analysis
apktool d app.apk
dex2jar app.apk
jd-gui app.jar

# Dynamic analysis
frida-ps -U
frida-trace -U -i "open" com.app.package
```

### iOS Analysis
```bash
# Static analysis
otool -l app.ipa
class-dump app.ipa

# Dynamic analysis
cycript -p ProcessName
objection explore
```

Cloud Services
-------------

### AWS Enumeration
```bash
# S3 bucket analysis
aws s3 ls s3://$BUCKET --no-sign-request
aws s3api get-bucket-acl --bucket $BUCKET

# Lambda enumeration
aws lambda list-functions --region us-east-1
```

### Azure Reconnaissance
```bash
# Azure AD enumeration
AADInternals.ps1
Get-AADIntTenantDetails

# Storage analysis
az storage account list
az storage container list
```

### GCP Analysis
```bash
# GCP bucket enumeration
gsutil ls gs://$BUCKET

# Project reconnaissance
gcloud projects list
gcloud services list
```

Authentication Testing
---------------------

### Password Attacks
```bash
# Hashcat
hashcat -m 1000 hashes.txt rockyou.txt
hashcat -m 1800 ntlm.txt --rule-file=custom.rule

# John the Ripper
john --wordlist=wordlist.txt hashes.txt
john --incremental --format=raw-md5 hashes.txt
```

### Token Analysis
```bash
# JWT testing
jwt_tool.py $TOKEN -t
jwt_tool.py $TOKEN -C -d wordlist.txt

# OAuth testing
oauthscan.py -u $URL
```

### Multi-Factor Authentication
```bash
# MFA bypass testing
mfascan.py -u $URL
2fas -t $TOKEN -b wordlist.txt
```

Documentation
------------

### Report Generation
```bash
# Custom report templates
pandoc report.md -o report.pdf --template=pentest.tex

# Evidence management
processevidence.py -i evidence/ -o report/
```

### Collaboration Tools
```bash
# Collaborative documentation
mkdocs serve
gitbook serve
```

### Evidence Collection
```bash
# Screenshot automation
eyewitness --web --threads 10 -f urls.txt

# Video recording
asciinema rec session.cast
```

Best Practices
-------------
1. Always maintain chain of custody for evidence
2. Document all command execution and outputs
3. Validate findings through multiple tools
4. Follow ethical guidelines and scope
5. Regular backup of findings
6. Use time stamping for all activities
7. Maintain separate environments for different tests
8. Version control all custom scripts and tools

Remember to:
- Keep tools updated
- Verify tool outputs
- Document methodology
- Follow proper escalation procedures
- Maintain secure communications
- Regular status updates
- Clean up after testing

