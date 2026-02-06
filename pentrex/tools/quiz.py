"""Quiz system for CEH domains."""

import random
from pentrex.tools.registry import register

# Question bank organized by domain
QUESTIONS = {
    "reconnaissance": [
        {
            "q": "Which tool is primarily used for DNS enumeration?",
            "options": ["Nmap", "DNSrecon", "Metasploit", "Burp Suite"],
            "answer": 1,
            "explanation": "DNSrecon is specifically designed for DNS enumeration, discovering subdomains, zone transfers, and DNS records."
        },
        {
            "q": "What is the first phase of ethical hacking?",
            "options": ["Scanning", "Reconnaissance", "Gaining Access", "Maintaining Access"],
            "answer": 1,
            "explanation": "Reconnaissance (footprinting) is always the first phase - gathering information about the target before any active engagement."
        },
        {
            "q": "Which Google dork finds login pages?",
            "options": ["site:target.com", "inurl:admin", "filetype:pdf", "cache:target.com"],
            "answer": 1,
            "explanation": "inurl:admin searches for URLs containing 'admin', commonly used to find login pages and admin panels."
        },
        {
            "q": "What does WHOIS lookup reveal?",
            "options": ["Open ports", "Domain registration info", "SSL certificates", "Server OS"],
            "answer": 1,
            "explanation": "WHOIS reveals domain registration details: owner, registrar, nameservers, and contact information."
        },
        {
            "q": "Which tool is used for email harvesting?",
            "options": ["Nmap", "theHarvester", "Nikto", "SQLmap"],
            "answer": 1,
            "explanation": "theHarvester collects emails, names, subdomains from public sources like search engines and social media."
        },
        {
            "q": "What is passive reconnaissance?",
            "options": ["Port scanning", "Gathering info without direct contact", "Exploiting vulnerabilities", "Social engineering"],
            "answer": 1,
            "explanation": "Passive recon gathers information without directly interacting with the target - using public sources, OSINT, etc."
        },
        {
            "q": "Shodan is used to find?",
            "options": ["SQL injections", "Internet-connected devices", "Malware samples", "Password hashes"],
            "answer": 1,
            "explanation": "Shodan is a search engine for internet-connected devices, revealing exposed services, IoT devices, and vulnerable systems."
        },
    ],
    "scanning": [
        {
            "q": "What does Nmap's -sS flag do?",
            "options": ["UDP scan", "TCP SYN scan", "Service version detection", "OS detection"],
            "answer": 1,
            "explanation": "The -sS flag performs a TCP SYN scan (half-open scan), which is stealthier because it doesn't complete the TCP handshake."
        },
        {
            "q": "Which port is commonly used by HTTPS?",
            "options": ["80", "443", "8080", "22"],
            "answer": 1,
            "explanation": "Port 443 is the default port for HTTPS (HTTP over TLS/SSL)."
        },
        {
            "q": "What type of scan sends packets with no flags set?",
            "options": ["SYN scan", "NULL scan", "FIN scan", "XMAS scan"],
            "answer": 1,
            "explanation": "A NULL scan sends packets with no TCP flags set. It can bypass some firewalls and identify open ports on certain systems."
        },
        {
            "q": "What does the -O flag in Nmap do?",
            "options": ["Output to file", "OS detection", "Open ports only", "Optimize speed"],
            "answer": 1,
            "explanation": "The -O flag enables OS detection, analyzing responses to guess the target's operating system."
        },
        {
            "q": "Which port does FTP use by default?",
            "options": ["20/21", "22", "23", "25"],
            "answer": 0,
            "explanation": "FTP uses port 21 for control and port 20 for data transfer."
        },
        {
            "q": "What is a banner grab?",
            "options": ["Stealing cookies", "Capturing service version info", "DDoS attack", "ARP spoofing"],
            "answer": 1,
            "explanation": "Banner grabbing captures service banners to identify software versions and potential vulnerabilities."
        },
        {
            "q": "Which Nmap flag enables aggressive scanning?",
            "options": ["-sA", "-A", "-aS", "-aggressive"],
            "answer": 1,
            "explanation": "The -A flag enables aggressive mode: OS detection, version detection, script scanning, and traceroute."
        },
    ],
    "system_hacking": [
        {
            "q": "What is the purpose of a rootkit?",
            "options": ["Encrypt files", "Hide malicious activity", "Spread via email", "Capture keystrokes"],
            "answer": 1,
            "explanation": "Rootkits are designed to hide the presence of malware or unauthorized access, maintaining stealth on compromised systems."
        },
        {
            "q": "Which technique captures passwords as they're typed?",
            "options": ["Phishing", "Keylogging", "Brute force", "Rainbow tables"],
            "answer": 1,
            "explanation": "Keyloggers record keystrokes, capturing passwords and other sensitive data as users type them."
        },
        {
            "q": "What does the Windows SAM database store?",
            "options": ["Network configs", "Password hashes", "System logs", "User preferences"],
            "answer": 1,
            "explanation": "The Security Account Manager (SAM) stores local user account password hashes in Windows systems."
        },
        {
            "q": "What is privilege escalation?",
            "options": ["Logging in remotely", "Gaining higher access rights", "Encrypting files", "Deleting logs"],
            "answer": 1,
            "explanation": "Privilege escalation is gaining higher access rights than initially granted, often from user to admin/root."
        },
        {
            "q": "Which file contains password hashes on Linux?",
            "options": ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/sudoers"],
            "answer": 1,
            "explanation": "/etc/shadow stores the actual password hashes, readable only by root."
        },
        {
            "q": "What is a pass-the-hash attack?",
            "options": ["Cracking passwords", "Using hash without cracking", "Stealing cookies", "DNS poisoning"],
            "answer": 1,
            "explanation": "Pass-the-hash uses captured NTLM hashes directly for authentication without needing the plaintext password."
        },
        {
            "q": "SUID bit allows a program to run as?",
            "options": ["Current user", "File owner", "Nobody", "Guest"],
            "answer": 1,
            "explanation": "SUID (Set User ID) makes a program run with the file owner's permissions, often exploited for privilege escalation."
        },
    ],
    "web_attacks": [
        {
            "q": "Which attack injects malicious scripts into web pages?",
            "options": ["SQL Injection", "XSS", "CSRF", "Directory Traversal"],
            "answer": 1,
            "explanation": "Cross-Site Scripting (XSS) injects malicious scripts that execute in victims' browsers, stealing cookies or performing actions on their behalf."
        },
        {
            "q": "What does SQL Injection primarily target?",
            "options": ["Web server", "Database", "Firewall", "DNS server"],
            "answer": 1,
            "explanation": "SQL Injection targets the database by manipulating queries through unsanitized user input."
        },
        {
            "q": "Which HTTP method is often exploited in CSRF attacks?",
            "options": ["GET", "POST", "OPTIONS", "HEAD"],
            "answer": 1,
            "explanation": "POST requests that change state are common CSRF targets since they can be triggered by hidden forms on malicious sites."
        },
        {
            "q": "What prevents XSS attacks?",
            "options": ["Firewall", "Output encoding", "SSL certificate", "Strong passwords"],
            "answer": 1,
            "explanation": "Output encoding converts special characters to HTML entities, preventing injected scripts from executing."
        },
        {
            "q": "What is directory traversal?",
            "options": ["Listing folders", "Accessing files outside web root", "Creating directories", "Deleting files"],
            "answer": 1,
            "explanation": "Directory traversal uses ../ sequences to access files outside the intended web directory."
        },
        {
            "q": "OWASP Top 10 is?",
            "options": ["Antivirus list", "Web vulnerability ranking", "Password policy", "Firewall rules"],
            "answer": 1,
            "explanation": "OWASP Top 10 lists the most critical web application security risks, updated periodically."
        },
        {
            "q": "What does a WAF protect against?",
            "options": ["DDoS only", "Web application attacks", "Physical theft", "Social engineering"],
            "answer": 1,
            "explanation": "Web Application Firewall filters malicious HTTP traffic, blocking SQLi, XSS, and other web attacks."
        },
    ],
    "network_attacks": [
        {
            "q": "What protocol does ARP Spoofing target?",
            "options": ["TCP", "UDP", "ARP", "ICMP"],
            "answer": 2,
            "explanation": "ARP Spoofing exploits the Address Resolution Protocol, which has no authentication, allowing attackers to associate their MAC with a victim's IP."
        },
        {
            "q": "Which attack floods a target with SYN packets?",
            "options": ["Ping of Death", "SYN Flood", "Smurf Attack", "Teardrop"],
            "answer": 1,
            "explanation": "SYN Flood exhausts server resources by sending many SYN packets without completing the handshake, leaving connections half-open."
        },
        {
            "q": "What does a Man-in-the-Middle attack intercept?",
            "options": ["Only passwords", "All traffic between two parties", "Only DNS queries", "Only HTTPS traffic"],
            "answer": 1,
            "explanation": "MitM attacks intercept all communication between two parties, potentially capturing any unencrypted data."
        },
    ],
    "wireless": [
        {
            "q": "Which wireless encryption is considered broken?",
            "options": ["WPA3", "WPA2", "WEP", "WPA2-Enterprise"],
            "answer": 2,
            "explanation": "WEP (Wired Equivalent Privacy) has fundamental cryptographic weaknesses and can be cracked in minutes."
        },
        {
            "q": "What tool is commonly used for wireless auditing?",
            "options": ["Wireshark", "Aircrack-ng", "Nmap", "Metasploit"],
            "answer": 1,
            "explanation": "Aircrack-ng is a complete suite for wireless security auditing, including packet capture and password cracking."
        },
        {
            "q": "What is a deauthentication attack?",
            "options": ["Cracking WPA", "Forcing clients to disconnect", "Spoofing an AP", "Capturing handshakes"],
            "answer": 1,
            "explanation": "Deauth attacks send spoofed frames to disconnect clients from an AP, often used to capture WPA handshakes when they reconnect."
        },
    ],
    "cryptography": [
        {
            "q": "Which algorithm is asymmetric?",
            "options": ["AES", "DES", "RSA", "Blowfish"],
            "answer": 2,
            "explanation": "RSA uses a public-private key pair (asymmetric), while AES, DES, and Blowfish use the same key for encryption and decryption (symmetric)."
        },
        {
            "q": "What is the purpose of a hash function?",
            "options": ["Encrypt data", "Create a fixed-size fingerprint", "Generate keys", "Compress files"],
            "answer": 1,
            "explanation": "Hash functions create a fixed-size digest (fingerprint) of data, used for integrity verification and password storage."
        },
        {
            "q": "Which attack uses precomputed hash tables?",
            "options": ["Brute force", "Dictionary attack", "Rainbow table attack", "Birthday attack"],
            "answer": 2,
            "explanation": "Rainbow table attacks use precomputed hash-to-plaintext mappings, trading storage for speed in cracking passwords."
        },
    ],
}


@register(
    name="get_quiz_question",
    description="Get a quiz question from a specific domain or random. Returns question, options, and stores answer internally.",
    parameters={
        "domain": {
            "type": "string",
            "description": "Domain: reconnaissance, scanning, system_hacking, web_attacks, network_attacks, wireless, cryptography, or 'random'"
        }
    }
)
def get_quiz_question(domain: str) -> dict:
    if domain == "random":
        domain = random.choice(list(QUESTIONS.keys()))
    
    if domain not in QUESTIONS:
        return {
            "error": f"Unknown domain: {domain}",
            "available": list(QUESTIONS.keys())
        }
    
    q = random.choice(QUESTIONS[domain])
    
    return {
        "domain": domain,
        "question": q["q"],
        "options": {
            "A": q["options"][0],
            "B": q["options"][1],
            "C": q["options"][2],
            "D": q["options"][3],
        },
        "correct_index": q["answer"],
        "explanation": q["explanation"]
    }


@register(
    name="list_quiz_domains",
    description="List all available quiz domains with question counts.",
    parameters={},
    required=[]
)
def list_quiz_domains() -> dict:
    return {
        "domains": {k: len(v) for k, v in QUESTIONS.items()},
        "total_questions": sum(len(v) for v in QUESTIONS.values())
    }
