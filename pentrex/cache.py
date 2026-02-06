"""Simple response cache for common queries."""

# Pre-computed responses for instant answers
CACHE = {
    "help": """Available commands:
• quiz [domain] - Test your knowledge (domains: reconnaissance, scanning, system_hacking, web_attacks, network_attacks, wireless, cryptography)
• explain [topic] - Learn a concept (sql_injection, xss, arp_spoofing, buffer_overflow, phishing, mitm)
• tool [name] - Tool guide (nmap, metasploit, burp_suite, wireshark, sqlmap, hydra, aircrack, john)
• scenario [name] - Attack walkthrough
• reset - Clear conversation""",

    "hi": "Hey! Ready to learn some security? Try 'quiz web_attacks' or 'explain sql injection'.",
    "hello": "Hey! Ready to learn some security? Try 'quiz web_attacks' or 'explain sql injection'.",
    
    "what can you do": """I can help you learn cybersecurity:
• Quiz you on CEH topics
• Explain attack techniques
• Show pentest tool usage
• Walk through attack scenarios

Try: 'quiz me' or 'explain xss'""",
}


def check_cache(query: str) -> str | None:
    """Return cached response if available."""
    q = query.lower().strip()
    
    # Exact match
    if q in CACHE:
        return CACHE[q]
    
    # Partial match
    for key, response in CACHE.items():
        if key in q:
            return response
    
    return None
