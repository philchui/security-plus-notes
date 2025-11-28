DOMAIN 2 — Threats, Vulnerabilities, Attacks (Master Outline)

2.1 Threat Actors & Profiles
2.2 Social Engineering (phishing, impersonation, watering hole, misinformation)
2.3 Application / Memory / Code Vulnerabilities
 • Overflow
 • Race condition
 • SQLi / XSS / injection
 • DLL injection / process hollowing
 • Malicious updates (SolarWinds)
 • Patch management errors
 • OS vulnerabilities
 • Zero-days
 • Cloud misconfigurations
 • Supply chain attacks
 • Misconfiguration vulnerabilities
 • Virtualization vulnerabilities
 • Hardware/firmware vulnerabilities (IoT, EOL/EOSL, compensating controls)

2.4 Malware & Variants
 • Virus, worm, ransomware
 • Fileless malware
 • Spyware, adware, bloatware
 • Rootkits
 • Logic bombs
 • Keyloggers
 • RATs
 • Botnets, C2, DDoS

2.5 Network Attacks
 • DoS/DDoS
 • Amplification/reflection
 • On-path (MITM)
 • ARP poisoning
 • Replay attacks
 • DNS poisoning / typosquatting
 • Wireless attacks
  – Deauth
  – Evil twin
  – RF jamming
  – PMF
  – Fox-hunting

DOMAIN 2 — Threats, Vulnerabilities, Attacks (Part 1)

Covering 2.1 Threat Actors, 2.2 Threat Vectors (Messaging / Files / Telephony / USB / Network / Wireless).

ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 2 (Part 1)
2.1 THREAT ACTORS — ULTRA-DENSE

Threat actors are defined by:
• Origin (internal/external)
• Resources (low → nation-state)
• Sophistication (script kiddie → APT)
• Motivation (money, political, ideological, revenge)
• Persistence (one-off → long-term foothold)

This table must be memorized verbatim for Security+.

A. Nation-State / APT (Advanced Persistent Threat)
Origin: External
Resources: Very high
Sophistication: Very high / custom malware
Motivation: Strategic, political, espionage

Behavior:
• Long-term infiltration
• Custom 0-days
• Supply-chain attacks
• Strong OPSEC
• Lateral movement

Targets:
• Governments
• Critical infrastructure
• Energy, finance, healthcare

Defenses:
• Segmentation
• EDR + behavioral analytics
• Threat intelligence
• Zero Trust
• Insider-risk monitoring

B. Organized Crime
Origin: External
Resources: High
Motivation: Money

Typical Attacks:
• Ransomware
• Business Email Compromise (BEC)
• Data theft → resale
• Double extortion ransomware
• Cryptomining

Defenses:
• Backups
• Email security
• Payment authorization controls
• Patching of internet-facing systems

C. Hacktivist
Motivation: Ideological, political, social

Attacks:
• DDoS
• Website defacement
• Doxing (publishing private info)
• Leaks

Moderate skill, high publicity motivation.

D. Insider Threat
Origin: Internal
Access: Legitimate internal access
Motivation: Revenge, financial, coercion

Risks:
• Data theft
• Sabotage
• Policy bypass
• Privilege misuse

Defenses:
• Separation of duties (SoD)
• UEBA (User and Entity Behavior Analytics)
• Strict offboarding
• Logging/monitoring
• Honeytokens

E. Script Kiddie
Low skill, uses pre-made tools (Metasploit, LOIC).
Motivation: curiosity, mischief, clout.

F. Shadow IT
Internal team installs unsanctioned cloud apps.
Risk: no patching, no backups, no governance.

Threat Actor Memory Hook: AIMR
A = Actor
I = Inside/Outside
M = Motivation
R = Resources

2.2 THREAT VECTORS — ULTRA-DENSE

Threat vector = HOW the attacker gets in.

Security+ loves tricking candidates by mixing motivations (actor) with delivery (vector).
Vectors = paths, not people.

We will cover vectors grouped into categories:
• Messaging
• Files
• Telephony
• USB / Peripherals
• Software/Patch
• Network/Wireless
• Defaults/Misconfig
• Supply Chain

A. Messaging Vectors (Email, SMS, IM/DM)

Phishing (Email)
• Spoofed sender
• Fake invoices
• Credential harvesting
• Malware links/attachments
• Urgency, fear, reward pretexts

Defenses:
• Secure email gateways
• SPF, DKIM, DMARC
• URL rewriting/sandboxing
• Anti-malware detonators
• User training + reporting workflows
• MFA

Smishing (SMS/Text)
Shortened URLs, fake bank alerts, delivery notifications.

Angler Phishing (Social Media)
Fake customer support accounts reply to your post.

Vishing (Voice)
Caller pretends to be bank, IT, government, IRS.
Goal: obtain sensitive info or MFA codes.

Clone Phishing
A real email is copied and resent with a malicious link/attachment.

B. File & Content Vectors

Executables
Obvious malware loaders.

PDFs
Can contain scripts, embedded objects.

Office Docs / Macros
VBA macros, add-ins.
Often delivered as password-protected ZIPs to bypass filters.

Defenses:
• Disable macros
• Protected view mode
• Allow-list signed macros
• EDR script control
• CDR (Content Disarm & Reconstruction)

Browser Extensions
Malicious, hijacked, or abandoned extensions.

Defenses:
• Extension allow-list
• Enterprise store control

SVG Files
SVG = XML → can embed HTML/JS → can trigger XSS/code execution.

C. Telephony Vectors

Vishing — Phone-based impersonation.

SPIT — Spam over internet telephony (VoIP).

War-Dialing — Calling thousands of numbers looking for modems/IVRs.

SMS flooding — Used to DoS mobile numbers.

D. Removable Media & Peripheral Vectors

USB Drop Attacks
Attacker plants USBs hoping victims plug them in.

BadUSB / HID Emulation
USB enumerates as a keyboard → types commands automatically.

Most people misunderstand this:
BadUSB is NOT “a malicious file.”
It’s a malicious device identity.

Defenses:
• Device control
• Disable USB storage/HID
• Auto-run disabled
• EDR scanning on insert

E. Software / Patch State Vectors

Unpatched Applications
Top enterprise attack vector.
Exploits known CVEs → RCE, privilege escalation.

Unsupported OS
Legacy systems without patches → must isolate.

Mitigations:
• Virtual patching via IPS/WAF
• VLAN isolation
• Jump hosts
• Restrict inbound/outbound

F. Network & Wireless Vectors

Exposed services / open ports
Public-facing services → attack surface.

Misconfigurations
Default credentials, open directories, weak firewall rules.

Wi-Fi
• Rogue AP
• Evil twin
• Deauthentication
• KRACK (older WPA2 weakness)
• WPA2-PSK cracking (weak passphrases)

Bluetooth
Weak pairing, data leaks.

802.1X Absence
Allows unauthorized devices to plug into network jacks.

G. Default Credentials & Weak Authentication

• “admin/admin”, “root/root”
• Mirai botnet scans 60+ defaults
• IoT devices rarely changed

Mitigation:
• Force password changes
• Unique per-device creds
• Segment IoT

H. Supply-Chain Vectors

Attackers compromise:
• Vendors
• Distributors
• Third-party providers
• Hardware manufacturers
• Cloud providers
• Update delivery chain

Examples:
• SolarWinds Orion (malicious signed updates)
• Target 2013 HVAC breach
• Counterfeit Cisco gear

✔️ End of Domain 2 — Part 1

DOMAIN 2 — Threats, Vulnerabilities, Attacks (Part 2)

This chunk covers Social Engineering in full depth (2.2), including phishing, impersonation, watering hole attacks, misinformation/disinformation, and all behavioral vectors.
Say “Next chunk.” when ready for Part 3.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 2 (Part 2)
SOCIAL ENGINEERING — COMPLETE FRAMEWORK

Social engineering = psychological manipulation to make a target perform an action they normally would not.
Security+ tests patterns, pretexts, delivery channels, and preventive controls.
The exam LOVES mixing these terms — you must know them in crisp definitions.

A. CORE SOCIAL ENGINEERING CONCEPTS

Impersonation
Attacker pretends to be:
• IT support
• Executive (CEO fraud / whaling)
• Bank, vendor, IRS
• Delivery person
• Law enforcement
• Building maintenance

Goal:
Gain trust → extract credentials, data, or actions.

Mitigations:
• Verification callbacks
• Challenge procedures
• Policies forbidding giving credentials over phone
• Security awareness training

Pretexting
The story that justifies the request.

Examples:
• “I’m IT, we detected malware on your machine.”
• “Accounting needs your W-2 for year-end audit.”
• “We have a package that requires your employee ID.”

Exam trigger phrase:
“A fabricated scenario used to manipulate the victim.”

Elicitation
Subtle extraction of info:
• “So what VPN software do you guys use?”
• “When does your team push patches?”
• “What’s the CEO’s email format?”

Always conversational, low-pressure.

Authority
Exploits power imbalance:
• CEO
• Government
• Police
• Doctors/experts

Key clue:
Victim complies because of perceived authority.

Intimidation
Threats, fear, legal consequences.

Example:
• “If you don’t act now, your account will be closed.”

Urgency
Time pressure:
• “Invoice overdue — pay immediately.”
• “Password reset required now.”

The most common social engineering trigger.

Familiarity / Liking
Attacker builds rapport:
• Pretends to know coworkers
• Uses shared interests
• Appears friendly or helpful

Scarcity
Limited-time offers:
• “Only 10 spots left.”
• “Your bonus expires today.”

B. PHISHING FAMILY (EMAIL, SMS, SOCIAL MEDIA, PHONE)

Phishing
Mass, untargeted email-based attack.

Spear Phishing
Targeted to specific person or team.
• Uses personal details
• Often mimics real communications

Whaling
Targets executives (CFO, COO, CEO).
• High-value wire fraud
• Business Email Compromise (BEC)

Smishing
SMS-based phishing.

Vishing
Voice/phone-based impersonation.

Angler Phishing
Social media impersonation:
• Fake customer support accounts
• DMs offering “help”

Clone Phishing
Legitimate email copied → malicious version forwarded.

C. MISINFORMATION / DISINFORMATION / INFLUENCE CAMPAIGNS

Security+ tests these heavily because of social-media exploitation.

Misinformation
False info shared accidentally.

Disinformation
False info shared intentionally to deceive.

Influence Campaign
Coordinated use of misinformation/disinformation at scale:
• Bots
• Fake accounts
• Paid ads
• Doctored video/images (deepfakes)

Goals:
• Political manipulation
• Social division
• Financial scams
• Reputation damage

D. BRAND IMPERSONATION / SEARCH ENGINE POISONING

Brandjacking
Fake website mimicking real brand.

Typosquatting / URL Hijacking
Attacker registers similar domain:
• professormessar.com
• professormesser.net
• professormesser.co

Usually leads to:
• Credential harvesting
• Malware distribution
• Ad fraud

Search Engine Poisoning
Attacker floods Google results with malicious lookalike sites.

E. WATERING HOLE ATTACKS

Attacker compromises a third-party site the target organization frequently visits.

Steps:

Recon (which sites employees use)

Attacker infects that site

Only visitors from target org get payload

Malware delivered silently

Why it works:
• The site is trusted
• Employee does nothing risky
• Bypasses user training
• Hard to detect

F. INSIDER SOCIAL ENGINEERING

Attack can originate from inside the org:
• Disgruntled employees
• Malicious insiders
• Inadvertent insiders

Includes:
• Policy bypass
• Data theft
• Credential abuse
• Sabotage

Mitigations:
• Least privilege
• UEBA
• SoD / dual control
• Audit everything
• Mandatory vacations

G. DEFENSE AGAINST SOCIAL ENGINEERING

User Training
Core control:
• Verify before trusting
• Don’t click embedded links
• Use official channels only
• Recognize pretexting patterns
• Report suspicious comms

Technical Controls
• Email filtering (SEG)
• DMARC/SPF/DKIM (anti-spoofing)
• URL rewriting
• Sandboxing
• Browser isolation
• MFA
• Conditional access

Process Controls
• Callback verification
• Change management
• Chain-of-command verification
• Vendor verification procedures
• Escalation paths

✔️ End of Domain 2 — Part 2

DOMAIN 2 — Threats, Vulnerabilities, Attacks (Part 3)

Covering Application / Memory / Code Vulnerabilities:
• Buffer overflows
• Race conditions / TOCTOU
• Memory injections (DLL injection, process hollowing)
• SQL Injection
• Cross-Site Scripting (XSS)
• Malicious updates / supply-chain code compromise
• Patch failures / OS vulnerabilities
• Zero-days

Say “Next chunk.” when ready for Part 4 (Malware & Variants).

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 2 (Part 3)
APPLICATION / CODE / MEMORY VULNERABILITIES

This section produces 99% of all classic Security+ scenario questions.

A. BUFFER OVERFLOWS (Memory Overrun)

Definition
Program writes more data than allocated → spills into adjacent memory.

Consequences:
• Privilege escalation (overwrite permission variables)
• Arbitrary code execution (overwrite return pointer)
• System crash (unstable overflow)

Transcript Example (must memorize)

Variable A: size 8 bytes
Variable B: holds privilege value (example: 1979)
Attacker inputs 9 bytes → 9th byte overwrites B
B becomes large value (example: 25,856) → application grants admin rights.

This structure EXACTLY mirrors real exam content.

Why It’s Dangerous
• Can lead to RCE (Remote Code Execution)
• Precise manipulation needed
• Crashes during testing but devastating if successful

Mitigations

Compiler/OS Protections:
• DEP (Data Execution Prevention): non-executable memory pages
• ASLR (Address Space Layout Randomization): randomize memory addresses
• Stack canaries: secret value before return pointer
• Safe functions: strncpy, memcpy_s

Design Protections:
• Input validation
• Manage bounds
• Use managed languages (Java, C#, Python)

Related Vulnerabilities
• Stack overflow
• Heap overflow
• Integer overflow

B. RACE CONDITIONS (Timing Attacks) — TOCTOU

Definition
Two operations occur simultaneously → program uses stale or incorrect data.

TOCTOU (Time-of-Check to Time-of-Use):
Attacker changes resource after check but before use.

Transcript Example (Bank Account)
User 1 deposits
User 2 deposits
Both withdraw based on stale balance
Final result inconsistent → duplicated funds

Dangers
• Privilege escalation
• Logic manipulation
• Data corruption
• Unpredictable results

Mitigation
• Thread-safe coding (locks, semaphores, mutexes)
• Atomic operations
• Re-validate data immediately before use
• Fuzzing during testing (concurrency tests)

C. MEMORY-RESIDENT MALWARE & CODE INJECTION

Attackers inject code into trusted processes to hide.

Process Injection
Malware writes payload into other process’s memory.

DLL Injection
Attacker forces a process to load a malicious DLL.

Behaviors:
• The injected DLL runs inside legitimate process
• Inherits same privileges
• Makes malware invisible to process lists

Process Hollowing
Attacker launches legitimate process, empties it, and fills it with malicious code.

Why It’s Powerful
• Evades traditional AV
• Appears as trusted process
• Can escalate privileges

Defenses
• EDR detecting API calls (WriteProcessMemory, LoadLibrary)
• Code signing
• AppLocker / WDAC
• Least privilege
• Patch OS vulnerabilities

D. SQL INJECTION (SQLi)

Core Concept
Application inserts unsanitized input into SQL query.
Classic payload: ' OR 1=1--

Transcript Example

Original:

SELECT * FROM users WHERE name='Professor';


Injected:
Professor' OR '1'='1

Returns all rows → data exposure.

Impacts
• Data theft
• Modifying/deleting records
• Admin takeover
• Entire DB access

Prevention
• Prepared statements
• Stored procedures
• Allow-list input validation
• Least privilege DB accounts
• WAF rules (UNION SELECT, OR 1=1)

E. CROSS-SITE SCRIPTING (XSS)

Definition
Attacker injects JavaScript into trusted webpage → runs in victim’s browser.

Types

Reflected — URL parameter triggers script

Stored (Persistent) — script stored on server

DOM-based — browser manipulates DOM insecurely

Impacts
• Steal cookies
• Session hijacking
• Account takeover
• Browser-based malware delivery

Mitigation
• Input validation
• Output encoding
• CSP (Content-Security-Policy)
• Sanitizing user input
• Using frameworks that auto-escape (React, etc.)

F. MALICIOUS UPDATES (SUPPLY-CHAIN ATTACKS)

Code Signing
Updates must be digitally signed by vendor.

Attack Scenarios
• Fake update popups
• Compromised developer environment
• Attacker inserts malware before code signing
• Man-in-the-middle during update

SolarWinds Orion Example
• Attackers injected malicious code into official update
• Signed and distributed to 18,000+ organizations
• Created backdoors into elite government networks

Mitigation
• Strict patch source verification
• Validate signatures
• Monitor for unexpected outbound traffic
• Test before deployment

G. PATCH & OS VULNERABILITIES

Patch Gap
Time from vendor release → full deployment.
Attackers reverse-engineer patches to create N-day exploits.

OS Vulnerabilities
Due to:
• Huge codebases
• Millions of lines of code
• Hidden bugs
• Complex dependencies

Patch Best Practices
• Back up before patch
• Test in sandbox
• Use trusted sources
• Validate signatures
• Roll out in phases

H. ZERO-DAY VULNERABILITIES

Zero-Day Definition
Flaw known to attackers but no patch exists.

Zero-Day Exploit
Active attack before vendor fixes it.

Protection
• Behavior-based detection
• EDR/XDR
• Network IDS heuristics
• Segmentation
• Rapid deployment of vendor patch once available

✔️ End of Domain 2 — Part 3

DOMAIN 2 — Threats, Vulnerabilities, Attacks (Part 4)

This chunk covers Malware & Variants entirely:
• Malware overview
• Viruses
• Worms
• Ransomware
• Fileless malware
• Spyware, adware, bloatware
• Keyloggers
• Logic bombs
• Rootkits
• RATs
• Botnets / C2 infrastructure
• Malware infection chain
• Detection techniques

When you're ready, say “Next chunk.” for Part 5.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 2 (Part 4)
FULL MALWARE & MALWARE BEHAVIOR FRAMEWORK

Malware = any malicious software designed to cause harm, steal data, or gain unauthorized access.

A. MALWARE OVERVIEW (FOUNDATION)

Malware Purposes
• Financial gain (ransomware, banking trojans, crypto miners)
• Espionage (APT implants)
• Disruption (wiping, sabotage)
• Persistence (backdoors, RATs)
• Botnet formation (distributed attacks)

Malware Entry Vectors
• Email attachments
• Phishing links
• Malicious websites
• Drive-by downloads
• USB devices
• Exploiting vulnerabilities
• Supply-chain updates

Malware Lifecycle (“Chain”)

Delivery (phish/drive-by/USB)

Execution (script, macro, exploit)

Persistence (registry keys, scheduled tasks)

Command and Control (C2) (attacker communication)

Lateral movement

Actions on objectives (exfiltration, encryption, theft)

Security+ repeatedly tests this sequence.

B. VIRUSES — ULTRA-DENSE

Definition
Malicious code that replicates by infecting host files and requires user action to run.

Types

a. Program/File-Infector Virus
Attaches to .exe files.

b. Boot-Sector Virus
Installs in Master Boot Record (MBR).

c. Macro Virus
Uses Office/VBA macros.
Spreads via documents (Word, Excel).

d. Script Virus
Based on scripting languages (VBScript, JavaScript, PowerShell).

e. Fileless Virus
Executes entirely in memory.

Fileless Malware
Critical exam concept.

Definition:
• No files written to disk
• Runs in memory only
• Uses system tools (PowerShell, WMI)
• Evades signature-based antivirus

How it spreads:
• Exploits vulnerabilities (Flash, Java, browser)
• Malicious scripts injected into memory
• Drive-by downloads

Mitigation:
• EDR behavioral analysis
• Restrict PowerShell (Constrained Language Mode)
• Patch browsers
• Least privilege

C. WORMS

Definition
Self-replicating malware that spreads automatically without user interaction.

Characteristics
• Exploits unpatched vulnerabilities
• Spreads at network speed
• Can carry secondary payloads (Ransomware, backdoors)

Example: WannaCry (2017)
• Used EternalBlue (SMBv1 vulnerability)
• Global outbreak
• Encrypted systems with ransomware payload

Mitigation
• Patch OS
• Disable SMBv1
• Firewall segmentation
• IDS/IPS signatures

D. RANSOMWARE — EXAM HEAVYWEIGHT

Definition
Malware that encrypts files and demands payment for decryption.

Behavior
• Leaves OS functional
• Displays ransom note
• Often uses double extortion (encrypt + steal data)
• Sometimes also spreads laterally via PsExec, SMB

Mitigation
• Offline backups (most important)
• Patch vulnerabilities
• EDR detection of rapid-file-encryption behavior
• Network segmentation
• Email filtering/sandboxing

Response
• Don’t pay
• Wipe + restore from known-good backup
• Incident report
• Forensics if needed

E. SPYWARE, ADWARE, BLOATWARE

Spyware
Covertly collects:
• Browsing habits
• Credentials
• Keystrokes
• Screenshots

Keylogger (special subtype)
Captures keystrokes before encryption → defeats TLS/VPN.

Mitigations:
• Anti-malware
• EDR
• Least privilege
• Hardened keyboards/secure input paths

Adware
Displays ads, tracks web usage.

Bloatware
Preinstalled vendor software.
Weakens system, presents vulnerabilities.

Mitigation:
• Remove unnecessary software
• Use golden images / clean OS deployments

F. LOGIC BOMBS

Definition
Malware triggered by specific condition:
• Date/time
• User login
• Specific event

Often insider-created.

Mitigation
• Change management
• File integrity monitoring (FIM)
• Strict privilege controls
• Logging

G. ROOTKITS

Definition
Stealth malware that hides:
• Processes
• Files
• Registry keys
• Network connections

Types
• User-mode
• Kernel-mode
• Boot/UEFI
• Firmware rootkits
• Driver-level rootkits

Why Dangerous
• Load before OS security
• Modify kernel
• Persist after reinstalls (UEFI)
• Evade detection tools

Detection
• Offline scans
• Secure Boot
• Memory forensics
• FIM

Mitigation
• Secure boot
• Hardware attestation
• Reflash firmware
• Full OS reinstall

H. REMOTE ACCESS TROJANS (RATs)

Definition
Malware giving attacker remote control:
• Keylogging
• Screen capture
• File transfer
• Camera/mic access
• System manipulation

Examples
• DarkComet
• PlugX
• njRAT

RAT = remote access tool + malware capabilities.

I. TROJANS

Definition
Malware disguised as legitimate software.

Types
• Downloader Trojan
• Dropper
• Fake installers
• Pirated software bundles

J. BOTNETS & C2 INFRASTRUCTURE

Botnet
Network of compromised “zombie” machines controlled remotely.

Command & Control (C2)
Attackers use:
• IRC
• HTTP/S
• Peer-to-peer
• Tor hidden services
• Social media channels

Uses
• DDoS
• Spam campaigns
• Credential stuffing
• Ransomware distribution

Detection
• Unusual outbound traffic
• Beaconing patterns
• DNS anomalies
• EDR alerts

K. MALWARE DETECTION METHODS

Signature-Based
Matches known patterns → fails against zero-days/fileless.

Heuristics
Detect suspicious patterns.

Behavioral Analysis
Looks for malicious actions:
• Rapid encryption
• Registry modification
• Network beacons

Sandboxing
Executes suspicious files in isolated VM.

Memory Analysis
Detects in-memory payloads, injections, hooks.

✔️ End of Domain 2 — Part 4

DOMAIN 2 — Threats, Vulnerabilities, Attacks (Part 5)

This chunk covers:
• Network attacks
• DoS vs DDoS
• Amplification & reflection attacks
• Botnets
• On-path / MITM
• ARP poisoning
• Replay attacks
• DNS poisoning & URL hijacking
• Wireless attacks (deauth, evil twin, jamming, PMF)

This is one of the most scenario-heavy areas on the actual Security+ exam.
When ready, say “Next chunk.” for Part 6.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 2 (Part 5)
NETWORK ATTACKS & WIRELESS ATTACKS
A. DENIAL OF SERVICE (DoS) & DISTRIBUTED DoS (DDoS)

DoS (single source)
Attacker overloads a system → service becomes unavailable.

Mechanisms:
• Bandwidth flood
• CPU exhaustion
• Memory exhaustion
• Vulnerability-trigger (malformed packet → crash)
• Resource depletion (threads/sockets)

DDoS (multiple sources)
Uses botnets → thousands/millions of devices coordinated to attack.

Why it’s harder to stop:
• Traffic originates from MANY IPs
• Cannot simply block one source
• Traffic may look legitimate
• Requires upstream ISP or cloud scrubbing

Botnets (C2-Controlled)
• Infected machines = zombies
• Controlled via Command & Control servers
• Used for:
◦ DDoS
◦ Spam
◦ Ransomware delivery
◦ Credential stuffing

Common C2 transports:
• IRC
• HTTP/S
• Peer-to-peer
• Tor hidden services

Self-Inflicted DoS
Accidental misconfigurations cause outages:
• Network loops (no STP)
• Misconfigured ACLs
• Saturating bandwidth
• Recursive DNS misconfig

Exam clue:
“Admin made a change → entire network collapsed.” → Self-DoS.

B. AMPLIFICATION & REFLECTION ATTACKS

Amplification = small request → massive response
Reflection = spoof victim’s IP → server replies to victim

Most exam questions combine both.

DNS Amplification
Attacker → tiny DNS query → open DNS resolver
Resolver → HUGE response (ANY query) → sent to victim

Amplification factor can exceed 50x–100x.

NTP Amplification
monlist command returns large client list.
Old NTP servers = dangerous amplifiers.

ICMP Amplification (Smurf Attack)
Attacker spoofs victim → sends ICMP echo-request to broadcast address
All hosts reply → flood victim.

Modern routers block directed broadcasts, but it’s still tested.

LDAP, SSDP, CLDAP Amplification
Any protocol that responds with more data than sent is usable.

C. ON-PATH ATTACKS (MITM — Man-In-The-Middle)

Definition:
Attacker sits between two parties → intercepts, reads, modifies, or redirects traffic.

Exam synonyms:
• On-path
• Man-in-the-middle
• Transparent proxy
• Session hijacking (if stealing cookies)

D. ARP POISONING (EXAM REQUIRED)

ARP = Address Resolution Protocol
Maps IP → MAC
Has no authentication
Therefore: easily forged.

How ARP Poisoning Works
Attacker sends forged ARP replies:

Victim’s ARP table:
192.168.1.1 → attacker MAC

Router’s ARP table:
192.168.1.9 → attacker MAC

Result:
• All traffic flows THROUGH attacker
• Fully invisible
• Enables: MITM, sniffing, modification, credential theft

Detection
• Duplicate MAC addresses
• ARP watch tools
• Strange ARP activity in logs

Mitigation
• Dynamic ARP Inspection (DAI)
• Port security (sticky MAC)
• VLAN segmentation
• Encrypted protocols (HTTPS, SSH)
• Use of certificate pinning

E. ON-PATH BROWSER ATTACK (MAN-IN-THE-BROWSER)

Even MORE dangerous than MITM.

Definition
Malware installs LOCAL proxy inside the victim’s browser.

Because it lives INSIDE the endpoint:
• Sees plaintext BEFORE encryption
• Sees decrypted data AFTER TLS

TLS cannot protect you.

Dangers
• Transaction manipulation (bank transfers)
• Credential theft
• Autofill harvesting
• Session hijacking

Mitigations
• Endpoint security (EDR)
• Hardening browsers
• Application whitelisting
• Secure boot

F. REPLAY ATTACKS

Definition
Attacker captures valid traffic → replays it later to impersonate user.

Examples:
• Captured login token
• Captured Kerberos ticket
• Captured authentication cookies

Mitigation
• Nonces
• Timestamps
• Session tokens
• TLS
• MFA

G. DNS ATTACKS

DNS Poisoning
Modify DNS responses to redirect victims.

Methods:
• Modify hosts file
• Poison resolver cache
• MITM the DNS traffic
• Compromise authoritative DNS server
• Compromise domain registrar login

Effects:
• Redirect to phishing sites
• Redirect email MX entries
• Redirect software update endpoints

DNSSEC (Mitigation)
Digitally signs DNS responses.
Clients verify authenticity.

URL Hijacking / Typosquatting
Register similar domain names:
• misspellings
• extra/missing letters
• different TLD

Used to:
• steal credentials
• deliver malware
• run ads

H. WIRELESS ATTACKS

This is a major exam hotspot.

Deauthentication Attack (802.11 Management-Frame Attack)

Core weakness:
Legacy Wi-Fi sent management frames unencrypted.

Attacker:
• Sniffs AP MAC + client MAC
• Sends forged “deauth” frames
• Client is forced offline
• If repeated → total DoS

Tools:
• airmon-ng
• aireplay-ng

Evil Twin
Attacker creates malicious AP:
• Same SSID
• Stronger signal

Victim connects → attacker performs MITM.

Mitigation:
• 802.1X
• Certificate-based Wi-Fi
• User training
• Wireless IDS

Rogue AP
Unauthorized (internal) AP connected to network.

RF Jamming
Attacker floods radio spectrum with noise.

Types:
• Constant jamming
• Random jamming
• Legit-looking packet floods
• Reactive jamming (only active when legitimate traffic observed)

Requires physical proximity.

Detection:
• Directional antennas
• Spectrum analyzers
• “Fox hunting” techniques

PMF (Protected Management Frames, 802.11w)
Fixes plaintext management frames.
Prevents:
• Deauth attacks
• Disassoc attacks

Important:
Not all management frames are encrypted (e.g., beacons, probe requests).

✔️ End of Domain 2 — Part 5

DOMAIN 2 — Threats, Vulnerabilities, Attacks (Part 6)

This chunk covers:
• Misconfiguration vulnerabilities (default creds, open S3 buckets, plaintext protocols, firewall errors)
• Cloud-specific vulnerabilities
• Legacy systems (EOL/EOSL) & compensating controls
• IoT / embedded firmware vulnerabilities
• Virtualization vulnerabilities (VM escape, resource reuse)
• Supply-chain vulnerabilities

After this section, Domain 2 will be nearly complete.
When ready, say “Next chunk.” for Part 7.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 2 (Part 6)
MISCONFIGURATION, CLOUD, IOT, VIRTUALIZATION, SUPPLY-CHAIN VULNS

This is one of the most high-yield Security+ categories.

A. MISCONFIGURATION VULNERABILITIES (LOW-EFFORT BREACH PATHS)

Misconfigurations are the #1 cause of real-world breaches.
Security+ LOVES these scenarios.

Public Cloud Storage Exposure (S3, Azure Blob, GCP Buckets)

Symptoms:
• Bucket left “public”
• Unauthenticated listing/download enabled
• Sensitive data found via search engines

Real examples:
• Verizon 14M records exposed (open S3 bucket)

Mitigation:
• Block Public Access
• Private ACLs only
• CSPM tools (Cloud Security Posture Management)
• Encryption at rest + audit logging
• Enforce IAM least privilege

Unsecured Admin Accounts (Root / Administrator)

Risks:
• Default passwords
• Direct root login over SSH/RDP
• No MFA
• Admin accounts enabled but unused

Fix:
• Disable direct root login
• Use sudo (Linux) or “Run as admin” (Windows)
• Enforce MFA for all admins
• Vaulted rotating credentials

Insecure Protocols (HTTP, FTP, Telnet, IMAP, POP3)

Problem:
Credentials & data transmitted in cleartext.

Exam keyword: Wall of Sheep
At DEF CON, plaintext creds are displayed from sniffed Wi-Fi traffic.

Secure alternatives:
• HTTPS
• SFTP / FTPS
• SSH
• IMAPS / POP3S
• SMTPS

Enforce TLS everywhere.

Default Credentials (IoT, routers, cameras)

Mirai botnet exploited dozens of default login combos.
IoT manufacturers ship many devices with:
• admin/admin
• root/12345
• No forced password change

Mitigations:
• Change every default
• Unique credentials per device
• Disable remote admin
• Segment IoT VLAN

Excessive Open Ports / Weak Firewall Rules

Symptoms:
• Exposed SSH, RDP, database ports
• Allow-all inbound rules
• Stale firewall rules
• Unknown services listening

Fix:
• Default-deny firewall rule
• Regular rule review
• External port scans
• WAF for web applications

Directory Traversal (../)

Occurs when input is not validated, allowing attacker to access:
• /etc/passwd
• application configs
• unintended directories

Fix:
Canonicalize path → only allow expected input.

B. CLOUD-SPECIFIC VULNERABILITIES

Cloud attacks = configuration + identity failures.

Weak Authentication
• No MFA for cloud console
• Use of static long-lived access keys
• Overly permissive IAM roles (“:*” resources)

Fix:
• Mandatory MFA
• Short-lived tokens
• Least privilege IAM

Unpatched Cloud Services
63% of public cloud code is unpatched (CVE ≥ 7).

Fix:
• Automated patching
• Continuous scanning
• Managed services

Public Exposure of Databases
• Open MongoDB / Elasticsearch
• Exposed RDS instances
• No firewall restrictions

Directory Traversal / RCE in Cloud Apps

Typical queries:
• ../../
• Unsafe file upload
• Log4Shell (Log4j)
• Spring4Shell

DDoS Exposure

Cloud services highly exposed to:
• SYN floods
• UDP floods
• HTTP floods

Fix:
• Auto-scaling
• CDNs
• Cloud-based DDoS mitigation (AWS Shield, Cloud Armor, Akamai)

C. LEGACY SYSTEMS (EOL/EOSL) + COMPENSATING CONTROLS

EOL = End of Life
EOSL = End of Service Life (no patches)

EOL/EOSL systems are unpatchable and must be isolated.

Why Legacy Systems Persist
• Critical business apps
• No vendor support
• High migration cost
• Hardware constraints

Risks
• No security patches
• Unfixable vulnerabilities
• Increased audit risk
• Often run SMBv1, outdated TLS, old kernels

Compensating Controls
When you cannot patch:

Isolation
• Segmented VLAN
• Firewall restrict inbound/outbound
• Jump hosts
• No Internet access

Virtual Patching
• IPS signatures
• WAF rules
• Reverse proxies

Access Controls
• Least privilege
• PAM
• MFA on jump hosts

Monitoring
• Log forwarding to SIEM
• EDR on the management system

Backups
• Frequent, tested
• Offline copies

Change Control
• Document exceptions
• Track risk acceptance

D. IOT / EMBEDDED FIRMWARE VULNERABILITIES

IoT = Internet of Things
Embedded firmware often insecure.

Why IoT Is High-Risk
• Usually unpatchable or slow to patch
• Vendor firmware delays (e.g., Trane 2014→2016 delay)
• Weak/no authentication
• Outdated libraries
• Exposed web UI
• Hard-coded credentials
• Rare logging/monitoring

Mitigation
• Network segmentation
• Disable unused services (UPnP, Telnet)
• Enforce HTTPS/SSH
• Change all defaults
• Inventory devices
• Monitor unexpected outbound traffic
• Vendor risk management

E. VIRTUALIZATION VULNERABILITIES

VMs introduce unique security risks.

VM Escape (Critical)
Attacker breaks out of guest VM → host → other VMs.

Example: Pwn2Own exploit chain via VMware virtual hardware.

Mitigation:
• Patch hypervisor
• Use Type 1 hypervisor
• Disable unnecessary virtual hardware (USB passthrough)
• Admin role hardening
• Segmentation of tenant networks

Resource Reuse / Data Remanence
Memory/storage remnants leaked between VMs.

Mitigation:
• Disable Transparent Page Sharing (TPS)
• Clear memory on VM shutdown
• Encrypt VM memory/storage

Snapshot Risks
Snapshots contain sensitive data.

Management Plane Attacks
Hypervisor APIs exposed → attacker gains centralized control.

Fix:
• Isolate management networks
• MFA
• Hardened consoles

F. SUPPLY-CHAIN VULNERABILITIES

Supply-chain attacks exploit trusted relationships upstream.

Hardware Supply Chain

Threats:
• Counterfeit devices
• Malicious firmware implants
• Backdoored components
• Intercepted deliveries

Mitigation:
• Authorized vendors only
• Verify authenticity
• Secure procurement
• Firmware integrity checking

Software Supply Chain

Attacker compromises:
• Build servers
• CI/CD pipelines
• Dependency libraries
• Vendor update channels

SolarWinds Orion (2020):
• Malicious code added to official update
• Update was digitally signed
• Distributed to 18,000 customers

Vendor / Third-Party Access

Example: Target 2013 HVAC vendor breach.
Vendor network → pivot into POS network.

Major exam point:
Third-party access must be least-privileged and segmented.

✔️ End of Domain 2 — Part 6

DOMAIN 2 — Threats, Vulnerabilities, Attacks (Part 7 — FINAL)

This chunk covers:
• Hardware/physical attacks
• Environmental attacks (HVAC, power, fire suppression)
• Physical brute force, RFID cloning, badge attacks
• Malware delivery through physical access
• Full consolidated exam cues

This completes Domain 2.
After this, we move into Domain 3 upon your command.
Say “Next chunk.” when ready for Domain 3.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 2 (Part 7 FINAL)
PHYSICAL & ENVIRONMENTAL ATTACKS
A. PHYSICAL ATTACKS

Even the strongest cyber protections fail if the attacker has physical access.
Security+ tests these less frequently than cyber attacks, but they’re core fundamentals.

Physical Brute Force
Attacker uses tools or strength to break:
• Doors
• Windows
• Server cages
• Network closets

Mitigations:
• Reinforced doors/frames
• Window film
• Motion alarms
• CCTV
• Guards

Lock Picking / Bypassing
Breaking into:
• Server rooms
• Network closets
• Data centers

Countermeasures:
• High-security locks
• Tamper-evident seals
• Key control procedures

Tailgating / Piggybacking
Attacker follows authorized user into secure area.

Mitigations:
• Mantraps
• Turnstiles
• Anti-tailgating sensors
• Guards
• Awareness training

RFID Cloning (Badge Duplication)
RFID badges can be cloned with <$50 equipment.
Attackers brush past someone → clone their badge ID.

Mitigations:
• Encrypted RFID
• Rolling code badges
• MFA for physical access
• RFID-blocking sleeves

Locking Down Devices

Techniques:
• Cable locks
• BIOS passwords
• Tamper-proof screws
• Secure racks/cabinets
• Disable unused ports
• USB port blockers

B. ENVIRONMENTAL ATTACKS

Attackers often target support systems rather than the systems themselves.

Power Disruption
Attacker flips breakers or cuts power.

Results:
• Outage
• Data corruption
• Hardware damage

Mitigations:
• UPS
• Generator
• Redundant power feeds

HVAC Manipulation
Hacking building management systems → overheating servers.

Impacts:
• Equipment shutdown
• Potential fire
• Data loss

Mitigations:
• Secure HVAC controls
• Network isolation
• Temperature monitoring

Fire Suppression Abuse
Triggering halon/gas release or sprinklers.

Mitigations:
• Restricted access
• Alarm monitoring
• Cameras

C. PHYSICAL SOCIAL ENGINEERING PATHS

Many attacks combine physical access + impersonation.

Impersonating Delivery / IT Staff
Attacker carries:
• Ladder
• Safety vest
• Clipboard
• Fake badge

Victims assume legitimacy.

Dumpster Diving
Searching trash for:
• Credentials
• Internal documents
• Network diagrams
• Financial records

Mitigation:
• Shred everything
• Locked disposal bins

Shoulder Surfing
Watching someone enter a password or PIN.

Mitigation:
• Privacy filters
• Awareness training

D. DEVICE-LEVEL ATTACKS

Hardware Keyloggers
Physical USB or inline keyboard logger captures keystrokes.

BIOS/UEFI Tampering
Attacker boots from USB to:
• Reset passwords
• Install backdoor
• Modify Secure Boot settings

Mitigation:
• BIOS/UEFI passwords
• Disable external boot devices
• Secure Boot

Physical Malware Delivery
Attacker walks up to machine → plugs in USB → executes payload.

E. PHYSICAL SECURITY DESIGN PRINCIPLES

Defense-in-Depth (Physical)
Layers:
• Perimeter → Building → Floor → Room → Rack → Device

Chokepoints
Force users through controlled entrances.

Isolation Zones
Critical infrastructure separated from public traffic.

Surveillance + Lighting
Lighting enables cameras; cameras enforce deterrence.

F. EXAM-FOCUSED SUMMARY (Domain 2 Consolidation)

Top attack categories:
• Phishing
• Ransomware
• SQLi
• XSS
• ARP poisoning
• DDoS
• Misconfigurations
• Credential harvesting
• Wireless deauth/evil twin
• Zero-days
• Logic bombs
• Supply-chain attacks
• Insider threats

Most common fixes:
• MFA
• Patching
• Segmentation
• Encryption
• Logging/SIEM
• Hardened configs
• Conditional access
• Disable macros
• Cloud access restrictions
• Least privilege
• Behavior-based EDR
• DNSSEC
• Default-deny
