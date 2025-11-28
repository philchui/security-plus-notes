MASTER OUTLINE
DOMAIN 1 — General Security Concepts

1.1 Security Controls (categories + types)
1.2 CIA Triad / Nonrepudiation
1.3 AAA (Identification, AuthN, AuthZ, Accounting)
1.4 Zero Trust / PBAC / PEPPDP
1.5 Physical Security
1.6 Deception & Disruption (honeypots, honeytokens)
1.7 Change Management (CAB, rollback, sandbox)
1.8 PKI, certificates, signatures, hashing
1.9 Encryption (symmetric, asymmetric, key exchange)
1.10 Obfuscation, tokenization, data masking
1.11 Blockchain concepts

DOMAIN 1 — General Security Concepts

1.1 SECURITY CONTROLS — FULL MEMORY FRAMEWORK

A. Security Control Categories (what they ARE)
This is the T-MOP model:

Technical (Logical)
Controls implemented through technology or system configuration.
• Firewalls (ACLs, NGFW)
• IDS/IPS
• Anti-virus / EDR
• Encryption (TLS, AES, disk encryption)
• MFA enforcement
• Logging mechanisms
• Backups (system-level automated backups)
• GPOs / configuration baselines

Managerial (Administrative)
Controls implemented through policies, governance, procedures.
• Security policy
• Acceptable Use Policy (AUP)
• Onboarding/offboarding processes
• Change control
• Standards, guidelines, rules of behavior
• Regulatory compliance (PCI, HIPAA, GDPR)
• Separation of duties

Operational
Controls dependent on people executing processes.
• Security training & awareness
• Incident response runbooks
• Physical guard checks
• Monitoring procedures
• Drills, tabletop exercises
• SOC analyst workflows

Physical
Controls involving physical restriction of access.
• Locks
• Fences
• Gates
• Turnstiles
• Mantraps
• Cameras / CCTV
• Badge readers
• Lighting
• Bollards

B. Security Control Types (what they DO)
This is the P-D-D-C-C-D model:

Preventive — stop an attack
◦ Firewall allow/deny
◦ Locked doors
◦ MFA
◦ Anti-tailgating mantraps
◦ Hardening

Deterrent — discourage attacker
◦ Warning signs
◦ Legal banners
◦ Visible cameras
◦ Guards at the front desk

Detective — discover an event
◦ SIEM alerts
◦ IDS signatures
◦ Log reviews
◦ Motion sensors

Corrective — restore after an event
◦ Backups
◦ System reimage
◦ Fire extinguisher
◦ Incident response steps

Compensating — alternative control when primary isn’t possible
◦ Temporary firewall block until patch is installed
◦ Extra guards
◦ Separation of duties when technical enforcement is unavailable

Directive — instruct expected behavior
◦ Training
◦ SOPs
◦ “Authorized personnel only” signs

Memory Pairing Trick:
Controls are ALWAYS both:
• A category (Technical / Managerial / Operational / Physical)
• A type (Preventive / Detective / Corrective, etc.)

Example:
A login banner = Deterrent–Technical.

1.2 CIA TRIAD + NONREPUDIATION (ULTRA-DENSE)

A. Confidentiality
Keep data private; restrict unauthorized access.

Methods:
• Encryption (AES, TLS)
• Access control lists (ACLs)
• File permissions
• MFA
• Data classification
• Least privilege

Attacks that break confidentiality:
• Sniffing (plaintext protocols)
• MITM
• Credential theft
• Brute force

B. Integrity
Ensure data has not been altered.

Methods:
• Hashing (SHA-256, SHA-3)
• Digital signatures
• Checksums (CRC)
• Version control
• File integrity monitoring (Tripwire, Wazuh)

Integrity failure examples:
• Modified logs
• Tampered config files
• Corrupted updates
• Transaction manipulation

C. Availability
Ensure systems are usable and accessible.

Methods:
• Redundancy (RAID, clustering)
• Load balancing
• Backups + disaster recovery
• Patch & maintenance
• DDoS mitigation

Availability threats:
• DoS/DDoS
• Ransomware
• Power loss
• Hardware failure

D. Nonrepudiation
A sender cannot deny sending information.

Achieved by:
• Digital signatures (private key signs hash)
• PKI (verified trust chain)
• Logged events with validation

Critical roles:
• Integrity + Authentication together enable nonrepudiation.

1.3 AAA — Identification, Authentication, Authorization, Accounting

A. Identification
You claim an identity.

Examples:
• Username
• Email
• Device certificate subject
• Service principal

B. Authentication (AuthN)
You prove who you are.

Factors:

Something you know (password/PIN)

Something you have (token, smartcard)

Something you are (biometrics)

Somewhere you are (geo/IP)

Something you do (behavioral patterns)

Centralized Authentication:
• RADIUS (UDP 1812/1813)
• TACACS+ (TCP 49)
• LDAP/Active Directory
• SAML / OAuth / OIDC (modern SSO)

Device Authentication:
• Certificates (X.509)
• EAP-TLS
• 802.1X

C. Authorization (AuthZ)
What you are allowed to do.

Models:
• RBAC — Role-based (department/role)
• ABAC — Attribute-based (user, device, context, time)
• Rule-based — If/then logic
• DAC — Owner decides permissions
• MAC — Labels + clearance levels

Key principles:
• Least privilege
• Separation of Duties (SoD)
• Privileged Access Management (PAM)

D. Accounting (Auditing & Logging)
Track who did what, when, from where.

Examples:
• VPN session start/stop
• Firewall logs
• RADIUS accounting records
• SIEM event correlation

✔️ End of Chunk 1

DOMAIN 1 — General Security Concepts (Part 2)

Covering 1.4 Zero Trust through 1.6 Deception / Honeypots.
When you're ready, tell me “Next chunk.”

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 1 (Part 2)
1.4 ZERO TRUST ARCHITECTURE (ZTA)

Zero Trust = “Never trust, always verify” — applies to users, devices, apps, processes, network flows.

A. ZTA Core Principles

Never trust, always verify
Every access request must be authenticated and authorized.

Least privilege everywhere
Users and devices get the minimum required access.

Assume breach
Design systems as if attackers are already inside.

Micro-segmentation
Break networks into granular zones; limit lateral movement.

Continuous verification
Evaluate identity, device posture, context every time a request is made.

Encrypt everything
Data in transit + at rest; strong mutual TLS where possible.

B. Functional Planes
You must memorize these — they show up in architecture questions.

Data Plane
Moves packets (switching/routing, NAT, QoS).
• Fast path
• “What happens to the packet right now?”

Control Plane
Decides policy and logic (routing tables, ACL updates).
• Slower path
• Centralized control logic
• SDN controllers, firewall rules, access policies

C. Context-Based Access (Adaptive Identity)
Access decisions consider:
• Location/IP
• Device health & certificate
• Time of day
• User role
• Behavioral baseline
• Risk score
• Relationship to org (employee, contractor, vendor)

High-risk → require more MFA
Low-risk → frictionless allow
Suspicious → deny or isolate

D. Zero Trust Enforcement Components (PBAC Framework)

PEP — Policy Enforcement Point
• The gatekeeper
• Firewalls, proxies, gateways, ZTNA agents
• Enforces allow/deny decisions

PDP — Policy Decision Point
• Evaluates policies and context
• Identity provider + access engine
• Makes final yes/no decisions

PA — Policy Administrator
• Communicates PDP decisions to PEP
• Issues session tokens or credentials

Policy Engine
• Logic core
• Risk scoring, continuous evaluation
• Uses policies, identity attributes, device posture

This is foundational for Zero Trust exam items.

E. Micro-Segmentation & Security Zones

Zones define trust levels:

Untrusted Zone
Internet, guest Wi-Fi

DMZ
Public-facing services (web, mail)

Trusted Internal Zone
Corporate LAN

Restricted / Sensitive Zone
Databases, payment systems, HR data

Rules:
• Untrusted → Trusted = deny by default
• Lateral movement between sensitive zones should be restricted
• User access should be specific to need

F. Technologies Supporting Zero Trust
• MFA
• TLS/IPsec
• Device certificates
• EDR + posture validation
• NAC (802.1X)
• Micro-segmentation (VLANs, SDN)
• SIEM + UEBA
• Conditional access (Okta, Azure AD)
• Cloud access proxies (CASB)

1.5 PHYSICAL SECURITY — ULTRA-DENSE MEMORY MAP

A. Barriers

Barricades / Bollards
Prevent vehicles from approaching building entrances.
Key term: stand-off distance.

Fences
• Anti-climb
• Height matters
• Razor wire
• Transparent (surveillance) vs. opaque (privacy)

Natural Barriers
Rivers, elevation, landscaping to funnel access through checkpoints.

B. Controlled Entry

Mantraps (Access Control Vestibules)
• Interlocked doors
• Only one door opens at a time
• Strong anti-tailgating control
• Used in datacenters, secure facilities

Modes include:
• Both doors locked, one unlocks at a time
• One always locked
• Multi-factor at each door

C. Monitoring

CCTV
• Motion detection
• ALPR
• Facial recognition
• Must pair with lighting
• Store logs securely

Guards
• Validation of ID
• Patrol zones
• Escort visitors
• Two-person control / integrity

Badges
• Visible identification
• Access-card with logs
• “Something you have”

D. Detection

Sensors
• Infrared (motion, body heat)
• Microwave (radar penetration)
• Ultrasonic
• Pressure sensors (floor mats)

E. Exam Mapping Table (For Instant Recall)

Control	Type	Category
Bollards	Preventive / Deterrent	Physical
Fences	Preventive / Deterrent	Physical
Mantrap	Preventive	Physical
CCTV	Detective / Deterrent	Technical + Physical
Guards	Preventive / Detective / Corrective	Operational
Badges	Preventive / Detective	Physical/Technical
Lighting	Deterrent / Preventive	Physical
IR/Microwave sensors	Detective	Physical/Technical
1.6 DECEPTION & DISRUPTION (HONEYPOTS, HONEYNETS, HONEYTOKENS)

A. Honeypot
Decoy system designed to:
• Lure attackers
• Observe behavior
• Waste attacker time
• Gather IoCs
• Divert attack away from production

Types:
• Low-interaction: simple emulation
• High-interaction: full OS

Characteristics:
• Isolated
• Controlled
• Fully monitored

B. Honeynet
Multiple honeypots forming a fake network:
• Mimics enterprise topology
• Used for deeper attacker research
• Captures lateral movement patterns

C. Honeyfile
Fake document intentionally placed on shares:
• “passwords.xlsx”, “salaries.docx”
• Access triggers alert
• Detects insider threats or compromised accounts

D. Honeytoken
Fake data objects:
• Bogus API keys
• Fake customer records
• Unique tracking email addresses

Purpose:
• Detect when data is accessed or exfiltrated
• Trace leaks even outside your network

E. Why Deception Helps
• Produces threat intelligence
• Creates early warnings
• Distracts attackers
• Provides attribution clues
• Helps tune detection rules

✔️ End of Chunk 2

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 1 (Part 3)
1.7 CHANGE MANAGEMENT (ULTRA-DENSE)

Change Management = formal, documented process to modify systems safely.

A. Purpose
• Maintain stability
• Reduce outages
• Avoid configuration drift
• Ensure testing + rollback
• Meet compliance (ISO 27001, NIST 800-53, PCI-DSS)
• Prevent unauthorized/untracked changes

B. Core Benefits

Stability — avoid breaking production

Accountability — who changed what, when, why

Communication — notify all impacted teams

Compliance — required by industry frameworks

Recovery Assurance — rollback validated

C. Change Control Process (Exam MUST-MEMORIZE)

Change Request (CR)
Document includes:
• Reason for change
• Scope
• Risk analysis
• Systems impacted
• Rollback plan
• Schedule

CAB Review (Change Advisory Board)
• Approves, rejects, or reschedules request
• Ensures no conflicts across org
• Reviews impact

Testing (Sandbox/Staging)
• Isolated environment
• Validate update compatibility
• Test rollback procedures
• Avoid outage in prod

Implementation
• During maintenance window
• Follow runbook
• Communicate real-time updates
• Possibly phased rollout (pilot → full)

Validation
• Confirm success with system owners
• Check logs and functionality
• Monitor performance

Documentation
• Update change logs
• Update configuration baselines
• Capture lessons learned

D. Key Concepts

Rollback Plan
Always required — revert system to known-good state if change fails.

Sandbox Testing
Mirror of production → test without impact.

Change Freeze
Period where changes are prohibited (holidays, major launch).

Maintenance Window
Defined time with minimal business impact (e.g., 2AM–4AM).

Scope Creep
Implementers cannot add “extra quick tweaks” outside approved scope.

E. Technician-Focused Change Rules
• Follow runbook exactly
• Pre-check dependencies
• Take snapshots/backups
• Validate after completion
• Notify stakeholders immediately

1.8 PUBLIC KEY INFRASTRUCTURE (PKI) — ULTRA-DENSE

PKI = framework enabling identity, trust, encryption, and digital signatures.

A. Cryptographic Foundation

Symmetric Encryption
• One key for both encryption & decryption
• Fast
• Poor scalability
• Used for: bulk data, TLS session keys, disk encryption

Asymmetric Encryption
• Key pair: public + private
• Slow
• Solves key distribution
• Enables: digital signatures, certificate-based identity

Algorithms:
• RSA
• ECC
• Diffie-Hellman (key exchange)
• ECDH

B. Certificates

Contain:
• Public key
• Subject (identity)
• Issuer
• Validity period
• Extensions (SAN, CRL distribution point)
• Digital signature from CA

X.509 Standard
Universal certificate format.

C. Certificate Authorities (CAs)

Root CA
• Highest trust
• Secure, offline whenever possible

Intermediate CA
• Issues end-entity certificates
• Signed by root

End-Entity Certificate
• Server, device, user certificate

Chain of trust:
Root → Intermediate → End-entity

D. Key Lifecycle

Generate keypair

Create CSR (Certificate Signing Request)

Submit to CA

CA validates identity

CA signs certificate

Deploy certificate

Renewal

Revocation (CRL, OCSP)

E. Revocation

CRL — Certificate Revocation List
• Downloaded periodically
• Inefficient

OCSP — Online Certificate Status Protocol
• Real-time status check

OCSP Stapling
• Server sends signed OCSP response during TLS handshake
• Improves speed and privacy

F. PKI Components
• CA — issues certs
• RA — verifies identity
• CRL/OCSP — revocation
• Repository — stores certificates
• Certificate policy — rules
• Key escrow — stores private keys (controversial)
• Key recovery agent — retrieves escrowed keys

G. Private Key Security
• Store in TPM, HSM, or secure enclave
• Protected by passphrases
• Never leave device unencrypted
• Loss compromises all encrypted data

1.9 ENCRYPTION & KEY EXCHANGE — ULTRA-DENSE

A. Data States

Data at Rest
◦ BitLocker, FileVault, EFS
◦ Full disk or file-level

Data in Transit
◦ HTTPS/TLS, IPsec, VPNs

Data in Use
◦ Process memory
◦ Secure enclaves

B. Encryption Algorithms

AES
• Symmetric
• 128/192/256-bit
• Standard for modern cryptography

DES
• Obsolete
• Too small key space

3DES
• Also deprecated

RSA
• Asymmetric
• Key exchange + signatures

ECC
• Same security with smaller keys

C. Key Exchange Models

Out-of-Band
• Key delivered separately
• Secure but manual
• Not scalable

In-Band (Protected by Asymmetric Crypto)
• Client generates symmetric session key
• Encrypts with server’s public key
• Server decrypts with private key
• This establishes session keys for TLS

Diffie–Hellman / ECDH
• Both parties compute shared key
• Key is never transmitted
• Resistant to passive sniffing

D. Brute Force Resistance
Larger keys = exponential difficulty
• Symmetric: ≥128 bits
• Asymmetric: ≥3072 bits (RSA)

E. Algorithm Transparency
The algorithm is public — only the key must remain secret.

F. Encryption in Databases

TDE (Transparent Data Encryption)
Full database encryption with symmetric key.

Column-Level Encryption
Encrypt only sensitive fields.

✔️ End of Chunk 3

DOMAIN 1 — General Security Concepts (Part 4)

Covering 1.10 Obfuscation / Steganography / Tokenization / Masking
and 1.11 Blockchain Concepts.
When you're ready for more, say “Next chunk.”

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 1 (Part 4)
1.10 OBFUSCATION, STEGANOGRAPHY, TOKENIZATION, DATA MASKING

These four appear together in exam questions.
You must know the differences cold, because Security+ often tests them in comparison.

A. Obfuscation
Make something harder to understand, but not encrypted.

Purpose
• Hide logic
• Hide sensitive string values
• Protect IP (source code)
• Delay reverse engineers
• Hide malware intent

Characteristics
• Reversible if method is known
• Not cryptographically secure
• Not “true” protection

Examples
• Complex variable/function renaming
• Packing executable code
• JavaScript obfuscators
• Malware hiding commands in convoluted code paths

B. Steganography
Hide data inside another file so the existence is hidden.

Terminology
• Cover object — file that carries hidden data (image, audio, video)
• Payload — hidden content
• Carrier medium — where bits are embedded

Types
• Image-based LSB (Least Significant Bit)
• Network steganography (data in unused protocol fields)
• Audio steganography
• Printed steganography (yellow dots in laser printers)

Security Notes
• Provides obscurity, not cryptographic privacy
• Best used with encryption

C. Tokenization
Replace sensitive data with a meaningless token that maps to real value in secure vault.

Key points
• Token has no mathematical relation to original
• Only tokenization server can map token → real data
• Used heavily in financial transactions (PCI)
• Prevents theft of actual PII/credit card numbers

Example
Credit card number stored as:

Actual: 4111 1111 1111 1111
Token: 91f3d7b2-bc29-44e7-a310-8a3e93fcf21e

Properties
• Reversible only via token vault
• Protects against database compromise
• Common in mobile payments (Apple Pay, Google Pay)

D. Data Masking
Hide part of the data for display, while original remains intact.

Examples
• Credit card on receipt: **** **** **** 2512
• Phone number (XXX) XXX–7814
• Email j***@gmail.com

Purpose
• Reduce accidental exposure
• Allow utility while maintaining privacy
• Common in customer service, logs, testing data

Techniques
• Asterisk masking
• Truncation
• Shuffling
• Substitution

Difference from Tokenization
• Masking = visual obfuscation
• Tokenization = substitute entire value with a vault-mapped token

1.11 BLOCKCHAIN TECHNOLOGY (ULTRA-DENSE)

Know only the Security+ relevant concepts — not cryptocurrency mechanics.

A. What Blockchain Is
• Distributed ledger
• Immutable chain of blocks
• Every block hashed
• Each block contains hash of previous
• Tamper-evident
• Distributed copies maintained across nodes
• Consensus required to add/edit

B. Key Characteristics (Exam-Focused)

Distributed
No central authority; all participants maintain copies.

Immutable
Changes break hash chain → rejected by nodes.

Transparent
All participants can verify (depends on blockchain type).

Cryptographically Linked
Hash of previous block ensures chain integrity.

Consensus
Nodes agree on validity (Proof of Work, Proof of Stake, etc.)

C. Security Purposes
Blockchain is used beyond cryptocurrency:
• Data integrity
• Anti-tampering
• Supply chain authenticity
• Timestamp verification
• Identity verification
• Distributed auditing
• Tracking records securely

D. Block Structure (Exam Concept)
Each block contains:
• Transactions/data
• Hash of previous block
• Own hash
• Nonce (in PoW systems)

Changing any transaction → changes block hash → breaks entire chain → detected instantly.

E. Where Blockchain Helps Security
• Prevent unauthorized modification of logs
• Enhance integrity of backups
• Validate authenticity of firmware or supply chain components
• Provide immutable audit trails

F. Exam Pointers
• Blockchain ≠ encryption mechanism
• Blockchain ensures integrity, not confidentiality
• Focus on hashing, distribution, immutability, consensus
• Perfect topic for questions about tamper-evident logging
