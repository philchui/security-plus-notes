DOMAIN 3 — Security Architecture (Part 1)
This chunk covers:
	•	Enterprise & network architecture fundamentals
	•	Zones, segmentation, micro-segmentation
	•	Data plane vs control plane
	•	Secure design principles (the foundation of architecture questions)
Say “Next chunk.” when ready for Part 2.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 3 (Part 1)
SECURITY ARCHITECTURE & DESIGN PRINCIPLES
Domain 3 is where Security+ starts testing how everything fits together — not individual attacks, but system-level design.

A. ENTERPRISE ARCHITECTURE — CORE CONCEPTS
Security architecture = how the organization structures networks, identities, systems, controls, and data to achieve CIA.

1. Security Zones (Trust Boundaries)
Zones segment networks by trust level:
a. Untrusted Zone
	•	The public internet
	•	Guest Wi-Fi
	•	External-facing resources
b. DMZ (Demilitarized Zone)
	•	Exposed services
	•	Web servers, email gateways, reverse proxies
	•	Strict inbound/outbound rules
	•	Acts as a buffer area
c. Trusted Internal Zone
	•	Corporate LAN
	•	Workstations, user subnets
	•	More permissive but still controlled
d. Restricted / High-Security Zone
	•	Database servers
	•	Payment systems (PCI)
	•	HR data
	•	Highly sensitive workloads
Rules of zones:
	•	Traffic from less trusted → more trusted must be filtered
	•	There is no such thing as “trusted by default”
	•	Inter-zone traffic requires firewalls/ACLs/WAFs

2. Segmentation (Network Compartmentalization)
Segmentation is mandatory in modern security.
a. VLAN Segmentation
	•	Logical segmentation
	•	Separates broadcast domains
	•	Departments, server tiers, IoT devices
b. Subnet-Based Segmentation
	•	Different subnets for security tiers
	•	Helps isolate sensitive systems
c. Firewall Segmentation
	•	Most powerful
	•	Enforces security policies between network segments
d. Micro-Segmentation (Zero Trust)
	•	Fine-grained segmentation at workload level
	•	Often implemented via SDN or host-based firewalls
	•	Example: DB server only accepts connections from application servers — not entire VLAN
Benefits:
	•	Stops lateral movement
	•	Reduces attack blast radius
	•	Improves visibility (per-segment logging)

3. Data Plane vs Control Plane (Architecture MUST-KNOW)
Exam scenario example: “Traffic is flowing normally, but routing tables are incorrect.” → Control-plane issue.
a. Data Plane (Forwarding Plane)
Handles real-time packet processing:
	•	Routing
	•	Switching
	•	NAT
	•	QoS
	•	Firewall rule enforcement
Key phrase: “Moves packets.”
b. Control Plane
Handles administrative and decision logic:
	•	Routing table computation
	•	Firewall rule updates
	•	SDN controller logic
	•	Network topology
	•	Policy management
Key phrase: “Decides how packets SHOULD move.”
Why this matters:
	•	Data-plane attacks: floods, DoS, malformed frames
	•	Control-plane attacks: BGP hijacking, route poisoning, management compromise

4. Secure Network Architecture Models
a. Three-Tier Architecture (Classic)
	1	Presentation tier (web front-end)
	2	Application tier (app logic, APIs)
	3	Database tier (data storage)
Traffic should flow in only one direction at each tier step.
b. Hub-and-Spoke Architecture
Central hub → multiple branch sites Used for VPN concentrators.
c. Full Mesh
Every node communicates with every other Expensive, highest resilience.

B. SECURE DESIGN PRINCIPLES (MANDATORY EXAM CONTENT)
These appear in architecture, operations, AND cloud questions.

1. Least Privilege
Only the minimal access needed.
Applies to:
	•	Users
	•	Applications
	•	System processes
	•	API tokens
	•	Service accounts
	•	Network flows

2. Separation of Duties (SoD)
Tasks that can cause harm must be split across roles.
Examples:
	•	Person approving wire transfer ≠ person requesting
	•	Admin who provisions accounts ≠ admin who audits permissions
	•	Developer ≠ deployment approver

3. Defense-in-Depth
Multiple independent layers of defense. If one fails → others protect.
Example layers:
	•	MFA
	•	Firewall
	•	EDR
	•	Logging/SIEM
	•	Backups
	•	Network segmentation

4. Redundancy & High Availability
Redundancy targets Availability.
Forms:
	•	RAID
	•	Clustering
	•	Load balancing
	•	Multiple ISPs
	•	Geographic failover
	•	Hot/warm/cold sites

5. Elasticity & Scalability
Elasticity = automatic scaling Scalability = ability to grow (manual or automatic)
Cloud question keywords:
	•	Auto-scaling
	•	On-demand provisioning
	•	Pay-as-you-grow

6. Resiliency
Ability to recover gracefully:
	•	Fault tolerance
	•	Graceful degradation
	•	Self-healing systems
	•	Multi-AZ cloud deployments

7. Secure Defaults / Fail-Secure
Fail-open = insecure (bad) Fail-closed = secure (preferred)
Example exam prompt: “Firewall stops working and now all traffic is allowed.” → Fail-open (bad).

8. Secure-by-Design / Secure-by-Default
Systems built with:
	•	Minimal services
	•	Hardened configs
	•	No default passwords
	•	Secure configuration templates

✔️ End of Domain 3 — Part 1
———————
DOMAIN 3 — Security Architecture (Part 2)
Covering:
	•	Secure network design and architecture components
	•	NAC (Network Access Control) & 802.1X
	•	Jump servers / Bastion hosts
	•	Load balancers
	•	Proxies / Reverse proxies / WAF
	•	VPN concentrators
	•	Honeynets (architectural role)
	•	Cloud shared responsibility
Say “Next chunk.” when ready for Part 3.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 3 (Part 2)
NETWORK SECURITY ARCHITECTURE COMPONENTS
This section is the backbone of architecture questions. Expect many scenario questions like:
“Traffic flows normally but cannot reach internal resources.” “Users can authenticate but cannot access internal apps.” “Public traffic stops at reverse proxy but cannot reach backend.”
These all relate to the components below.

A. NETWORK ACCESS CONTROL (NAC)
NAC determines whether a device is allowed onto the network.
Two models: pre-admission and post-admission.

1. 802.1X (MOST IMPORTANT NAC TOPIC)
Port-based NAC. Used for:
	•	Corporate Wi-Fi
	•	Wired Ethernet ports
	•	VPNs
Components:
	•	Supplicant — the device (laptop/phone)
	•	Authenticator — the switch/AP
	•	Authentication Server — RADIUS server
Common Auth Methods:
	•	EAP-TLS (certificate-based, strongest)
	•	PEAP/MSCHAPv2 (username/password)
Actions:
If device fails posture check:
	•	Placed in quarantine VLAN
	•	Denied access
	•	Given limited remediation network

2. Posture Assessment
Checks:
	•	OS version
	•	Patch level
	•	Anti-malware running
	•	Disk encryption
	•	Firewall enabled
If fail → quarantine.

3. Enforcement
	•	VLAN assignment
	•	ACL application
	•	Isolation
Exam phrases:
	•	“Certificate-based Wi-Fi” → EAP-TLS
	•	“Machine authentication” → device certificates
	•	“Port-based authentication” → 802.1X

B. JUMP SERVERS / BASTION HOSTS
A dedicated hardened system used as a secure entry point for admin access.
Characteristics:
	•	Single-controlled choke point
	•	All admin access must pass through it
	•	Usually placed in DMZ or management network
	•	Enforces MFA + logging
	•	No direct RDP/SSH to servers
Exam usage:
If question says:
“Limit admin access to internal servers, require monitoring.” Answer: Use a jump server/bastion host.

C. LOAD BALANCERS
Distribute traffic across multiple servers.

1. Types
	•	Layer 4 (TCP/UDP) — faster, simpler
	•	Layer 7 (HTTP) — can inspect content

2. Load-Balancing Methods
	•	Round robin
	•	Least connections
	•	Weighted distribution
	•	Source IP hash

3. Load Balancer Benefits
	•	Scalability
	•	Availability via failover
	•	Can terminate TLS (SSL offloading)
	•	Health checks for backend servers
Exam cues:
“Distribute traffic evenly.” “Reduce load on servers.” “Increase fault tolerance.”
→ answer: load balancer.

D. PROXIES & REVERSE PROXIES — ULTRA IMPORTANT
1. Forward Proxy
Client → Proxy → Internet Used for:
	•	Filtering content
	•	Caching
	•	Logging outbound traffic
	•	Anonymization

2. Reverse Proxy
External traffic → Reverse Proxy → Internal servers Used for:
	•	Protect internal server identities
	•	SSL termination
	•	Load balancing
	•	WAF integration
Exam clue:
“Only expose one IP to the internet while hiding internal servers.” → Reverse proxy.

E. WEB APPLICATION FIREWALL (WAF)
Protects web applications at Layer 7. Detects:
	•	SQLi
	•	XSS
	•	Command injection
	•	Path traversal
	•	API abuse
WAF sits:
	•	On reverse proxy
	•	On load balancer
	•	As cloud service (Cloudflare, AWS WAF)

F. VPN CONCENTRATORS
Dedicated device or service for secure remote access.
Technologies:
	•	SSL/TLS VPN
	•	IPsec VPN
	•	Always-on VPN (machine-level)
Exam clues:
	•	“Remote users authenticate to centralized device.”
	•	“Encrypted tunnel for remote office.”
→ VPN concentrator.

G. HONEYPOTS & HONEYNETS AS ARCHITECTURE ELEMENTS
Beyond Domain 1: In architecture, honeypots are used to segment attacker activity.
Uses:
	•	Place in isolated “research network”
	•	Observe attacker behavior
	•	Detect lateral movement
	•	Trigger SIEM alerts
HoneyNets mimic full enterprise layout:
	•	Fake AD
	•	Fake databases
	•	Fake servers

H. CLOUD ARCHITECTURE (SHARED RESPONSIBILITY MODEL)
Extremely exam-heavy. Must know exactly who is responsible for what.

1. SaaS (Software as a Service)
Provider responsible for:
	•	Application
	•	OS
	•	Infrastructure Customer responsible for:
	•	Data
	•	Account/access management
	•	User configuration

2. PaaS (Platform as a Service)
Provider:
	•	Infrastructure
	•	OS
	•	Runtime
Customer:
	•	Applications
	•	Data
	•	Accounts

3. IaaS (Infrastructure as a Service)
Provider:
	•	Hardware
	•	Hypervisor
Customer:
	•	OS
	•	Applications
	•	Configs
	•	Data
	•	Network controls
	•	Access controls

4. Customer Must ALWAYS Manage:
	•	IAM
	•	MFA
	•	Data encryption choices
	•	Logging
	•	Monitoring
	•	Compliance

I. CLOUD ARCHITECTURE DESIGN ELEMENTS
1. CASB (Cloud Access Security Broker)
Provides:
	•	Shadow IT detection
	•	Access control
	•	Data loss prevention
	•	API inspection
	•	Compliance enforcement

2. CSPM (Cloud Security Posture Management)
Scans for:
	•	Public buckets
	•	Weak IAM roles
	•	Exposed services
	•	Unencrypted storage
	•	Misconfigurations

3. Micro-Segmentation in Cloud
Traffic between:
	•	App tier
	•	DB tier
	•	Admin network Must be restricted via:
	•	SGs (Security Groups)
	•	NACLs
	•	Host-based firewalls

✔️ End of Domain 3 — Part 2
————
DOMAIN 3 — Security Architecture (Part 3)
Covering:
	•	Secure system design
	•	Resilience / redundancy / clustering / failover
	•	Network appliances & controls (firewalls, IPS/IDS, DLP, HSM, TPM, secure enclave)
	•	Email security architecture
	•	Logging architecture (SIEM, SOAR, UEBA)
	•	Configuration baselines & hardening principles
When you're ready, say “Next chunk.” for Part 4.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 3 (Part 3)
SECURE DESIGN, RESILIENCY, HARDENING & CORE SECURITY APPLIANCES
This section provides architecture-level comprehension required in scenario questions.

A. SYSTEM RESILIENCY & AVAILABILITY DESIGN
1. Redundancy
Duplicate critical components:
	•	Multiple power supplies
	•	Multiple NICs
	•	RAID arrays
	•	Dual routers/firewalls
2. High Availability (HA)
Systems designed for minimal downtime:
	•	Active/active clusters
	•	Active/passive clusters
	•	Automatic failover
Keywords:
	•	“No single point of failure”
	•	“Failover cluster”
	•	“Primary/secondary node”

3. Load Balancing (Scalability + Availability)
Already covered, but key principles:
	•	Distribute load
	•	Health checks
	•	Session persistence (“sticky sessions”)
	•	SSL offloading

4. Fault Tolerance
Systems continue running despite failures:
	•	RAID-1/5/6/10
	•	ECC RAM
	•	Redundant networking

5. Replication
Data duplicated across:
	•	Data centers
	•	Cloud regions
	•	Clusters
Forms:
	•	Asynchronous
	•	Synchronous
	•	Multi-master

6. Disaster Recovery (DR) Architectures
Hot Site
	•	Fully equipped
	•	Near-instant failover
	•	Most expensive
Warm Site
	•	Partially equipped
	•	Shorter RTO/RPO
Cold Site
	•	Physical space only
	•	Long recovery time

B. FIREWALLS & PERIMETER SECURITY ARCHITECTURE
Understanding firewall types is a must.

1. Packet-Filtering Firewall (Layer 3/4)
Simple:
	•	Source/dest IP
	•	Source/dest port
	•	Protocol (TCP/UDP)

2. Stateful Firewall
Tracks connection state:
	•	SYN, SYN-ACK
	•	Established sessions Allows dynamic filtering.

3. Next-Gen Firewall (NGFW)
Adds:
	•	Application-layer filtering
	•	Identity awareness
	•	Intrusion detection/blocking
	•	URL filtering
Keywords:
	•	Layer 7 firewall
	•	Deep packet inspection (DPI)

4. Web Application Firewall (WAF)
Protects against:
	•	SQLi
	•	XSS
	•	Command injection
	•	Path traversal

5. Firewall Architectures
	•	Inline
	•	Tap/span
	•	Proxy-based
	•	Distributed firewalling (cloud SGs, host-based)

C. IDS / IPS ARCHITECTURE
1. IDS (Intrusion Detection System)
Monitors traffic → alerts.
Types:
	•	NIDS (network-based)
	•	HIDS (host-based)
Methods:
	•	Signature-based
	•	Anomaly-based
	•	Behavior-based

2. IPS (Intrusion Prevention System)
Inline, can block attacks.
Important concept: IPS must be positioned inline → can introduce latency → requires fail-open/fail-closed decisions.

D. DLP (DATA LOSS PREVENTION) ARCHITECTURE
Prevents leakage of sensitive data.
1. Network DLP
Monitors outbound:
	•	Email
	•	Web traffic
	•	FTP
	•	Cloud access
2. Endpoint DLP
Monitors:
	•	USB transfers
	•	Copy/paste
	•	Printing
	•	Local file access
3. Cloud DLP
Monitors:
	•	SaaS apps
	•	Cloud storage (S3, Drive, OneDrive)
Keywords:
	•	“Prevent sensitive data exfiltration”
	•	“Block PII from leaving network”

E. SECURE CRYPTOGRAPHIC HARDWARE
1. HSM (Hardware Security Module)
Used for:
	•	High-volume crypto operations
	•	TLS certificate private keys
	•	Code-signing keys
	•	Central enterprise key storage
Features:
	•	Tamper-resistant
	•	Often clustered
	•	Stores private keys securely
	•	Cannot export private keys
Exam clue:
“Store SSL private keys securely for thousands of servers.”
→ HSM.

2. TPM (Trusted Platform Module)
Local device chip:
	•	Stores keys
	•	Enforces BitLocker
	•	Supports Secure Boot
	•	Device identity
Difference vs HSM:
	•	TPM = per-device
	•	HSM = enterprise-wide

3. Secure Enclave
Separate coprocessor:
	•	True RNG
	•	Hardware-isolated
	•	Protects sensitive operations
Examples:
	•	Apple Secure Enclave
	•	Intel SGX
	•	ARM TrustZone

F. EMAIL SECURITY ARCHITECTURE
1. Secure Email Gateway (SEG)
Protects inbound email:
	•	Spam
	•	Phishing
	•	Malicious attachments
	•	URL rewriting
	•	Sandboxing

2. SPF (Sender Policy Framework)
Validates sending IP.
3. DKIM (DomainKeys Identified Mail)
Validates message integrity using digital signature.
4. DMARC
Enforces policies for SPF + DKIM failures.
This trio is extremely testable.

G. LOGGING, MONITORING & ANALYTICS ARCHITECTURE
1. SIEM (Security Information and Event Management)
Centralized log aggregation + correlation.
Provides:
	•	Alerts
	•	Dashboards
	•	Threat detection
	•	Compliance reporting

2. UEBA (User and Entity Behavior Analytics)
Machine learning to detect anomalies:
	•	Impossible travel
	•	Unusual login times
	•	Privilege misuse

3. SOAR (Security Orchestration, Automation, Response)
Automates:
	•	Ticket creation
	•	Blocking IPs
	•	Quarantining endpoints
	•	Playbook execution
Exam trigger words:
	•	“Automated incident response”
	•	“Runbooks”
	•	“Playbook automation”

H. SYSTEM HARDENING & CONFIG BASELINES
1. Hardening
Reducing attack surface by:
	•	Disabling unused services
	•	Disabling default accounts
	•	Applying latest patches
	•	Using strong configurations
	•	Enforcing MFA
	•	Removing bloatware
	•	Enabling firewalls

2. Configuration Baselines
Standard secure configuration templates:
	•	CIS Benchmarks
	•	STIGs (DoD)
	•	Golden images
Used for:
	•	Servers
	•	Endpoints
	•	Cloud workloads
	•	Containers

3. Secure OS / Server Deployment Steps
	•	Patch
	•	Harden
	•	Remove defaults
	•	Disable unnecessary ports/services
	•	Install monitoring agents
	•	Enforce encryption policies
	•	Apply baseline

✔️ End of Domain 3 — Part 3
—————————————————
DOMAIN 3 — Security Architecture (Part 4 — FINAL)
Covering:
	•	Secure data architecture (classification, retention, destruction)
	•	Application architecture security
	•	Containerization & virtualization inside architecture
	•	Edge, fog, and zero-trust network design
	•	Infrastructure as Code (IaC) & secure automation principles
	•	Consolidated Domain 3 architecture cues
After this, Domain 3 will be complete.
When you're ready for Domain 4, say “Next chunk.”

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 3 (Part 4 FINAL)
ADVANCED ENTERPRISE ARCHITECTURE + SECURE DESIGN PATTERNS

A. SECURE DATA ARCHITECTURE
Data security architecture defines how data is classified, stored, encrypted, transmitted, retained, destroyed.

1. Data Classification
Labels assigned based on sensitivity.
Typical tiers:
	•	Public
	•	Internal
	•	Confidential
	•	Restricted / Highly Confidential
	•	Regulated (PCI, PHI, PII)
Classification informs:
	•	Access control
	•	Retention policies
	•	Encryption requirements
	•	Backup rules

2. Data Lifecycle
Security+ tests this more than people realize.
	1	Create
	2	Store
	3	Use
	4	Share
	5	Archive
	6	Destroy
Each stage requires different controls.

3. Data Retention Policies
Ensure data is kept:
	•	As long as required
	•	No longer than necessary
Compliance examples:
	•	HIPAA
	•	GDPR “right to be forgotten”
	•	PCI DSS (don’t store CVV)

4. Data Sovereignty
Data must stay within geographic/legal borders.
Exam clue:
“Data cannot leave the EU.”

5. Data Loss Prevention (DLP) Integration
DLP applies controls based on classification:
	•	Block PII uploads
	•	Prevent email exfiltration
	•	Restrict USB data copies

6. Secure Destruction
	•	Shredding
	•	Degaussing
	•	Cryptographic erasure (destroy encryption key)

B. APPLICATION ARCHITECTURE SECURITY
Security must be baked into app architecture, not slapped on after.

1. Application Sandboxing
Container or VM isolation to protect system from:
	•	Malicious code
	•	Exploits
	•	Browser attacks
Examples:
	•	Docker containers
	•	Browser sandbox
	•	VM-based isolation

2. Secure Coding Architecture
Security must be considered in:
	•	Input validation
	•	Output encoding
	•	Strong authentication
	•	Role-based access (RBAC)
	•	Dependency management
	•	API rate limiting

3. API Security Architecture
Threats:
	•	API key leakage
	•	Insecure direct object references (IDOR)
	•	Overly permissive endpoints
	•	Missing rate limits
Mitigations:
	•	OAuth 2.0
	•	API gateways
	•	WAF rules
	•	Schema validation
	•	TLS everywhere

4. Web Application Architecture
Layers:
	•	Client
	•	Web server
	•	Application server
	•	Database server
Security:
	•	WAF
	•	Input sanitization
	•	Parameterized queries
	•	Strict session handling
	•	Certificate pinning

5. Secure Session Management
Prevent:
	•	Session fixation
	•	Session hijacking
	•	Token reuse
Controls:
	•	Random session IDs
	•	HttpOnly cookies
	•	Secure flag
	•	Short TTL
	•	Regenerate tokens after login

C. CONTAINER & ORCHESTRATION ARCHITECTURE (Docker / Kubernetes)
Frequently appears in Security+ v3 exam revisions.

1. Container Benefits
	•	Isolation
	•	Consistency
	•	Scalability
	•	Lightweight virtualization

2. Container Security Needs
	•	Signed images
	•	Private registries
	•	No root containers
	•	Minimal base images
	•	Secrets management
	•	RBAC in orchestrator

3. Kubernetes Security Concepts
	•	RBAC
	•	Secrets
	•	Pod security policies
	•	Network policies
	•	Admission controllers
	•	Service mesh (mTLS)

D. EDGE, FOG, AND CLOUD ARCHITECTURE

1. Edge Computing
Processing occurs at the device or near-device (IoT, gateways).
Pros:
	•	Low latency
	•	Decentralized
Security challenges:
	•	Physical tampering
	•	Weak authentication
	•	Limited patching

2. Fog Computing
Intermediate layer between cloud and edge.
Used for:
	•	Aggregation
	•	Filtering
	•	Pre-processing

3. Cloud Architecture Recap
Cloud = distributed systems with:
	•	Multi-tenancy
	•	Shared responsibility
	•	Segmented security groups
	•	Federated identity
	•	Elasticity

E. INFRASTRUCTURE AS CODE (IaC) & AUTOMATION SECURITY
Tools: Terraform, Ansible, CloudFormation.

1. IaC Benefits
	•	Repeatability
	•	Consistency
	•	Automated hardening
	•	No human misconfigurations
	•	Version control for infrastructure

2. IaC Security Concerns
	•	Credential storage in scripts
	•	Template vulnerabilities
	•	Secrets in Git repos
	•	Automated deployment of insecure configs

3. IaC Best Practices
	•	Use secrets vaults
	•	Check templates into version control
	•	Security scanning for IaC files
	•	Use “golden modules”
	•	Least privilege IAM policies

F. CONSOLIDATED DOMAIN 3 ARCHITECTURAL CUES
If question says:
“Control which devices connect to network jacks.”
→ 802.1X (NAC) → RADIUS → Posture assessment

“Admins must only enter network from one controlled point.”
→ Jump server / Bastion host

“Traffic must be inspected for SQLi, XSS.”
→ WAF

“Prevent data leaving via USB.”
→ Endpoint DLP

“Block outbound traffic to known-bad cloud apps.”
→ CASB

“Implement secure cryptographic key storage for entire enterprise.”
→ HSM

“Service disruption must be minimized with active/passive systems.”
→ High availability cluster

“Ensure web servers aren’t directly exposed.”
→ Reverse proxy

“Need defense-in-depth for cloud workloads.”
→ SGs + NACLs + WAF + IAM least privilege

✔️ DOMAIN 3 COMPLETE
