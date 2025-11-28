DOMAIN 5 — Governance, Risk, and Compliance (Part 1)
Covering:
	•	Security policies vs standards vs guidelines vs procedures
	•	Security roles (data owner, data steward, DPO, system owner, etc.)
	•	Risk management fundamentals
	•	Likelihood × Impact model
	•	Risk responses (avoid, accept, transfer, mitigate)
	•	Vendor/third-party risk basics
When you’re ready for Part 2, say “Next chunk.”

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 5 (Part 1)
GOVERNANCE • POLICY • RISK MANAGEMENT • ROLES
Domain 5 is concept-heavy — full of definitions that appear deceptively similar. Security+ tests your understanding of governance hierarchy, risk treatments, and ownership roles.

A. POLICY, STANDARD, GUIDELINE, PROCEDURE — EXAM MUST KNOW
Security frameworks follow a hierarchy. If you know this perfectly, many questions are trivial.

1. Policy (“the what”)
High-level organizational rules.
Examples:
	•	“All data must be encrypted at rest.”
	•	“MFA required for all admin access.”
Characteristics:
	•	Broad
	•	Mandatory
	•	Approved by leadership

2. Standard (“the how much / how strong”)
Defines specific technical requirements.
Examples:
	•	“AES-256 required for all encrypted storage.”
	•	“Minimum password length: 14 characters.”

3. Guideline (“the recommended way”)
Optional best practices.
Examples:
	•	“Prefer password managers for storing credentials.”
Guidelines are not mandatory for compliance.

4. Procedure (“the how to do it step-by-step”)
Technical or operational instructions.
Examples:
	•	“Steps to onboard a new user.”
	•	“Steps to apply a patch.”
	•	“Procedure for rotating database keys.”
Procedures are detailed, whereas policies are broad.

Exam Cue Summary
Term
Meaning
Notes
Policy
High-level rules
Mandatory
Standard
Technical requirements
Enforceable
Guideline
Recommended practice
Optional
Procedure
Step-by-step instructions
Exact steps
If you see words like “step-by-step,” “how-to,” “instructions,” → Procedure.

B. SECURITY ROLES & RESPONSIBILITIES
Knowing these roles is crucial — exam questions revolve around “Who is responsible for…?”

1. Data Owner (Business Owner)
	•	Defines classification
	•	Determines sensitivity
	•	Approves access
	•	Responsible for compliance
Usually department leadership (CFO for financial data, HR director for HR data).

2. Data Steward / Data Custodian
	•	Implements data owner’s policies
	•	Handles day-to-day data management
	•	Ensures accuracy and storage integrity
Think: operational caretaker.

3. Data Processor
Processes data on behalf of data controller/owner. Common in GDPR context (cloud vendors, SaaS providers).

4. Data Controller
Determines why and how data is processed. (The organization itself.)

5. Data Protection Officer (DPO) — GDPR Role
	•	Ensures privacy compliance
	•	Interfaces with regulators
	•	Mandatory for large-scale PII processing

6. System Owner
	•	Owns a specific system (e.g., payroll server)
	•	Responsible for ensuring system security
	•	Manages system-specific updates and configs

7. Security Administrator
	•	Implements security controls
	•	Maintains firewalls, IDS, SIEM
	•	Performs user provisioning

8. Privacy Officer
	•	Ensures compliance with privacy laws (HIPAA, GDPR, etc.)
	•	Oversees privacy policies

9. User
	•	Follows policies
	•	Responsible for proper data handling

C. RISK MANAGEMENT (ULTRA-DENSE)
Risk = Likelihood × Impact
Security+ tests the risk treatment decisions heavily.

1. Risk Terminology
	•	Threat — potential danger
	•	Vulnerability — weakness that can be exploited
	•	Impact — damage if exploited
	•	Likelihood — chance of occurrence
	•	Risk — likelihood × impact
	•	Residual Risk — risk remaining after mitigation

2. Risk Assessment Types
Qualitative
	•	Uses descriptions (low/medium/high)
	•	Heat maps
Quantitative
	•	Uses numbers ($ value)
	•	ALE (Annualized Loss Expectancy)
	•	SLE (Single Loss Expectancy)
	•	ARO (Annual Rate of Occurrence)
Formulas:
SLE = AV × EF Asset Value × Exposure Factor
ALE = SLE × ARO

3. RISK RESPONSE OPTIONS (MEMORIZE THIS)
a. Mitigate
Add controls to reduce risk. Example: install firewall, add MFA.
b. Transfer
Shift risk to third party. Example: cyber insurance, outsourcing.
c. Avoid
Stop doing the risky activity. Example: disable vulnerable service.
d. Accept
Do nothing; acknowledge risk. Example: formally documented acceptance.

4. Compensating Controls
Alternative control used when primary control is impractical. Example: isolate legacy systems instead of upgrading.

D. THIRD-PARTY / VENDOR RISK
This touches supply-chain themes from Domain 2 but from a governance perspective.

1. Vendor Assessment
Evaluates:
	•	Security posture
	•	Compliance history
	•	Patch cycles
	•	Incident history
	•	Data-handling policies

2. Vendor Agreements
	•	SLA — uptime/performance
	•	MOU — informal agreement
	•	BPA — business partnership terms
	•	ISA — technical security requirements for interconnection

3. Vendor Monitoring
Continuous oversight:
	•	Audits
	•	Logs
	•	Pen test reports
	•	Compliance attestations (SOC 2, ISO 27001)

✔️ End of Domain 5 — Part 1
————————————
DOMAIN 5 — Governance, Risk, and Compliance (Part 2)
Covering:
	•	Governance frameworks (NIST, ISO, SOC, COBIT)
	•	Compliance frameworks (HIPAA, PCI DSS, GDPR, FISMA)
	•	Audit concepts (internal vs external, attestation vs assessment)
	•	Security controls mapping & governance structure
	•	Privacy & data-protection principles
Say “Next chunk.” when ready for Part 3 (final).

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 5 (Part 2)
FRAMEWORKS • COMPLIANCE • GOVERNANCE MODELS • AUDIT FUNDAMENTALS
This is the highest-density section of Domain 5 — it appears in dozens of exam questions.

A. SECURITY & RISK GOVERNANCE FRAMEWORKS
Governance frameworks define how organizations manage security.
These are framework name → purpose questions.

1. NIST
U.S. federal standard-setter.
a. NIST Cybersecurity Framework (NIST CSF)
Functions:
	1	Identify
	2	Protect
	3	Detect
	4	Respond
	5	Recover
Widely used across industries.

b. NIST SP 800-53
Security controls for federal information systems.
3 control families:
	•	Technical
	•	Operational
	•	Management

c. NIST SP 800-171
Protects Controlled Unclassified Information (CUI) in non-federal systems.

d. NIST SP 800-37 (RMF)
Risk Management Framework:
	•	Categorize
	•	Select
	•	Implement
	•	Assess
	•	Authorize
	•	Monitor

2. ISO/IEC Frameworks
a. ISO 27001
Information Security Management System (ISMS). Focus: risk management + governance.
b. ISO 27002
Security control best practices.
c. ISO 27701
Privacy Information Management (GDPR alignment).

3. SOC Reports (System and Organization Controls)
SOC 1
Financial reporting controls.
SOC 2
Security, Availability, Confidentiality, Privacy.
	•	Trust Service Criteria (TSC):
	◦	Security
	◦	Availability
	◦	Processing integrity
	◦	Confidentiality
	◦	Privacy
SOC 3
Public summary of SOC 2 (less detail).

4. COBIT
Framework for governance of enterprise IT.
Focus:
	•	Align IT goals with business goals
	•	Control objectives
	•	Audit readiness

5. CIS Controls
Critical Security Controls (CSC):
	•	18 controls
	•	Practical baseline hardening
	•	Realistic enterprise best practices

B. COMPLIANCE REGULATIONS (MAJOR EXAM CONTENT)

1. HIPAA (U.S. Healthcare)
Protects PHI (Protected Health Information).
Important sections:
	•	Privacy Rule
	•	Security Rule
Controls include:
	•	Safeguarding electronic health data
	•	Access tracking
	•	Breach notification

2. PCI DSS (Payment Industry)
Protects cardholder data.
Key requirements:
	•	Network segmentation
	•	No default passwords
	•	Encryption of stored card data
	•	Secure key management
	•	Quarterly scans
	•	Penetration tests
	•	Strict access controls

3. GDPR (European Union)
Protects personal data of EU subjects.
Principles:
	•	Data minimization
	•	Purpose limitation
	•	Storage limitation
	•	Accuracy
	•	Integrity & confidentiality
	•	Lawfulness, fairness, transparency
Rights:
	•	Right to access
	•	Right to be forgotten
	•	Right to data portability
	•	Right to rectification
Requires:
	•	Data Protection Officer (DPO)
	•	Breach notification (72 hours)
	•	Data sovereignty compliance

4. FISMA (Federal Information Security Modernization Act)
Requires U.S. federal agencies to comply with NIST frameworks.

5. SOX (Sarbanes–Oxley Act)
Financial reporting accuracy.
Requires:
	•	Log retention
	•	Audit trails
	•	Internal controls

6. FERPA (Education)
Protects student educational records.

7. COPPA
Protects data of children under 13.

8. GLBA (Gramm–Leach–Bliley Act)
Protects financial customer data.

C. AUDIT / ASSESSMENT CONCEPTS

1. Internal vs External Audits
Internal Audit
Performed by internal team.
Focus:
	•	Internal compliance
	•	Gaps
	•	Readiness
External Audit
Performed by independent third party. Used for certifications (PCI, SOC 2).

2. Attestation vs Assessment
Attestation
3rd party verifies security controls. (“We confirm you meet the criteria.”)
Assessment
Evaluates effectiveness of controls. Often includes remediation advice.

3. Types of Audits
a. Compliance Audit
Checks adherence to frameworks.
b. Technical Security Audit
System-level configs & controls.
c. Operational Audit
Examines processes & procedures.
d. Financial Audit
Regulated by SOX, SOC 1.

4. Audit Artifacts
	•	Policies
	•	Procedures
	•	Logs
	•	Configuration reports
	•	Vulnerability scans
	•	Evidence of control execution

D. PRIVACY CONCEPTS (HIGH-YIELD)

1. Data Minimization
Collect only what is needed.

2. Purpose Limitation
Use data only for stated purpose.

3. Consent Requirements
Must be:
	•	Explicit
	•	Informed
	•	Withdrawable
	•	Specific

4. Data Sovereignty
Data must reside in certain geographic regions.

5. Data Transfer Agreements
For cross-border data movement.

6. Anonymization vs Pseudonymization
Anonymization
Irreversible removal of identifiers.
Pseudonymization
Reversible, using keys or mapping tables.

E. SECURITY CONTROL MAPPING
You will see questions like:
“Which control type addresses this requirement?”
Mapping must be instant.

1. Administrative/Managerial
	•	Policies
	•	Risk assessments
	•	Training
2. Technical
	•	Firewalls
	•	Encryption
	•	Access control
	•	Antivirus
3. Physical
	•	Locks
	•	Cameras
	•	Guards

Control Types
	•	Preventive
	•	Detective
	•	Corrective
	•	Compensating
	•	Directive

✔️ End of Domain 5 — Part 2
—————————————
DOMAIN 5 — Governance, Risk, and Compliance (Part 3 — FINAL)
Covering:
	•	Security documentation management (policies, procedures, baselines)
	•	Security awareness & training programs
	•	Data roles + responsibilities (full mapping)
	•	Continuous monitoring (governance-level)
	•	Third-party risk (deep detail)
	•	Control assessment & reporting
	•	FINAL Domain 5 consolidated cues
After this, the entire Security+ Ultra-Dense Memory Scaffold will be complete.
When you're ready for the wrap-up or to begin next phases (Cheat Sheet, Flashcards, Weak-Area Map), just tell me.

🔥 ULTRA-DENSE MEMORY SCAFFOLD — DOMAIN 5 (Part 3 FINAL)
POLICY MANAGEMENT • TRAINING • CONTINUOUS MONITORING • THIRD-PARTY RISK

A. SECURITY DOCUMENTATION & KNOWLEDGE MANAGEMENT
This is about how organizations maintain, store, version-control, and enforce policies.

1. Documentation Structure (Governance Stack)
TOP → DOWN (in order of authority):
	1	Policies — high-level mandatory rules
	2	Standards — technical requirements
	3	Baselines — minimum mandatory configuration sets
	4	Guidelines — recommended practices
	5	Procedures — step-by-step instructions
Exam pattern: If a question describes how to do something → procedure. If describing what must be done → policy. If describing technical specification → standard or baseline.

2. Change Management of Documentation
Policy documents must have:
	•	Version control
	•	Review dates
	•	Owner/approver
	•	Distribution list
	•	Training requirements

3. Exceptions Process
Documented, risk-assessed deviations from policy.
Example: legacy system cannot meet password policy → exception with compensating controls.

4. Data Governance Documentation
	•	Data flows
	•	Data lineage
	•	Classification scheme
	•	Handling rules
	•	Retention schedule
	•	Destruction procedures

B. SECURITY AWARENESS & TRAINING PROGRAMS
Security+ tests “what training is appropriate” based on role/scenario.

1. Types of User Training
a. General security awareness
For all employees:
	•	Phishing
	•	Password hygiene
	•	Clean desk policy
	•	Physical access rules
b. Role-based training
Admins, developers, HR, finance, and managers.
Examples:
	•	Developers → secure coding
	•	HR → data privacy
	•	SOC → incident detection
c. Specialized training
For:
	•	Incident responders
	•	Forensic analysts
	•	System architects

2. Training Goals
	•	Reduce human error
	•	Prevent social engineering
	•	Ensure policy understanding
	•	Improve reporting of incidents
	•	Maintain compliance

3. Training Reinforcement Techniques
	•	Phishing simulations
	•	Posters & reminders
	•	Login banners
	•	Mandatory annual refresh

C. CONTINUOUS MONITORING (GOVERNANCE LEVEL)
Different from SOC operations; this is about enterprise-wide oversight.

1. What Continuous Monitoring Includes
	•	Config baseline scanning
	•	Vulnerability scanning
	•	Patch compliance
	•	SIEM analytics
	•	IAM activity monitoring
	•	Cloud posture (CSPM)
	•	Network telemetry (NetFlow, SNMP)

2. Governance Layer
Continuous monitoring feeds:
	•	Risk dashboards
	•	Compliance reporting
	•	Audit evidence
	•	Leadership briefings

3. Drift Detection
Ensures systems remain aligned with baseline.

D. THIRD-PARTY RISK MANAGEMENT (ADVANCED DETAIL)
One of the most important parts of modern governance.

1. Third-Party Relationships
Examples:
	•	Cloud vendors
	•	SaaS providers
	•	Managed service providers (MSPs)
	•	Consultants
	•	Contract developers
	•	Payment processors
	•	HVAC vendors (e.g., Target 2013 breach)

2. Third-Party Risk Lifecycle
a. Initial Due Diligence
Before signing contract:
	•	Security questionnaires
	•	SOC 2 Type II reports
	•	Pen test results
	•	Data-handling procedures
	•	Incident response readiness
	•	Background checks
b. Contractual Controls
Agreements must define:
	•	SLAs
	•	Security requirements
	•	Access controls
	•	Encryption requirements
	•	Logging & retention
	•	Breach notification timelines
	•	Right-to-audit clause
c. Ongoing Monitoring
	•	Annual assessments
	•	Continuous monitoring
	•	Reviewing vulnerability disclosures
	•	Reviewing new SOC reports
	•	Watching access logs for vendor accounts
d. Offboarding Vendors
	•	Revoke credentials
	•	Destroy/sanitize data
	•	Terminate VPN & interconnects
	•	Validate compliance with contract obligations

3. Risk Transfer
Used when outsourcing:
	•	Cyber insurance
	•	Liability sharing
	•	Managed security services

4. Third-Party Access Controls
Vendor access must be:
	•	Least privileged
	•	Monitored
	•	Time-limited
	•	Logged
	•	Segmented
	•	MFA enforced

E. SECURITY CONTROL ASSESSMENT & REPORTING

1. Assessment Types
	•	Internal assessment
	•	External audit
	•	Independent attestation
	•	Vulnerability assessment
	•	Penetration test
	•	Configuration review
	•	Compliance audit

2. Maturity Models
Used to rate organizational security posture:
	•	CMMI
	•	NIST CSF maturity tiers
	•	Proprietary models (low → optimized)

3. Reporting to Management
Reports must include:
	•	Risk ranking
	•	Findings
	•	Recommendations
	•	Residual risk
	•	Business impact
	•	Remediation requirements
	•	Dependencies

F. CONSOLIDATED DOMAIN 5 EXAM CUES
If question says:
“Define high-level organizational rules.” → Policy.
“Specifies required minimum encryption standards.” → Standard.
“Step-by-step instructions.” → Procedure.
“Responsible for classifying data.” → Data Owner.
“Processes data on behalf of controller.” → Data Processor.
“Ensures privacy compliance.” → DPO (GDPR).
“Determine impact and downtime tolerance.” → BIA.
“Choose control if legacy system cannot be patched.” → Compensating control.
“Evaluate third-party system interconnection.” → ISA.
“Ensure continuous compliance.” → Continuous monitoring.
“Demonstrate control effectiveness to external regulator.” → Attestation.
“Right to be forgotten.” → GDPR.
“Framework for ISMS.” → ISO 27001.
“Manage CUI.” → NIST SP 800-171.

✔️ DOMAIN 5 COMPLETE
