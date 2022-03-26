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

**Footprinting Concepts** -> 2.1
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

**Google Dorks** -> 2.2
1. Utilize Google advance search features to footprinting a target
- What in the world are Google Dorks?
- How do we use them to perform recon?
- https://gbhackers.com/latest-google-dorks-list/
- https://www.boxpiper.com/posts/google-dork-list

**Shodan, Censys and Thingful** -> 2.3
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

**Sub-Domain Enumeration** -> 2.4
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

**Geolocation Recon** -> 2.5
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

**Social Networking Recon** -> 2.6
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

**Job Board Recon** -> 2.7
1. Gather useful target information like employed technologies and organizational structure through searching job board posts
- We're talking about recon and today's show is about using Job Boards for that purpose. Can you help us put the puzzle together on how that works?
    - Job boards contain a lot of information
        - Job roles
        - Contact info
        - Locations
        - Email Addresses
        - Implemented technologies

**Deep/Dark Web Recon** -> 2.8
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

2.9 -> **Custom Wordlists**
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

2.10 -> **Metadata Recon**
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

**Malware Concepts And Components**
1. Define Malware
2. List the common malware types
3. Explain how malware spreads
4. List and define common components that make up, or are used by Malware
























