**Basic Cybersecurity Concepts**
1. Define the 5 elements of information security
- People watching may be new to cybersecurity. We need to cover foundational cybersecurity topics. can you list the 5 main concepts/elements of cybersecruity for us?
    - List the5 elements of cybersec
- CIA Triad
    - Confidentiality
    - Intergrity
    - Availability
- How about 2 other elements fit into the picture
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












































