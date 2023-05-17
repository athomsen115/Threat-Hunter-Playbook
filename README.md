# Threat-Hunter-Playbook
Collection of resources related to building out the Threat Hunter Playbook, to create hunt plans for cyber threat hunter
Be sure to check out my Whitepaper, and stay tuned for the Threat Hunter Playbooks for both ICS and Enterprise to be uploaded
Next project, building my THP into a website for greater visualization and use

## Operating Systems
Security Onion: https://securityonionsolutions.com/ - free open platform for threat hunting, security monitoring, and log management
Parrot Security: https://www.parrotsec.org/ - Linux distro focused on security, forensics, privacy, and development
Kali Purple: https://www.kali.org/blog/kali-linux-2023-1-release/ - ultimate SOC-in-a-box community project

## ICS Tools and Repositories
Malcolm: https://github.com/cisagov/Malcolm – Network traffic analysis tool suite
GrassMarlin: https://github.com/nsacyber/GRASSMARLIN - passively maps ICS networks
Ettercap: https://www.ettercap-project.org/
https://github.com/MDudek-ICS?tab=repositories – Massive Industrial Control Systems security related repositories collection
https://github.com/ITI/ICS-Security-Tools/tree/master/tools – repository of a variety of tools designed for ICS
https://github.com/paulveillard/cybersecurity-industrial-control-systems-security - collection of software, libraries, documents, books, and resources about industrial control systems
https://socprime.com/blog/siem-edr/threat-hunting-tools-our-recommendations/ - list of recommended threat hunting tools
https://securityboulevard.com/2022/03/5-best-threat-hunting-tools-for-your-security-team/ - list of 5 recommended tools for threat hunting
https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/SCADA.md - contains articles, tools, simulators, and honeypots

## YARA Rules
YARA tool: https://github.com/virustotal/yara/releases - yara download
https://virustotal.github.io/yara/ - yara facts
https://yara.readthedocs.io/en/stable/ - yara documentation
https://www.cisa.gov/uscert/sites/default/files/FactSheets/NCCIC%20ICS_FactSheet_YARA_S508C.pdf - NCCIC Factsheet
https://github.com/BayshoreNetworks/yextend - extension for yara to target zipped files
https://rhisac.org/threat-intelligence/new-cyber-tools-targeting-ics-scada-devices/ - ASRock driver exploit yara rules
https://github.com/dragosinc/CRASHOVERRIDE - crashoverride yara rules
https://github.com/MDudek-ICS/TRISIS-TRITON-HATMAN/blob/master/yara_rules/ics-cert.yara - triton yara rules
https://github.com/Yara-Rules/rules/tree/master/malware - APT list of multiple rules, includes Havex, Stuxnet, BlackEnergy, APT #’s, etc…

## Snort/Suricata Rules
https://github.com/digitalbond/Quickdraw-Suricata - A set of ICS IDS rules for use with Suricata
https://github.com/digitalbond/Quickdraw-Snort - Digital Bond's IDS/IPS rules for ICS and ICS protocols
https://github.com/ITI/ICS-Security-Tools/blob/master/configurations/rules/talos-snort.rules – Snort and Talos specific rules for ICS
https://github.com/CyberICS/Suricata-Rules-for-ICS-SCADA - Suricata rule set to detect scan tools targeting PLC interfaces
https://suricon.net/wp-content/uploads/2017/12/SuriCon17-Stevens_Browning.pdf – PowerPoint containing Suricata basics and a few rule examples for ICS

## Scripts
NMAP scripts: https://github.com/CyberICS/Nmap-script-SCADA - Nmap scripts for SCADA protocols
NMAP script: https://nmap.org/nsedoc/scripts/iec-identify.html - Attempts to identify IEC 60870-5-104 ICS protocol
NMAP ICS Tutorial: https://github.com/gnebbia/nmap_tutorial/blob/master/sections/ics_scada.md - provides tips and walkthrough for scanning ICS devices with NMAP
Python: https://github.com/ITI/ICS-Security-Tools/tree/master/scripts - various industrial security python scripts
ATT&CK: https://github.com/mitre-attack/attack-scripts/ - contains standalone scripts and utilities for working with ATT&CK

## Exploitation (provided to test changes you have made, with permission from company you are evaluating)
Industrial Exploitation Framework: https://github.com/dark-lbp/isf - exploitation framework based on Python, like metasploit framework
ICSsploit: https://github.com/tijldeneut/icssploit - exploitation framework based on Python, it's similar to metasploit framework
ICS Pentesting Tools: https://github.com/kh4sh3i/ICS-Pentesting-Tools - curated list of tools related to ICS security and pentesting
MITRE Caldera: https://github.com/mitre/caldera - automated adversary emulation platform
Pentest Repository: https://github.com/enaqx/awesome-pentest - collection of penetration testing and offensive cybersecurity resources
Attack Graph Generator: https://github.com/mehgrmlhmpf/AttackGraphGeneratorMasterThesis – ICS purple teaming simulation

## Other Tools
dnstwist: https://github.com/elceef/dnstwist – phishing domain scanner
exiftool: https://exiftool.org/ – tool for reading and working with PDF metadata 
johntheripper: https://github.com/openwall/john - password cracker
MITRE Cascade: https://github.com/mitre/cascade-server - “blue-team” focused automated analytics server
snyk: https://snyk.io/ – software composition analysis tool
steghide: https://steghide.sourceforge.net/ – steganography engine
strings: https://linux.die.net/man/1/strings – finds and prints text strings embedded in files
volatility: https://github.com/volatilityfoundation/volatility – advanced memory forensics framework

## Training
MITRE Training: https://attack.mitre.org/resources/training/ - MITRE Training guides and articles
MITRE ATT&CK Training: https://app.cybrary.it/browse/refined?q=Mitre%20ATT%26CK%20Defender – video training of MITRE; can be used in conjunction with MITRE ATT&CK Defender Certification
GRFICS: https://github.com/Fortiphyd/GRFICSv2 - contains 5 ICS VMs to create a training range 


## Additional Resources
SANS Blog Part 1: https://www.sans.org/blog/ics-threat-hunting-they-are-shootin-at-the-lights-part-1/
SANS Blog Part 2: https://www.sans.org/blog/ics-threat-hunting-they-are-shootin-at-the-lights-part-2/
Threat Hunting Blog: https://blog.cyberproof.com/blog/leveraging-threat-hunting-tools-to-improve-threat-detection-response
https://www.cisa.gov/sites/default/files/publications/2021-seminars-ics-security-508.pdf – ICS security seminar slides
CISA Advisory on APT Tools: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-103a – list of APT Cyber Tools Targeting ICS/SCADA Devices and mitigations to apply
CISA Advisories: https://www.cisa.gov/news-events/cybersecurity-advisories 
PLC Security: https://plc-security.com/ - contains information on secure PLC coding practices and PLC security info
List of Resources: https://github.com/ics-iot-bootcamp/ICS_Awesome_List - list of communities, conferences, exercises, trainings, articles, and more
Default Passwords: https://github.com/arnaudsoullie/ics-default-passwords - default passwords for a few ICS systems
Scanner IPs: https://github.com/CyberICS/list_ics_scanner - list of ICS scanners
