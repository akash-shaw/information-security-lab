# Tools

## [Kali Linux](https://www.kali.org/)

kali linux is a debian based linux distribution focused around various information security tasks such as pen testing, security research, forensics, reverse engineering, etc.

## [OWASP](https://owasp.org/)
he Open Worldwide Application Security Project (formerly Open Web Application Security Project) (OWASP) is an online community that produces freely available articles, methodologies, documentation, tools, and technologies in the fields of IoT, system software and web application security.

## [OWASP ZAP](https://www.zaproxy.org/)

Zed Attack Proxy (ZAP) by Checkmarx is a free, open-source penetration testing tool. ZAP is designed specifically for testing web applications and is both flexible and extensible.

At its core, ZAP is what is known as a “manipulator-in-the-middle proxy.” It stands between the tester’s browser and the web application so that it can intercept and inspect messages sent between browser and web application, modify the contents if needed, and then forward those packets on to the destination. It can be used as a stand-alone application, and as a daemon process.

## [Metasploit](https://www.metasploit.com/) 

The Metasploit Project is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. It is owned by Rapid7, a Boston, Massachusetts-based security company.

Its best-known sub-project is the open-source Metasploit Framework, a tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.

The Metasploit Project includes anti-forensic and evasion tools, some of which are built into the Metasploit Framework. In various operating systems it comes pre installed.

## [Burp Suite](https://portswigger.net/burp)

Burp Suite is a proprietary collection of software tools for security assessment and penetration testing of web applications. It was initially developed in 2003-2006 by Dafydd Stuttard to automate his own security testing needs, after realizing the capabilities of automatable web tools like Selenium. Stuttard created the company PortSwigger to flagship Burp Suite's development. A community, professional, and enterprise version of this product are available.

Notable capabilities in this suite include features to proxy web-crawls (Burp Proxy),[6] log HTTP requests/responses (Burp Logger and HTTP History), capture/intercept in-motion HTTP requests (Burp Intercept), and aggregate reports which indicate weaknesses (Burp Scanner). This software uses a built-in database containing known-unsafe syntax patterns and keywords to search within captured HTTP requests/responses.

Burp Suite possesses several penetration-type functionalities. A few built-in PoC services include tests for HTTP downgrade, interaction with tool-hosted external sandbox servers (Burp Collaborator), and analysis for pseudorandomization strength (Burp Sequencer). This tool permits integration of user-defined functionalities through download of open-source plugins (such as Java Deserialization Scanner and Autorize).


## [Ettercap](https://www.ettercap-project.org/)

Ettercap is a comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.

##  [Hydra](https://www.kali.org/tools/hydra/)

Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.

This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely.

It supports: Cisco AAA, Cisco auth, Cisco enable, CVS, FTP, HTTP(S)-FORM-GET, HTTP(S)-FORM-POST, HTTP(S)-GET, HTTP(S)-HEAD, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MS-SQL, MySQL, NNTP, Oracle Listener, Oracle SID, PC-Anywhere, PC-NFS, POP3, PostgreSQL, RDP, Rexec, Rlogin, Rsh, SIP, SMB(NT), SMTP, SMTP Enum, SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, Teamspeak (TS2), Telnet, VMware-Auth, VNC and XMPP.


## [Mosquitto](https://mosquitto.org/)

Mosquitto is an open-source MQTT (Message Queuing Telemetry Transport) broker crucial for IoT communication. It's lightweight, ideal for low-power devices like sensors and microcontrollers. Using a publish/subscribe model, Mosquitto allows devices to send messages (publish) to specific topics, and other devices (subscribers) interested in those topics receive the messages. It handles real-time data transmission efficiently, even across unreliable networks, ensuring messages reach recipients once they reconnect. Mosquitto is cross-platform, compatible with Linux, Windows, macOS, and embedded systems like Raspberry Pi. It's widely used for IoT device communication, home automation, and sensor networks, providing efficient data exchange between devices in various applications. It's a fundamental component for building and scaling IoT solutions.




## [Nmap](https://nmap.org/)

Nmap (Network Mapper) is a network scanner created by Gordon Lyon (also known by his pseudonym Fyodor Vaskovich). Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses.

Nmap provides a number of features for probing computer networks, including host discovery and service and operating system detection. These features are extensible by scripts that provide more advanced service detection, vulnerability detection, and other features. Nmap can adapt to network conditions including latency and congestion during a scan.

Nmap started as a Linux utility and was ported to other systems including Windows, macOS, and BSD. It is most popular on Linux, followed by Windows.


## [sqlmap](https://sqlmap.org/)

sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.


## [Sqlninja](https://sqlninja.sourceforge.net/)

Sqlninja's main goal is to get interactive OS-level access on the remote DB server and to use it as a foothold in the target network. As an experimental feature, it can also extract data from the database. In a nutshell, here's what it does:

-   Fingerprint of the remote SQL Server (version, user performing the queries, user privileges, xp_cmdshell availability, DB Server authentication mode)
-   Bruteforce of the 'sa' password (SQL Server 2000 only)
-   Privilege escalation to 'sa' (SQL Server 2000 only)
-   Creation of a custom xp_cmdshell if the original one has been disabled
-   Upload of executables
-   Reverse scan in order to look for a port that can be used for a reverse shell
-   Direct and reverse shell, both TCP and UDP
-   DNS tunneled pseudoshell, when no ports are available for a bindshell
-   ICMP tunneled shell, if the target DBMS can communicate via ICMP Echo with the attacking machine
-   Metasploit wrapping, when you want to use Meterpreter or even want to get GUI access on the remote DB server
-   OS privilege escalation on the remote DB server using token kidnapping or through CVE-2010-0232
-   Extraction of data from the remote DB, using WAITFOR-based inference or DNS-based tunnels
-   All of the above can be done with obfuscated SQL code, in order to confuse IDS/IPS systems


## [netcat](https://nmap.org/ncat/)

netcat (often abbreviated to `nc`) is a computer networking utility for reading from and writing to network connections using TCP or UDP. The command is designed to be a dependable back-end that can be used directly or easily driven by other programs and scripts. At the same time, it is a feature-rich network debugging and investigation tool, since it can produce almost any kind of connection its user could need and has a number of built-in capabilities.
It is able to perform port scanning, file transferring and port listening.


## [ MSFvenom](https://www.offsec.com/metasploit-unleashed/msfvenom/)

MSFvenom is a command-line tool that is part of the Metasploit Framework. it combines the functionalities of msfpayload and msfencode into a single tool. MSFvenom is primarily used for generating and encoding payloads, which can be deployed on a target machine to exploit vulnerabilities during penetration testing. It allows ethical hackers and penetration testers to craft malicious executables or scripts to achieve objectives like privilege escalation and remote code execution. 


## [Microsoft Threat Model]()

hreat modeling is a core element of the Microsoft Security Development Lifecycle (SDL). It’s an engineering technique you can use to help you identify threats, attacks, vulnerabilities, and countermeasures that could affect your application. You can use threat modeling to shape your application's design, meet your company's security objectives, and reduce risk.

![threat_modeling](https://cdn-dynmedia-1.microsoft.com/is/image/microsoftcorp/response:VP1-539x349)

There are five major threat modeling steps:

-   Defining security requirements.  
-   Creating an application diagram.  
-   Identifying threats.  
-   Mitigating threats.  
-   Validating that threats have been mitigated.

Threat modeling should be part of your routine development lifecycle, enabling you to progressively refine your threat model and further reduce risk.

The Microsoft Threat Modeling Tool makes threat modeling easier for all developers through a standard notation for visualizing system components, data flows, and security boundaries. It also helps threat modelers identify classes of threats they should consider based on the structure of their software design. We designed the tool with non-security experts in mind, making threat modeling easier for all developers by providing clear guidance on creating and analyzing threat models.

he Threat Modeling Tool enables any developer or software architect to:

-   Communicate about the security design of their systems.  
-   Analyze those designs for potential security issues using a proven methodology. 
-   Suggest and manage mitigations for security issues.


## [PyCharm](https://www.jetbrains.com/pycharm/)

PyCharm is an integrated development environment (IDE) used for programming in Python. It provides code analysis, a graphical debugger, an integrated unit tester, integration with version control systems, and supports web development with Django. PyCharm is developed by the Czech company JetBrains and built on their IntelliJ platform.

It is cross-platform, working on Microsoft Windows, macOS, and Linux. PyCharm has a Professional Edition, released under a proprietary license and a Community Edition released under the Apache License. PyCharm Community Edition is less extensive than the Professional Edition
