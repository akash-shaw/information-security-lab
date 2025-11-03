# Tool Exploration for Information Security

MS Teams Access Code: `hrtvl3x`

## [Kali Linux](https://www.kali.org/)
Kali Linux is a Debian based operating system maintained by the core Debian team to be used for cybersecurity applications specifically. While general OS installations limit certain hardware/software configurations for certain vectors of usage to prevent exploitation, Kali does no such thing - enabling the user to perform various kinds of operations with modularity. Kali is bundled with various readymade tools that allow automation of penetration testing in various stages. It is therefore used by penetration testing teams (both ethical and unethical) to carry out tests/exploits.

## [Owasp-Zap](https://www.zaproxy.org/)
Made by the Open Wroldwide Security Application Project (OWASP), Zed Attack Proxy (ZAP) is a web application vulnerability scanner designed for both automated and manual use. It acts a proxy server and inspects web traffic - analyzing network requests and related data for vulnerability exposure. It also has code review built in to assist fixing any possible issues before a piece of software is pushed into production.

## [Metasploit](https://www.metasploit.com/)
Designed to be a portable network tool in HD Moore in 2003, Metasploit has grown out to be an entire open source penetration testing framework, alongside its derivative sub projects like the OpCode Database, Shellcode Archive etc. Metasploit has, by itself, grown to be a collective of various tools throughout the decades, including coverage for most major publicly known exploits/CVEs used in the field - including those that were leaked from the NSA/TAO hacks in the late 2010s. It is a go to toolkit for penetration testers to approach security issues in any testing scenario. 

## [Burpsuite](https://portswigger.net/burp)
BurpSuite is a tool focused at web exploitation, used by researchers reverse engineering products for APIs. It features detection and exploitation capabilities for vulnerabilities such as Cross Site Scripting (XSS), SQL Injection, Cross Site Request Forgery (CSRF), XML External Entity Injection, Server Side Request Forgery (SSRF) and more. It is used to exploit and map APIs from various applications as well, and can be then used to map them and perform any of the above mentioned exploits.

## [Ettercap](https://www.ettercap-project.org/)
Ettercap is a Man in the Middle (MITM) tool used by security researchers to ensure end to end security of data/action pipelines. It allows users to perform the following tests 
- Host Lists through ARP requests sent to any subnet mask as specified by the user.
- Unified Sniffing: Kernel IP forwarding is disabled, user sends a request with a specific MAC address that is same as the attacker's one but with different IPs, so the packet is then return to the attacker instead.
- Bridged Sniffing
- ARP Poisoning
- ICMP redirection (Half Duplex MITM)
- DHCP Spoofing
- Port Stealing
- Character Injection
et cetera

## [Hydra](https://www.kali.org/tools/hydra/)
Hydra is a network login hacking tool built into Kali Linux used to gain unauthorized access to a remote system over various protocols and suites of tools, enabling an analyst to possibly establish/take down proxies, gain RCE, modify system resources (or their allocation and therefore cost). It supports SSL-based platforms as well and is easy to build extensions for to add support for a newer communication protocol.

## [Mosquitto](https://mosquitto.org/)
Mosquitto is an OSS MQTT broker designed for messaging/message passing applications, including message stores (to facilitate later delivery to a dormant user). It uses a PubSub model over TCP (which is a byeffect of its roots in MQTT) based on topics each client is subscribed to via JSON/XML. Mosquitto scanners are used to identify MQTT brokers during a communication stream and mapping them to engineer exploits accordingly.

## [nmap](https://nmap.org/)
NMap (Network Mapper) is a network discovery tool used in security auditing. NMap uses raw IP packets in various ways to map available hosts, services, versions, OSes, firewalls and can do so with scale and for large networks. 

## [netcat](http://nmap.org/ncat/)
Netcat is used to read and write data across TCP/UDP connections via stdio and is a reliable backend tool to drive programs or scripts that require text passing usage. Ncat, its successor developed by the NMap team adds support for SSL, SOCK4/5 proxies, IPv6 support and other extended functionality. Due to its low level nature, it is easy to obscure and mask with ease.

## [sqlmap](https://sqlmap.org/)
sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It supports mosgt major database and database paradigms such as MySQL, PostgreSQL, Microsoft Access etc. It fully supports the following SQL injection techniques: boolean-based blind, time-based blind, error-based, UNION query-based, stacked queries and out-of-band. It can connect via DBMS credentials if required, includes functionality to enumerate users, password hasehs, priveleges, roles, tables, columns etc.

## [sqlninja](https://www.kali.org/tools/sqlninja/)
SQLninja is a SQL server injection and takeover tool  targeted to exploit SQL Injection vulnerabilities on a web application that uses Microsoft SQL Server as its back-end. Its main goal is to provide a remote access on the vulnerable DB server, even in a very hostile environment. It supports DB fingerprinting, dagta extraction, Metasploit integration to obtain a graphical access to the remote DB server through a VNC server injection or just to upload Meterpreter, obtain a DNS based or ICMP tunneled shell and bruteforcing of sa passwords too. 

## [msfvenom](https://www.rapid7.com/blog/post/2011/05/24/introducing-msfvenom/)
MSFVenom is a fork off the Metasploit Framework merging both `msfpayload` and `msfencode` into one unified tool and framework instance, with a wider variety of I/O file formats and with refined payload generation.

## [Microsoft Threat Modelling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
The Microsoft Threat Modeling Tool used as a part of the SDL allowing software architects to identify and mitigate any risks as they happen. It follows the STRIDE methodology: STRIDE stands for Spoofing, Tampering, Repudiation, Information disclosure, Denial of service and Elevation of privilege. A user designs their architecutre in STRIDE and marks the boundaries accordingly, and STRIDE gives us a list of all possible threat scenarios that the system could be exposed to by crossreferencing then Microsoft Security Database.

## [PyCharm](https://www.jetbrains.com/pycharm/)
PyCharm is the Jetbrains IDE for Python built for use in complex corporate workflows, with an entire extensive plugin ecosystem around it. It inlcudes PEP8 compliance checks, linters, treesitters etc to make development faster and more secure.
