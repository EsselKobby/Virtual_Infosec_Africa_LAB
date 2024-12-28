#  INTERNAL PENETRATION TEST

###### Ethical Hacking Bootcamp
[Virtual Infosec Africa,](https://virtualinfosecafrica.com) [Department of Telecommunications Engineering](https://teleng.knust.edu.gh/)
___
Author:
Bernard Kobina Forson Essel.


[Source](https://github.com/EsselKobby/VIA-LAB)

___

## Table of Contents

- [INTERNAL PENETRATION TEST](#internal-penetration-test)
          - [Ethical Hacking Bootcamp](#ethical-hacking-bootcamp)
  - [Table of Contents](#table-of-contents)
    - [Executive Summary](#executive-summary)
    - [Analysis of Overall Security Posture](#analysis-of-overall-security-posture)
    - [Key Recommendations](#key-recommendations)
    - [Testing Methodology](#testing-methodology)
     - [HOSTS DISCOVERY](#hosts-discovery)
            - [SUBDOMAIN ENUMERATION](#subdomain-enumeration)
        - [SERVICE DISCOVERY](#service-discovery)
              - [NMAP,SERVICE DISCOVERY \& PORT SCANNING](#nmapservice-discovery--port-scanning)
              - [Nmap Service Discovery Output](#nmap-service-discovery-output)
        - [VULNERABILITY SCANNING](#vulnerability-scanning)
            - [DETAILED FINDINGS](#detailed-findings)
              - [APACHE 2.4.49(SSL \& HTTP)](#apache-2449ssl--http)
            - [Finding Summary](#finding-summary)
            - [Evidence](#evidence)
            - [Affected Resources:](#affected-resources)
            - [Recommendations:](#recommendations)
            - [References:](#references)
              - [SQL 5.6.49 (mysql)](#sql-5649-mysql)
            - [Finding Summary](#finding-summary-1)
            - [Evidence](#evidence-1)
            - [Affected Resources:](#affected-resources-1)
            - [Recommendations:](#recommendations-1)
            - [References:](#references-1)
              - [RealVNC 5.3.2 (vnc)](#realvnc-532-vnc)
            - [Finding Summary](#finding-summary-2)
            - [Evidence](#evidence-2)
            - [Affected Resources:](#affected-resources-2)
            - [Recommendations:](#recommendations-2)
            - [References:](#references-2)
              - [rdp MICROSOFT TERMINAL SERVICES (rdp)](#rdp-microsoft-terminal-services-rdp)
            - [Finding Summary](#finding-summary-3)
            - [Evidence](#evidence-3)
            - [Affected Resources:](#affected-resources-3)
            - [Recommendations:](#recommendations-3)
            - [References:](#references-3)
      - [CVSS v3.0 Reference Table](#cvss-v30-reference-table)
            - [THE 'CEWL' TOOL](#the-cewl-tool)
        - [WEB-BASED ATTACK SURFACES](#web-based-attack-surfaces)
    ___
    
___

### Executive Summary

The internal network penetration test conducted on the IP range 10.10.10.0/24 for Virtual Infosec Africa evaluated the security of the network infrastructure through a series of targeted assessments. 

Initially, Nmap was used for host and service discovery, revealing several active devices and their associated services. This scan identified critical services, such as HTTP, SSH, and FTP, with some running outdated versions or misconfigured settings, which could pose security risks.

Following this, Metasploit was employed for vulnerability scanning, uncovering multiple security weaknesses. Notably, several high-risk vulnerabilities were detected, including unpatched software and misconfigured services that could be exploited by attackers to gain unauthorized access to the network.

To assess the web application security, Eyewitness was utilized to document and analyze the web-based services. This analysis pinpointed several web applications with known vulnerabilities and improper configurations, potentially allowing sensitive data exposure or system compromise.
The findings highlight significant security gaps that need to be addressed promptly. The detailed report includes specific recommendations for patch management, service hardening, and web application security improvements to enhance the network's overall security posture.

___
### Analysis of Overall Security Posture

The penetration test revealed several critical vulnerabilities in the network infrastructure, indicating a weakened security posture. The host and service discovery phase exposed multiple active devices with open ports and outdated or misconfigured services. These findings suggest that the network is susceptible to various types of attacks, including unauthorized access and exploitation of known vulnerabilities. The presence of unpatched services, particularly those with critical roles like HTTP and SSH, further compounds the risk, making it easier for potential attackers to exploit these weaknesses.

Additionally, the vulnerability scanning using Metasploit uncovered significant security flaws, including unpatched software and misconfigurations that could be leveraged for unauthorized access. The web-based surface attack analysis using Eyewitness highlighted vulnerabilities in web applications, which could potentially lead to data breaches or system compromises. Collectively, these findings point to an urgent need for a comprehensive security overhaul. Implementing recommended remediation strategies, such as regular patching, service hardening, and securing web applications, is crucial for fortifying the network and mitigating potential threats. Without these improvements, the network remains vulnerable to exploitation and potential breaches.

___

### Key Recommendations

* Ensure all software is updated with the latest security patches and implement a regular patch management process.
* Review and close unnecessary open ports, and harden configurations for critical services.
* Strengthen authentication by implementing multifactor authentication (MFA) and apply the principle of least privilege to user accounts and services.
* Conduct periodic vulnerability assessments and penetration tests, and prioritize and remediate high-risk vulnerabilities promptly.
* Review and secure web applications, implement web application firewalls (WAFs), and adhere to secure coding practices.
* Enable comprehensive logging and monitoring to detect suspicious activities, and develop and regularly update an incident response plan.

___

### Testing Methodology

The penetration test began with a thorough **Host and Service Discovery** phase using Nmap, a widely-used network scanning tool. This step involved scanning the provided IP range (10.10.10.0/24) to identify all active hosts and enumerate the services running on their respective ports. By mapping out the network and cataloging open ports and services, this phase provided a foundational understanding of the network's topology and potential entry points for further testing.

Following discovery, the **Vulnerability Scanning** phase employed Metasploit to assess the identified services for known vulnerabilities. This automated scanning process aimed to uncover weaknesses such as outdated software, unpatched vulnerabilities, and misconfigurations that could be exploited by attackers. The results highlighted critical security issues and provided a basis for prioritizing remediation efforts based on the severity of the vulnerabilities discovered.

Finally, the **Web-Based Surface Attack** analysis was conducted using Eyewitness, which focused on the security of web applications within the network. This tool documented the web-based services and assessed their security posture, identifying vulnerabilities and misconfigurations that could lead to data breaches or system compromises. This phase aimed to provide insights into the security of web applications and recommend improvements to safeguard against potential exploits.


___

### HOSTS DISCOVERY

The Nmap tool was use to scan for the host available in the network scope. The command used for the host discovery is shown below:

![hostdiscover](/assets/hostdiscover.jpg)

The output from the host discovery was then filtered to get their IP Addresses. The host discovery filter by using the **grep** and **awk** commands is shown below:

![hostfilter](/assets/hostfilter1.jpg)

##### SUBDOMAIN ENUMERATION

The subdomain enumeration was done using the **aiodnsbrute** on the hosts in the network scope(10.10.10.1/24)

![aiodnsbrute](/assets/aiodnsbrute.jpg)

___

### SERVICE DISCOVERY

The service discovery helps for the identification and understanding of the services running on the network and the ports they're using and also provide an insight into the network's attack surface.

**Service Discovery** also helps to identify which services are running on specific devices along with their versions enabling testers to pinpoint any known vulnerabilities associated with those services which could serve as entry point for attackers.

**Port Scanning** identifies open ports which serves as gateway for communication between devices by finding this open ports testers can define which services are accessible and possess potential vulnerabilities. For an instance,an open port running an outdated or misconfigured service could provide attacks with a direct path to exploit the network.

###### NMAP,SERVICE DISCOVERY & PORT SCANNING

The Service Discovery and Port Scanning was done using the Nmap tool. The command and output with the various file outputs are shown below: 

![NmapService](/assets/nmapservice.jpg)

The **HTTP** service scan discovery using the nmap tool is show below:

![NmapServiceHttp](/assets/nmapservice_http.jpg)

###### Nmap Service Discovery Output

![nmapserviceoutput](/assets/servicescantype.png)

---

### VULNERABILITY SCANNING
##### DETAILED FINDINGS



###### APACHE 2.4.49(SSL & HTTP)

*Apache 2.4.49 Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    High      |         8.8    |

##### Finding Summary
It was found that there was insufficient security on the **APACHE HTTP server 2.4.49** whereby an attacker can use a path traversal attack to map URLs to files outside the directories configured by Alias-like directories.  If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. 


##### Evidence

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the HTTP server which is shown below:

![apache http](/assets/apachehttp.png)

##### Affected Resources:

  10.10.10.2,  10.10.10.30,   10.10.10.45,      10.10.10.55


##### Recommendations:

* Upgrade Apache: Update to Apache HTTP Server 2.4.51 or later, which contains fixes for these vulnerabilities.
* Secure Aliased Directories: Ensure Alias and AliasMatch directives are correctly configured and protected. 
* Apply Require all denied where needed.
* Disable CGI Scripts: If CGI scripts are not required in aliased directories, disable them.
* Review Configurations: Regularly check and audit directory configurations and access controls.
* Implement Rate Limiting: Use modules like mod_evasive to control request rates and mitigate potential DoS attacks.
* Monitor Server Performance: Use monitoring tools to detect and respond to unusual server behavior.

##### References:

[https://www.cve.org/CVERecord?id=CVE-2021-42013](https://www.cve.org/CVERecord?id=CVE-2021-42013)



###### SQL 5.6.49 (mysql)

*MySQL 5.6.49  Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    Medium      |         4.3    |

##### Finding Summary.

The MySQL version running on the remote host is 5.6.x, up to and including 5.6.48, and is affected by several vulnerabilities. The **CVE-2020-14539** vulnerability in the MySQL Server's optimizer allows a low-privileged attacker with network access to cause a denial of service by making the server hang or crash. The **CVE-2020-14550** affects the MySQL Client's C API, enabling a similar denial of service attack. Additionally, **CVE-2020-1967** impacts MySQL Connectors using OpenSSL, where an unauthenticated attacker with network access via TLS can also cause a denial of service. These issues affect MySQL versions up to 5.6.48, 5.7.30, and 8.0.20, and have been identified based on the reported version number, as Nessus has not directly tested these vulnerabilities.


##### Evidence.

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the mySql server which is shown below:

![mysql img](/assets/mysql.png)

##### Affected Resources:

  10.10.10.5, 10.10.10.40


##### Recommendations:

* Upgrade MySQL:  Upgrade to the latest stable version of MySQL that includes fixes for these vulnerabilities. For MySQL 5.6 users, consider upgrading to a more recent, supported version such as MySQL 5.7.x or 8.0.x, if feasible. 
* Check for Patches: Review the MySQL release notes and apply any relevant security patches that address these vulnerabilities. Ensure that your system is patched with all available updates to mitigate the identified issues.
* Regular Backups: Maintain up-to-date backups of your MySQL databases. Ensure that backups are stored securely and can be quickly restored in the event of an attack or failure.
* Test Recovery Procedures: Periodically test your backup and recovery procedures to ensure they work as expected and can be executed quickly in an emergency.
* Restrict Network Access: Limit network access to your MySQL server using firewall rules or network segmentation. Only allow connections from trusted IP addresses and networks to reduce the risk of exploitation.

##### References:

[https://www.tenable.com/plugins/nessus/138571](https://www.tenable.com/plugins/nessus/138571)

###### RealVNC 5.3.2 (vnc)
*RealVNC 5.3.2   Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    High      |         7.8    |

##### Finding Summary

There was an insight of **CVE-2008-4770** which affects VNC Viewer versions 4.0 to 4.4.2 and allows a remote VNC Server to execute arbitrary code through crafted RFB protocol data. **CVE-2008-3493** can cause a denial of service (application crash) in VNC Viewer 4.1.2.0 via a malicious framebuffer update packet. **CVE-2006-2369** is a severe vulnerability in VNC Enterprise Edition 4.1.1 and other products using RealVNC, enabling remote attackers to bypass authentication through insecure security type requests. Lastly, **CVE-2004-1750** affects VNC Server versions 4.0 and earlier, allowing denial of service through a large number of connections to port 5900. For any additional security issues with VNC, contact the Help Center.


##### Evidence

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the realvnc server which is shown below:

![vnc img](/assets/vnc.png)

##### Affected Resources:

10.10.10.10, 10.10.10.50


##### Recommendations:

* Update VNC Viewer: Upgrade to the latest version of VNC Viewer that addresses the vulnerabilities identified in CVE-2008-4770 and CVE-2008-3493. Ensure you are using a version where these issues are patched.
* Review Authentication Settings: Regularly review and update authentication settings to align with best security practices and to prevent unauthorized access.
* Apply Security Patches: Regularly check for and apply security patches provided by VNC software vendors. Ensure that your systems are up to date with the latest security updates.
* Conduct Vulnerability Assessments: Perform regular security audits and vulnerability assessments on your VNC installations to identify and address any new or existing security issues.
* Review Logs: Regularly review VNC server logs for unusual activity or signs of attempted exploitation, and respond promptly to any suspicious events.
* Monitor and Limit Connections: Monitor the number of connections to port 5900 and implement rate limiting or connection limits to mitigate potential denial of service attacks.

##### References:

[https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=realvnc+5.3.2](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=realvnc+5.3.2)


###### rdp MICROSOFT TERMINAL SERVICES (rdp)
*rdp Analysis*

|Current Rating|CVSS            |
|    ---       |   ---          |
|    Critical      |         9.8    |

##### Finding Summary


The various xrdp(Remote Desktop Protocol) versions prior to 0.10.0 are vulnerable to **CVE-2024-39917**, which allows attackers to bypass the `MaxLoginRetry` configuration parameter and make an infinite number of login attempts. In FreeRDP, **CVE-2023-40576** involves an Out-Of-Bounds Read in the `RleDecompress` function due to insufficient data length in the `pbSrcBuffer` variable, potentially causing errors or crashes. Similarly, **CVE-2023-40575** affects FreeRDP with an Out-Of-Bounds Read in the `general_YUV444ToRGB_8u_P3AC4R_BGRX` function, leading to crashes from insufficient data in the `pSrc` variable. Both FreeRDP issues have been addressed in version 3.0.0-beta3, and users are advised to upgrade, as there are no known workarounds.


##### Evidence.

The *Metasploit Auxiliary Module* was used to scan for vulnerabilities on the rdp server which is shown below:

![rdp img](/assets/rdp.png)

##### Affected Resources:

10.10.10.11, 10.10.10.31, 10.10.10.60


##### Recommendations:

* Implement Rate Limiting: If upgrading is not immediately possible, consider implementing additional rate-limiting mechanisms at the network level to mitigate excessive login attempts.
* Monitor for Exploits: Keep an eye on security advisories and updates related to FreeRDP for any additional patches or improvements.
* Implement Monitoring and Alerts: Set up monitoring and alerting systems to detect unusual activities and potential security incidents promptly.
* Apply Security Patches: Regularly check for and apply security patches and updates for all software to mitigate vulnerabilities.
* Upgrade xrdp: Update to xrdp version 0.10.0 or later, which includes a fix for the login attempt issue.


##### References:

[https://www.cve.org/CVERecord](https://www.cve.org/CVERecord?id=CVE-2023-40576)

---


##### THE 'CEWL' TOOL

CEWL (Custom Word List generator) is a command-line tool used to create customized word lists for password cracking and security testing. It works by spidering websites to extract words from the content, including HTML, JavaScript, and other textual elements. CEWL allows users to specify various options such as the minimum and maximum word length, depth of crawling, and the inclusion of specific file types, making it a versatile tool for generating targeted word lists based on the content of web pages.

The **cewl** tool was used for  to develop a custom wordlist by directing it to the company's website,[Virtual Infosec Africa](https://www.virtualinfosecafrica.com)

### WEB-BASED ATTACK SURFACES

###### THE EYEWITNESS TOOL
**EyeWitness** is a powerful open-source tool designed for web application reconnaissance and assessment. It automates the process of capturing screenshots of web servers and applications by spidering a list of URLs or IP addresses. EyeWitness supports both HTTP and HTTPS protocols and can handle various types of web applications, providing visual snapshots that aid in evaluating web server configurations, identifying exposed services, and conducting security assessments. The tool is particularly useful for security professionals and penetration testers for quickly gathering visual data about web assets and their exposure.

The generation for the screenshots of web servers output using **Eyewitness**, the preparation of the list of HTTP and HTTPS hosts are saved up in a file. The eyewitness command to process the lists of URLs is shown below:

![eyewitness img](/assets/eyewitness1.png)

###### Eyewitness Output

![eyewitness output](/assets/eyewitness.png)

###### THE MFSVENOM TOOL

**msfvenom** is a versatile tool within the Metasploit Framework used for generating custom payloads for exploitation and penetration testing. It allows security professionals to create a wide range of payloads, including reverse shells, bind shells, and Meterpreter sessions, in various formats such as executables, scripts, and documents. By specifying payload types, options like local or remote ports, and output formats (e.g., executable, script, or shellcode), msfvenom helps in crafting tailored payloads to suit specific testing scenarios. It is commonly used to generate payloads for use in attacks against vulnerabilities, facilitating the assessment of system security and response to potential threats.

###### PAYLOAD GENERATION

*Web Server: Apache Tomcat(Java based)*; *Host:10.10.10.55*

The Metasploit tool,msfvenom was used to generate the payloads and filter them for the specific web server which is JAVA Based.The output is shown below:

![java img](/assets/java.png)

There was a need for the selection of a specific payload that can trigger a TCP bind shell when executed by an attacker. The output is shown below:

![java img](/assets/javapayload.png)

The resulted payload was then saved in the *payload.war*, The Java Based web server payload has an extension of **war**. The output of this process is further shown below: 

![javafile img](/assets/javafile.png)

*Web Server: Python server(base64 encode)*; *Host:10.10.10.30*

The Metasploit tool,msfvenom was used to generate the payloads and filter them for the specific web server which is Python Based.The output is shown below:

![java img](/assets/python.png)

There was a need for the selection of a specific payload that can execute a base64 encoding. The output is shown below:

![java img](/assets/pythonpayload.png)

The resulted payload was then saved in the *payload.cmd*, The Python server payload has an extension of **cmd**. The output of this process is further shown below: 

![javafile img](/assets/pythonfile.png)

---
## CVSS v3.0 Reference Table

| Qualitative Rating |  CVSS Score |
| ---                |        ---  |
|**None/Informational**|      N/A  |
|**Low**             |0.1 - 3.9    |
|**Medium**          |4.0 - 6.9    |
|**High**            |7.0 - 8.9    |
|**Criticial**       | 9.0 - 10.0  |

###### Table1: Common Vulnerability Scoring System Version 3.0

---
## Summary of Vulnerability Findings


|     Finding              |     Severity                |
|  ---                   |    ---                    |
|Remote Code Execution (RCE) for apache 2.4.49 | High       |
|Denial of Service (DoS) in apache |  High                  |
|SQL injection via crafted parameters leading to unauthorized access | Medium |
|Improper input validation of access passwords | Medium |
|Arbitrary code execution on VNC server | High          |

*Table*: *Some Common Vulnerability Findings* 

**Snapshot of the PassCrack Program Project**

![dictionary attack](/PassCrack/dictionary%20program%20.png)

![reverse brute attack](/PassCrack/reverse%20brute%20program.png)

