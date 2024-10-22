----------------------------
Cross verifying findings from Nesssus Pulgin Ids and Port Numbers for each Vulnerability and checks for the particular add-on for each vulnerability and finds the vulnerable IPs for each vulnerability.
----------------------------
About:
=======
The main objective of this tool is to integrate the Nessus with nmap and verify the results received from Nessus. The update in this tool has integrated the detection of widely more number of Vulnerabilities. The list of Vulnerabilities updated in this version are:
	• DNS - Zone transfer
	• DNS - Cache Snoop
	• DNS – Open Recursive Queries
	• HTTP header – HSTS
	• HTTP header - verbose server banner
	• HTTP -- vulnerable software/server version
	• F5 BIG-IP Cookie Information Disclosure
	• xmpp-info
	• my-sql info
	• SSL – heartbleed
	• SSL - Client initiated renegotiation
	• SSL - ROBOTS vulnerabilities
	• Rpcinfo
	• memcached-info
	• HTTP Insecure Methods
	• HTTP Vulnerable CVEs
	• LDAP 
	• Microsoft-Exchange-Client-Access-Server-Info-Disclosure
	• Rdp-Enum-Encryption
	• SNMP Sys Descr
	• XDMCP-discover
Some of the functions are still need to verify on beta version like:
	• LDAP 
	• HTTP Vulnerable CVEs
	• Rdp-Enum-Encryption
Working:
=========
	• On the start, we have to install the pre-requisites required for running the tool by running the “nst-install.sh” file in the terminal.
	• Now, after receiving the report from the nessus scan (csv file), we can run the main tool named in the folder as “automation.py” which will run a scan for different vulnerabilities.
	• As soon as the main tool is executed, the required input field appears, asking the number of nessus reports(csv file) will be checked.
	• Next, we need to insert the csv file’s name contained in the same folder as the main tool file.
	• Basically, the tool extracts the Pulgin Ids and Port Numbers for each Vulnerability and checks for the particular add-on for each vulnerability and finds the vulnerable IPs for each vulnerability.
	• Then the tool executes and shows the list of vulnerable ips for every particular vulnerability.
	• Then for the output, the csv files containing the list of vulnerable ips for every vulnerability is listed and stored in the folder named as Assessment 1

Installation:
==============
For Kali Linux(Recommended):
-----------------------------
	1) cd NST-Tool/
	2) cd opt/kali/
	3) chmod +x kali-nst-install.sh
	4) ./kali-nst-install.sh
For Ubuntu Linux:
	01) cd NST-Tool/
	02) cd opt/ubuntu/
	03) chmod +x ubuntu-nst-install-1.sh
	04) ./ubuntu-nst-install-1.sh
	05) sudo curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash 
	06) source $HOME/.bashrc &> /dev/null
	07) source /root/.bashrc &> /dev/null
	08) nvm install node
	09) chmod +x ubuntu-nst-install-2.sh
	10) ./ubuntu-nst-install-2.sh
Note: If you get any error while installing then first please let the tool complete the installtion process than reboot the system and run the install file again.
NOTE : install scrot for screenshots in your linux

"apt-get update && apt-get install scrot"

Note: Keep the Testssl in the root Directory (/root/testssl)

------------------------Keep the Testssl in the root directory.-----------------------------

1.Copy the Folder in your Linux Machine
2.Update the Python to Python > 3.9
3.Run the following command : 
	"python3 -m pip install -r requirements.txt" && "python -m pip install -r requirements.txt"
4. keep the Nessus CSV file in the "Automation" folder
5. After that, Run the Following Command:
      "Python3 automation.py"
6. It will ask for the number of CSV OUTPUT. (CSV OUTPUT: these are nessus csv output files).
7. then, It will ask for csv file name
8. Write the name of the csv file. eg - output.csv
9. Wait for testssl and other serivces to get completed then just collect the csv file in Instances folder for SSL and other services Related Findings (SSH, FTP, NTP). 


----------------------------------------------------------------------------------------

Currently can test and triage for ssh,ftp,ntp,ssl.

dns, ike, http-headers will give later on, there is some confusion will nesssus plugins.
