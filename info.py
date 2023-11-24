import sys
import os
import subprocess
import csv
import pandas as pd

def information_disclosure_test():
	print(" ------------------------------Information-Disclosure FILES and OUTPUT-----------------------------")

	a = ("info_results")
	os.mkdir(a)
	b = ("info_instances")
	os.mkdir(b)


	try:
		argum1 = "info_input.txt"
		print("Checking for MEMCHache, MySql, RPC info, XMPP information disclosure\n")

		subprocess.run([".././nst-info.sh",argum1])
		

	except Exception as e:
		print(e)



	try:
		
		print("\n\n\t++++++Checking for Microsoft Client_Access_Server_Information_Disclosure++++++\n")

		logs1 = open("info-logs-IP-Disclosure.log", "w")
		vuln1 = open("Vuls-IP_disclosure.txt" , "w")

		# Default path is the '/' for checking about the internal IP disclosure

		logs1.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "info_input.txt"),'r') as list_file1 :
			Lines = list_file1.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -p"+port+" --script http-internal-ip-disclosure "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs1.write(output)

				if "Internal IP Leaked" in output :
					print("\n\n\t"+ip_addr+":"+port+" ====> Internal IP disclosed\n\n")
					logs1.write("\n\n\t"+ip_addr+":"+port+" ====> Internal IP disclosed\n\n")
					vuln1.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs1.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")


		list_file1.close()
		logs1.close()
		vuln1.close()

	except Exception as e:
		print(e)


	try:

		print("\t++++++Checking for Information Disclosure from the SNMP Service++++++\n")
		
		
		logs2 = open("info-logs-SNMPsysdescr.log", "w")
		vuln2 = open("Vuls-list_SNMPsysdescr.txt" , "w")

		# Attempts to extract system information from an SNMP service.

		logs2.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "info_input.txt"),'r') as list_file2 :
			Lines = list_file2.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -sU -p "+port+" --script snmp-sysdescr "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs2.write(output)

				if ("snmp-sysdescr:" in output) or ("System uptime:" in output):
					print("\n\n\t"+ip_addr+":"+port+" ====> Information Disclosure\n\n")
					logs2.write("\n\n\t"+ip_addr+":"+port+" ====> Information Disclosure\n\n")
					vuln2.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs2.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")


		list_file2.close()
		vuln2.close()
		logs2.close()


	except Exception as e:
		print(e)


	try:
		
		print("\t++++++Checking an XDCMP for Infromation Disclosure+++++\n")

		
		logs3 = open("info-logs-xdmcp-discover.log" , "w")
		vuln3 = open("Vuls-xdmcp-discover.txt" , "w")

		logs3.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "info_input.txt"),'r') as list_file3 :
			Lines = list_file3.readlines()
	
			for line in Lines :
				line = line.rstrip()
		
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
		
				cmd = "nmap -Pn -sU -p "+port+" --script xdmcp-discover "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs3.write(output)

				if ("Session id:" in output) or ("Authorization data:" in output) :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					logs3.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					vuln3.write(ip_addr+":"+port+"\n")
				else :
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs3.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")

				# print(output)
		

		list_file3.close()
		logs3.close()
		vuln3.close()


	except Exception as e:
		print(e)



def information_disclosure_filearrangement():
	a = ('info_results')
	b = ('info_instances')

	try:

		command1 = "mv info*.log %s/" % (a)
		command2 = "mv Vuls-*.txt %s/" % (b)

		os.system(command1)
		os.system(command2)


	except Exception as e:
		print(e)


	os.chdir(b)


	try:
		data_frame_list = []
		if os.path.isfile("Vuls-memcached-info.txt"):
			df1 = pd.read_csv('Vuls-memcached-info.txt', names=['Memcached info.'])
			data_frame_list.append(df1)
		
		if os.path.isfile("Vuls-mysql-info.txt"):
			df2 = pd.read_csv('Vuls-mysql-info.txt', names=['Vuln. mysql info.'])
			data_frame_list.append(df2)
	
		if os.path.isfile("Vuls-rpc-info.txt"):
			df3 = pd.read_csv('Vuls-rpc-info.txt' , names=['Vuln. rpc info.'])
			data_frame_list.append(df3)

		if os.path.isfile("Vuls-xmpp-info.txt"):
			df4 = pd.read_csv('Vuls-xmpp-info.txt', names=['Vuln. XMPP info.'])
			data_frame_list.append(df4)

		if os.path.isfile("Vuls-IP_disclosure.txt"):
			df5 = pd.read_csv('Vuls-IP_disclosure.txt', names=['Vuls-IP_disclosure'])
			data_frame_list.append(df5)

		if os.path.isfile("Vuls-list_SNMPsysdescr.txt"):
			df6 = pd.read_csv('Vuls-list_SNMPsysdescr.txt', names=['Vuln. SNMP system description'])
			data_frame_list.append(df6)

		if os.path.isfile("Vuls-xdmcp-discover.txt"):
			df7 = pd.read_csv('Vuls-xdmcp-discover.txt', names=['Vuln. XDCMP discovery'])
			data_frame_list.append(df7)

		result = pd.concat(data_frame_list,axis=1)
		result.to_csv("final_info_disclose.csv", index=False)

	except Exception as e:
		print(e)

	os.chdir('..')


