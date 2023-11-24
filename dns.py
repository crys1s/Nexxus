import sys
import subprocess
import os
import csv
import pandas as pd


# The input is getting in form of as --> ip_address:port

def dnstest():
	print("----------------------DNS FILES AND OUTPUTS--------------------")
	a = ("dnsresults")
	os.mkdir(a)
	b = ("dnsinstances")
	os.mkdir(b)

	try:
		argum1 = "dns_input.txt"
		# Zone-transfer and Cache Snoop
		subprocess.call([".././nst-dns.sh", argum1])
	
	except Exception as e:
		print(e)

		
	try:		
		print("\n\n\t-------------Checking for Open Recursive Queries----------------\n")
 
		logs = open("dns-logs_open_recursive_queries.log" , "w")
		vuln = open("Vuls-DNS-Recursive.txt" , "w")

		logs.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "dns_input.txt"),'r') as list_file :
			Lines = list_file.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
		
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -sU -p"+port+" --script=dns-recursion "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs.write(output)

				if "Recursion appears to be enabled" in output :
					print("\n\n\t"+ip_addr+":"+port+" ====> Recursion Enabled\n\n")
					logs.write("\n\n\t"+ip_addr+":"+port+" ====> Recursion Enabled\n\n")
					vuln.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Recursion is not Enabled\n\n")
					logs.write("\n\n\t"+ip_addr+":"+port+" ====> Recursion is not Enabled\n\n")


		list_file.close()
		logs.close()
		vuln.close()

	
	except Exception as e:
		print(e) 
		
	
	try:
		print("\n\n\t-------------Checking for DNS ZONE Transfer----------------\n")
		logs1 = open("dns-logs_dns-zone-transfer.log" , "w")
		vuln1 = open("Vuls-DNS-Zone-transfer.txt" , "w")

		logs1.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "dns_input.txt"),'r') as list_file1 :
			Lines = list_file1.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
		
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -d --script dns-zone-transfer.nse "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs1.write(output)
				
				if "dns-zone-transfer: ERROR" in output:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs1.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					
				elif "dns-zone-transfer:" in output:
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					logs1.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					vuln1.write(ip_addr+":"+port+'\n')
				 
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs1.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					
					
		list_file1.close()
		logs1.close()
		vuln1.close()

	
	except Exception as e:
		print(e) 
			


def dnsfilearrangement():
	a = ('dnsresults')
	b = ('dnsinstances')
	
	try:
		command1 = "mv dns*.log %s/" % (a)
		command2 = "mv Vuls-DNS-*.txt  %s/" % (b)

		os.system(command1)
		os.system(command2)
	
	except Exception as e:
		print(e)	

	os.chdir(b)

	try:
		data_frame_list = []
		
		if os.path.isfile("Vuls-DNS-CS.txt"):
			df1 = pd.read_csv('Vuls-DNS-CS.txt', names=['Vulnerable DNS Cache Snooping List'])
			data_frame_list.append(df1)

		if os.path.isfile("Vuls-DNS-Zone-transfer.txt"):
			df2 = pd.read_csv('Vuls-DNS-Zone-transfer.txt' , names=['Vulnerable DNS Zone Transfer'])
			data_frame_list.append(df2)

		if os.path.isfile("Vuls-DNS-Recursive.txt"):
			df3 = pd.read_csv('Vuls-DNS-Recursive.txt', names=['Vulnerable Open Recursive Queries'])
			data_frame_list.append(df3)	
		
		result = pd.concat(data_frame_list, axis=1)
		result.to_csv("finaldns.csv", index=False)
	
	except Exception as e:
		print(e)

	os.chdir('..')


def dnsscreenshots():

	b = ('dnsinstances')
	c = ('dnsscreenshots')

			




