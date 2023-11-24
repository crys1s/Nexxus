import os
import sys
import subprocess
import pandas as pd
import csv


def rdptest():
	print("-------------------------------RDP FILES AND OUTPUT------------------------------------")

	a = ('rdpresults')
	os.mkdir(a)
	b = ('rdpinstances')
	os.mkdir(b)

	try:
		print("\t-----------------Checking encryption level of RDP-------------------------\n")

		logs = open("logs-RDP-encryption.log" , "w")
		vuln = open("vuln_RDP_encryption.txt" , "w")

		logs.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "rdp_input.txt"),'r') as list_file :
			Lines = list_file.readlines()
	
			for line in Lines :
				line = line.rstrip()
		
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
		
				cmd = "nmap -Pn -p "+port+" --script rdp-enum-encryption "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs.write(output)

				if ("RDP Encryption level: None" in output) or ("RDP Encryption level: Low" in output) :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					logs.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					vuln.write(ip_addr+":"+port+"\n")
				else :
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
	
				# print(output)
				# print(output)
		

		list_file.close()
		logs.close()	
		vuln.close()

	except Exception as e:
		print(e)


	try:
		print("\t-------------------- Checking for RDP MITM Vuln-------------------------\n")
		
		logs1 = open("logs-RDP-MITM.log","w")
		vuln1 = open("vuln-RDP-MITM.txt","w")
		
		logs1.write(subprocess.getoutput("date")+"\n")
		
		with open(os.path.join(sys.path[0], "rdp_input.txt"),'r') as list_file1:
			Lines = list_file1.readlines()
			
			for line in Lines:
				line = line.rstrip()
				
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
				
				cmd = "perl /root/rdp-sec-check/rdp-sec-check.pl "+ip_addr
				
				output = subprocess.getoutput(cmd)
				print(output)
				logs1.write(output)
				
				if "has issue ONLY_RDP_SUPPORTED_MITM" in output:  
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
		
		
	try:
		print("\t-------------------- Checking for WEAK_RDP_ENCRYPTION_SUPPORTED---------------\n")
			   
		logs2 = open("logs-WEAK_RDP_ENCRYPTION_SUPPORTED.log","w")
		vuln2 = open("vuln-WEAK_RDP_ENCRYPTION_SUPPORTED.txt","w")
		
		logs2.write(subprocess.getoutput("date")+"\n")
		
		with open(os.path.join(sys.path[0], "rdp_input.txt"),'r') as list_file2:
			Lines = list_file2.readlines()
			
			for line in Lines:
				line = line.rstrip()
				
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
				
				cmd = "perl /root/rdp-sec-check/rdp-sec-check.pl "+ip_addr
				
				output = subprocess.getoutput(cmd)
				print(output)
				logs2.write(output)
				
				if "WEAK_RDP_ENCRYPTION_SUPPORTED" in output:  
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					logs2.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					vuln2.write(ip_addr+":"+port+'\n')
					
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs2.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					
		list_file2.close()
		logs2.close()
		vuln2.close()
		
	except Exception as e:
		print(e)
		
	try:
		print("\t-------------------- Checking for NLA_NOT_SUPPORTED_DOS---------------\n")
		
		logs3 = open("logs-NLA_NOT_SUPPORTED_DOS.log","w")
		vuln3 = open("vuln-NLA_NOT_SUPPORTED_DOS.txt","w")
		
		logs3.write(subprocess.getoutput("date")+"\n")
		
		with open(os.path.join(sys.path[0], "rdp_input.txt"),'r') as list_file3:
			Lines = list_file3.readlines()
			
			for line in Lines:
				line = line.rstrip()
				
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
				
				cmd = "perl /root/rdp-sec-check/rdp-sec-check.pl "+ip_addr
				
				output = subprocess.getoutput(cmd)
				print(output)
				logs3.write(output)
				
				if "has issue NLA_NOT_SUPPORTED_DOS" in output:  
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					logs3.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					vuln3.write(ip_addr+":"+port+'\n')
					
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs3.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					
		list_file3.close()
		logs3.close()
		vuln3.close()
		
	except Exception as e:
		print(e)
		
		

def rdpfilearrangement():
	
	a = ('rdpresults')
	b = ('rdpinstances')

	try:

		command1 = "mv logs*.log %s/" % (a)
		command2 = "mv vuln*.txt %s/" % (b)

		os.system(command1)
		os.system(command2)

	except Exception as e:
		print(e)


	os.chdir(b)

	try:

		data_frame_list = []

		if os.path.isfile("vuln_RDP_encryption.txt"):
			df1 = pd.read_csv('vuln_RDP_encryption.txt', names=['vuln_RDP_encryption'])
			data_frame_list.append(df1)
			
		if os.path.isfile("vuln-RDP-MITM.txt"):
			df2 = pd.read_csv('vuln-RDP-MITM.txt', names=['Microsoft Windows RDP Server Man-In-The-Middle Weakness'])
			data_frame_list.append(df2)
			
		if os.path.isfile("vuln-WEAK_RDP_ENCRYPTION_SUPPORTED.txt"):
			df3 = pd.read_csv('vuln-WEAK_RDP_ENCRYPTION_SUPPORTED.txt', names=['Terminal Services Accept Weak Encryption'])
			data_frame_list.append(df3)
			
		if os.path.isfile("vuln-NLA_NOT_SUPPORTED_DOS.txt"):
			df4 = pd.read_csv('vuln-NLA_NOT_SUPPORTED_DOS.txt', names=['Terminal Services Do Not Support NLA'])
			data_frame_list.append(df4)
			
		result = pd.concat(data_frame_list, axis=1)
		result.to_csv("finalrdp.csv",index=False)

	except Exception as e:
		print(e)


	os.chdir('..')




