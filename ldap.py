import sys
import os
import subprocess
import pandas as pd
import csv

def ldaptest():

	print("---------------------------------LDAP FILES AND OUTPUT-------------------------------------------")
	a = ('ldapresults')
	os.mkdir(a)
	b = ('ldapinstances')
	os.mkdir(b)

	try:
		print("\t++++++Checking for LDAP Anonymous bind++++++\n")

		logs = open("logs-LDAP_anonymous_bind.log", "w")
		vuln = open("vulnerable_LDAP_anonymous_bind.txt" , "w")

		# Used ldapsearch requires the Ip of the LDAP server 
		# Identifying base name than querying for the ldap users

		logs.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "ldap_input.txt"),'r') as list_file :
			Lines = list_file.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0]
				port = line[1]

				cmd = "ldapsearch -h "+ip_addr+" -p "+port+" -x -s base -b '' \""+str('(objectClass=*)')+"\" \"*\" +"
				print(cmd)
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs.write(output)

				start = output.find('dc=')
				end = output.find('supportedControl:')
		
				if start < 0:
					print("\n\n\t"+ip_addr+" ====> Not Vulnearble\n\n")
					logs.write("\n\n\t"+ip_addr+" ====> Not Vulnerable\n\n")
				else:
					base_name = output[start:end]
					cmd1 = "ldapsearch -h "+ip_addr+" -p "+port+" -x -b \""+base_name+"\""
			
					output1 = subprocess.getoutput(cmd1)
					print(output1)
					logs.write(output1)

					if ("ntUniqueId:" in output1) or ("ntUserDomainId:" in output1) or ("ntUserLastLogon:" in output1):
						print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
						logs.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
						vuln.write(ip_addr+":"+port+'\n')

					else:
						print("\n\n\t"+ip_addr+":"+port+" ====> Safe\n\n")
						logs.write("\n\n\t"+ip_addr+":"+port+" ====> Safe\n\n")


		list_file.close()
		vuln.close()
		logs.close()

	except Exception as e:
		print(e)

def ldapfilearrangement():
	a = ('ldapresults')
	b = ('ldapinstances')

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

		if os.path.isfile("vulnerable_LDAP_anonymous_bind.txt"):
			df1 = pd.read_csv("vulnerable_LDAP_anonymous_bind.txt", names=['LDAP Anonymous bind'])
			data_frame_list.append(df1)

		result = pd.concat(data_frame_list, axis=1)
		result.to_csv("finalldap.csv",index=False)

	except Exception as e:
		print(e)

	os.chdir('..')

