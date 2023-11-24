import os
import subprocess
import sys
import csv
import pandas as pd

def cvetest():
	print("-----------------------------------CVEs FILES AND OUTPUTS-----------------------------------------------")

	a = ("cveresults")
	os.mkdir(a)
	b = ("cveinstances")
	os.mkdir(b)

	print("------------------Testing for CVE-2010-0738--------------(53337)")	
	try:

		logs1 = open("logs_cve2010-0738.log", "w")
		vuln1 = open("vulnerable_cve2010-0738.txt" , "w")

		# Array of paths to check. Defaults to {"/jmx-console/"}.

		logs1.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "cve_input.txt"), "r") as list_file1 :
			Lines = list_file1.readlines()

			for line in Lines :
				line = line.rstrip()
		
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -p"+port+" --script=http-vuln-cve2010-0738 "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs1.write(output)

				if "Authentication bypass" in output :
			
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack"+"\n\n")
					logs1.write("\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack"+"\n\n")
					vuln1.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable"+"\n\n")
					logs1.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable"+"\n\n")


		list_file1.close()
		vuln1.close()
		logs1.close()	


	except Exception as e:
		print(e)



	try:
		print("------------------Testing for CVE-2011-3192--------------(55976)")	

		logs2 = open("logs_cve2011-3192.log", "w")
		vuln2 = open("vulnerable_cve2011-3192.txt" , "w")

		logs2.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "cve_input.txt"),'r') as list_file2 :
			Lines = list_file2.readlines()

			for line in Lines :
				line = line.rstrip()
	
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
			
				cmd = "nmap -Pn -sS -p "+port+" --script http-vuln-cve2011-3192 "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs2.write(output)
		
				if "VULNERABLE" in output :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
					logs2.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
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
		print("------------------Testing for CVE-2014-2126--------------(73533)")

		logs3 = open("logs_cve2014-2126.log", "w")
		vuln3 = open("vulnerable_cve2014-2126.txt" , "w")


		logs3.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "cve_input.txt"),'r') as list_file3 :
			Lines = list_file3.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -p "+port+" --script http-vuln-cve2014-2126 "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs3.write(output)

			if "VULNERABLE" in output :
				print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
				logs3.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
				vuln3.write(ip_addr+":"+port+'\n')
			else:
				print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
				logs3.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")


		list_file3.close()
		vuln3.close()
		logs3.close()

	except Exception as e:
		print(e)


	try:
		print("------------------Testing for CVE-2014-2127--------------(73533)")
			
		logs4 = open("logs_cve2014-2127.log", "w")
		vuln4 = open("vulnerable_cve2014-2127.txt" , "w")


		logs4.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "cve_input.txt"),'r') as list_file4 :
			Lines = list_file4.readlines()

			for line in Lines :
				line = line.rstrip()
		
				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
		
				cmd = "nmap -Pn -p "+port+" --script http-vuln-cve2014-2127 "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs4.write(output)

				if "VULNERABLE" in output :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
					logs4.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
					vuln4.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs4.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")


		list_file4.close()
		vuln4.close()
		logs4.close()

	except Exception as e:
		print(e)


	try:
		print("------------------Testing for CVE-2014-2128--------------(73533)")


		logs5 = open("logs_cve2014-2128.log", "w")
		vuln5 = open("vulnerable_cve2014-2128.txt" , "w")


		logs5.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "cve_input.txt"),'r') as list_file5 :
			Lines = list_file5.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0] 
				port = line[1]
		
				cmd = "nmap -Pn -p "+port+" --script http-vuln-cve2014-2128 "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs5.write(output)

				if "VULNERABLE" in output :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
					logs5.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
					vuln5.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs5.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")


		list_file5.close()
		vuln5.close()
		logs5.close()
	
	except Exception as e:
		print(e)

	
	try:
	
		print("------------------Testing for CVE-2014-2129--------------(73533)")

		logs6 = open("logs_cve2014_2129.log" , "w")
		vuln6 = open("vuln_cve2014_2129.txt" , "w")

		logs6.write(subprocess.getoutput("date")+'\n')

		# Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SIP Denial of Service Vulnerability (CVE-2014-2129). using nmap

		with open(os.path.join(sys.path[0], "cve_input.txt"),'r') as list_file6 :
			Lines = list_file6.readlines()
	
			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0] 
				port = line[1]

				cmd = "nmap -Pn -p "+port+" --script http-vuln-cve2014-2129 "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs6.write(output)

				if ("VULNERABLE" in output) :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					logs6.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					vuln6.write(ip_addr+":"+port+"\n")
				else :
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs6.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")

				# print(output)
				# print(output)
		

		list_file6.close()
		vuln6.close()
		logs6.close()
	
	except Exception as e:
		print(e)


	try:
			
		print("------------------Testing for CVE-2015-1635--------------(82828)")

		logs7 = open("logs_cve2015_1635.log" , "w")
		vuln7 = open("vuln_cve2015_1635.txt" , "w")

		logs7.write(subprocess.getoutput("date")+'\n')

		# Default using the URI to use in request : Default: /

		with open(os.path.join(sys.path[0], "cve_input.txt"),'r') as list_file7 :
			Lines = list_file7.readlines()
	
			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -p "+port+" --script http-vuln-cve2015-1635.nse "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs7.write(output)
	
				if ("VULNERABLE" in output) :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					logs7.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable\n\n")
					vuln7.write(ip_addr+":"+port+"\n")
				else :
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs7.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")

				# print(output)
				# print(output)
		

		list_file7.close()
		logs7.close()	
		vuln7.close()

	except Exception as e:
		print(e)



	try:
		print("------------------Testing for CVE-2017-1001000--------------(97210)")

		logs8 = open("logs_cve2017-1001000.log", "w")
		vuln8 = open("vulnerable_cve2017-1001000.txt" , "w")

		# Default path is the '/' for Wordpress root directory on the website.

		logs8.write(subprocess.getoutput("date")+'\n')

		with open(os.path.join(sys.path[0], "cve_input.txt"),'r') as list_file8 :
			Lines = list_file8.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0]
				port = line[1]

				cmd = "nmap -Pn -p"+port+" --script http-vuln-cve2017-1001000 "+ip_addr
		
				output = subprocess.getoutput(cmd)
				print(output)
				logs8.write(output)

				if "VULNERABLE" in output :
					print("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
					logs8.write("\n\n\t"+ip_addr+":"+port+" ====> Vulnerable to attack\n\n")
					vuln8.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")	
					logs8.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")


		list_file8.close()
		vuln8.close()
		logs8.close()

	except Exception as e:
		print(e)


def cvefilearrangement():
				
	a = ('cveresults')
	b = ('cveinstances')

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
		
		if os.path.isfile("vulnerable_cve2010-0738.txt"):
			df1 = pd.read_csv('vulnerable_cve2010-0738.txt', names=['vulnerable_cve2010-0738'])
			data_frame_list.append(df1)

		if os.path.isfile("vulnerable_cve2011-3192.txt"):
			df2 = pd.read_csv('vulnerable_cve2011-3192.txt' , names=['vulnerable_cve2011-3192'])
			data_frame_list.append(df2)

		if os.path.isfile("vulnerable_cve2014-2126.txt"):
			df3 = pd.read_csv('vulnerable_cve2014-2126.txt', names=['vulnerable_cve2014-2126'])
			data_frame_list.append(df3)	

		if os.path.isfile("vulnerable_cve2014-2127.txt"):
			df4 = pd.read_csv('vulnerable_cve2014-2127.txt', names=['vulnerable_cve2014-2127'])
			data_frame_list.append(df4)

		if os.path.isfile("vulnerable_cve2014-2128.txt"):
			df5 = pd.read_csv('vulnerable_cve2014-2128.txt' , names=['vulnerable_cve2014-2128'])
			data_frame_list.append(df5)

		if os.path.isfile("vulnerable_cve2014-2129.txt"):
			df6 = pd.read_csv('vulnerable_cve2014-2129.txt', names=['vulnerable_cve2014-2129'])
			data_frame_list.append(df6)
	 
		if os.path.isfile("vuln_cve2015_1635.txt"):
			df7 = pd.read_csv('vuln_cve2015_1635.txt' , names=['vuln_cve2015_1635'])
			data_frame_list.append(df7)

		if os.path.isfile("vulnerable_cve2017-1001000.txt"):
			df8 = pd.read_csv('vulnerable_cve2017-1001000.txt', names=['vulnerable_cve2017-1001000.txt'])
			data_frame_list.append(df8)



		result = pd.concat(data_frame_list, axis=1)
		result.to_csv("finalcve.csv",index=False)

	except Exception as e:
		print(e)

	os.chdir('..')



	