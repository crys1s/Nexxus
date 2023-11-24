import sys
import subprocess
import os
import re


def ike_scan_test():
	print("------------------------Performing IKE-SCAN------------------------")
	
	a = ('ikeresults')
	os.mkdir(a)
	b = ('rdpinstances')
	os.mkdir(b)
	
	try:
	   
		logs = open("logs-ike-scan.log","w")
		vuln = open("vuln-ike-scan.txt","w")   
		logs.write(subprocess.getoutput("date")+'\n')
	
		with open(os.path.join(sys.path[0],"ike_input.txt"),'r') as list_file:
			Lines = list_file.readlines()

			for line in Lines:
				line = line.rstrip()

				line = line.split(":")   

				ip_addr = line[0]
				port = line[1]

				cmd = "ike-scan -M -A "+ip_addr+" --id=demogroupname -P -d "+port
				output = subprocess.getoutput(cmd)
				print(output)
				logs.write(output)
			
				if "IKE PSK parameters" and "hash" and "1 returned handshake" in output:
					print("\n\n\t"+ip_addr+":"+port+" ====> Returning IKE-HASH Vulnerable\n\n")
					logs.write("\n\n\t"+ip_addr+":"+port+" ====> Returning IKE-HASH Vulnerable\n\n")
					vuln.write(ip_addr+":"+port+'\n')
				else:
					print("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
					logs.write("\n\n\t"+ip_addr+":"+port+" ====> Not Vulnerable\n\n")
			
			
				#file1.close()
	
		list_file.close()
		logs.close()
		#vuln.close()

	except Exception as e:
		print(e)


def ikefilearrangement():

	a = ('ikeresults')
	b = ('ikeinstances')
	
	try:
		
		command1 = "mv logs*.log %s/" % (a)
		command2 = "mv vuln*.txt %s/" % (b)
		
		os.system(command1)
		os.system(command2)
		
	except Exception as e:
		print(e)
		
	 
	try:
		data_frame_list = []
		
		if os.path.isfile("vuln-ike-scan.txt"):
			df1 = pd.read_csv('vuln-ike-scan.txt', names=['IKE-Aggressive with Pre-Shared Key'])
			data_frame_list.append(df1)
			
	except Exception as e:
		print(e)
		
	os.chdir('..')
	 
	 