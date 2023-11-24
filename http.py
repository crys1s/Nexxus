import sys
import os
import subprocess
from subprocess import PIPE,STDOUT
import csv
import pandas as pd

def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))
def prLightPurple(skk): print("\033[94m {}\033[00m" .format(skk))
def prPurple(skk): print("\033[95m {}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))
def prLightGray(skk): print("\033[97m {}\033[00m" .format(skk))
def prBlack(skk): print("\033[98m {}\033[00m" .format(skk))


# input --> ip_address:port

def httptest():
	print(" -----------------------------HTTP FILES AND OUTPUTS--------------------------------")

	a = ("httpresults")
	os.mkdir(a)
	b = ("httpinstances")
	os.mkdir(b)

	try:
		argum1 = "http_input.txt"
		# HSTS header, Verbose Server Banner, Vulnerable software/server version, Big-IP cookie Information Disclosure
		
		subprocess.call([".././nst-http.sh",argum1])
		
		
	except Exception as e:
		print(e)

	try:
		# Checking for HTTP Insecure Methods
		# your first argument will be the file of domain ips
		# your second argument will be the test file that you want to upload (Should be in current directory)
		
	
		prGreen("\n\n\t++++++Checking for HTTP Insecure Methods++++++")
		logs = open("logs_HTTP_Insecure_Methods.log" , "w")
		vuln = open("Vuls-http-Insecure_Methods.txt" , "w")
		

		with open(os.path.join(sys.path[0], "http_input.txt"),'r') as list_file :
			Lines = list_file.readlines()

			for line in Lines :
				line = line.rstrip()

				line = line.split(":")
				ip_addr = line[0]
				port = line[1]
					
				host = subprocess.getoutput("echo "+ip_addr+" | httpx -silent")
				print(host)			
				
				#cmd2 = 'curl --insecure'+host+'/ --upload-file '+sys.argv[2]				
				#cmd3 = 'curl --insecure -X DELETE '+host+'/test_file.txt'
				cmd5 = 'sudo nmap -p'+port+' -Pn --script http-trace -d '+ip_addr
				#cmd6 = 'sudo nmap -Pn -T3 --script http-open-proxy -p '+port+' '+ip_addr

				#output1 = subprocess.getoutput(cmd2)
				
		
				# print(cmd4)
				# print(output4)

				# Checking for PUT method enabled or not
				"""logs.write(output1+"\n")

				if ('PUT' in output1) :
					print(output1)
					print("\n\n\t"+ip_addr+" ====> PUT method enabled\n\n")
					logs.write("\n\n\t"+ip_addr+" ====> PUT method enabled\n\n")

				else :
					print(output1)
					print("\n\n\t"+ip_addr+" ====> PUT method disabled\n\n")
					logs.write(str(output1))
					logs.write("\n\n\t"+ip_addr+" ====> PUT method disabled\n\n")


				
				# Checking for DELETE method enabled or not
				output3 = subprocess.getoutput(cmd3)

				if "DELETE" in output1 :
					print(output1)
					print("\n\n\t"+ip_addr+" ====> DELETE method enabled\n\n")
					logs.write(output1)
					logs.write("\n\n\t"+ip_addr+" ====> DELETE method enabled\n\n")
					vuln.write(ip_addr+":"+port+'\n')
				else :
					print(output1)
					print("\n\n\t"+ip_addr+" ====> DELETE method disabled\n\n")
					logs.write(str(output1))
					logs.write("\n\n\t"+ip_addr+" ====> DELETE method disabled\n\n")
				"""
		
				# Checking for TRACE method enabled or not
				output5 = subprocess.getoutput(cmd5)				
		
				if ("http-trace: TRACE is enabled" in output5) or ("TRACE is enabled" in output5) :
					print(output5)
					print("\n\n\t"+ip_addr+" ====> HTTP TRACE enabled\n\n")
					logs.write(output5)
					logs.write("\n\n\t"+ip_addr+" ====> HTTP TRACE enabled\n\n")
					vuln.write(ip_addr+":"+port+'\n')
				else :
					print(output5)
					print("\n\n\t"+ip_addr+" ====> HTTP TRACE disabled\n\n")
					logs.write(output5)	
					logs.write("\n\n\t"+ip_addr+" ====> HTTP TRACE disabled\n\n")

		

				# Checking for CONNECT method or if http-proxy is open
				"""output6 = subprocess.getoutput(cmd6)
				if ("Potentially OPEN proxy" in output6):
					print(output6)
					print("\n\n\t"+ip_addr+" ====> HTTP CONNECT enabled\n\n")
					logs.write(output6)
					logs.write("\n\n\t"+ip_addr+" ====> HTTP CONNECT enabled\n\n")
					vuln.write(ip_addr+":"+port+'\n')
				else:
					print(output6)
					print("\n\n\t"+ip_addr+" ====> HTTP CONNECT disabled\n\n")
					logs.write(output6)
					logs.write("\n\n\t"+ip_addr+" ====> HTTP CONNECT disabled\n\n")
				"""
	
		list_file.close()
		logs.close()
		vuln.close()
	
	except Exception as e:
		print(e)



def httpfilearrangement():
	a = ('httpresults')
	b = ('httpinstances')

	try:
		command1 = "mv http.log logs_HTTP_Insecure_Methods.log %s/" % (a)
		command2 = "mv Vuls-http-*.txt %s/" % (b)
		
		os.system(command1)
		os.system(command2)

	except Exception as e:
		print(e)

	os.chdir(b)

	try:
		
		data_frame_list = []
		if os.path.isfile("Vuls-http-Insecure_Methods.txt"):
			df1 = pd.read_csv('Vuls-http-Insecure_Methods.txt', names=['HTTP Insecure methods enabled'])
			data_frame_list.append(df1)
		
		if os.path.isfile("Vuls-http-hsts.txt"):
			df2 = pd.read_csv('Vuls-http-hsts.txt', names=['HSTS header not present'])
			data_frame_list.append(df2)

		if os.path.isfile("Vuls-http-vsb.txt"):
			df3 = pd.read_csv('Vuls-http-vsb.txt' , names=['Verbose Server Banner'])
			data_frame_list.append(df3)

		if os.path.isfile("Vuls-http-sv.txt"):
			df4 = pd.read_csv('Vuls-http-sv.txt', names=['Vulnerable Software Version'])
			data_frame_list.append(df4)
		
		if os.path.isfile("Vuls-http-bigip.txt"):
			df5 = pd.read_csv('Vuls-http-bigip.txt', names=['BIG-IP Cookie Information Disclosure'])
			data_frame_list.append(df5)

		result = pd.concat(data_frame_list,axis=1)
		result.to_csv("finalhttp.csv", index=False)

	except Exception as e:
		print(e)

	os.chdir('..')



