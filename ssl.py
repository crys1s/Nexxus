import sys
import os
import subprocess
import csv
import pandas as pd

def ssltest():
	print(" ------------------------------------SSL TESTING FILES AND OUTPUT----------------------------------------- ")

	a = ("sslresults")
	# os.mkdir(a)
	b = ("sslinstances")
	# os.mkdir(b)

	try:
		argum1 = "ssl_input.txt"
		print("Checking for client initiated renegotiation, Heartbleed and ROBOTS vulnerabilities")

		subprocess.run([".././nst-ssl.sh",argum1])
		

	except Exception as e:
		print(e)

	
def sslfilearrangement():
	a = ("sslresults")
	b = ("sslinstances")

	try:
		command1 = "mv ssl*.log %s/" % (a)
		command2 = "mv Vuls-*.txt %s/" % (b)

		os.system(command1)
		os.system(command2)

	except Exception as e:
		print(e)
		
	os.chdir(b)


	try:
		data_frame_list = []
		if os.path.isfile("Vuls-ssl-cir.txt"):
			df1 = pd.read_csv('Vuls-ssl-cir.txt', names=['Client initiated renegotiation'])
			data_frame_list.append(df1)

		if os.path.isfile("Vuls-ssl-hb.txt"):
			df2 = pd.read_csv('Vuls-ssl-cir.txt', names=['Heartbleed'])
			data_frame_list.append(df2)

		if os.path.isfile("Vuls-ssl-robots.txt"):
			df3 = pd.read_csv('Vuls-ssl-robots.txt', names=['Robots Vulnerabilities'])
			data_frame_list.append(df3)


		result = pd.concat(data_frame_list,axis=1)
		result.to_csv('finalssl.csv',index=False)

	except Exception as e:
		print(e)

	os.chdir('..')











	
