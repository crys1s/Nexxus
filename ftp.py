import os
import csv
import subprocess
import pandas as pd

def ftptest():
    print("---------------------------FTP FILES AND OUTPUTS----------------------")
    a = ("ftpresults")
    os.mkdir(a)
    b = ("ftpinstances")
    os.mkdir(b)

    try:
            command = "cat ftphost.txt | wc -l"
            j = int(subprocess.check_output([command], shell = True, stderr=subprocess.STDOUT))
            print(j)
            with open("id.txt", "w") as myfile:
                for i in range(1, j+1):
                    myfile.write("%s\n" % i)
            myfile.close()

            with open('ftphost.txt', 'r') as host, open('ftpport.txt', 'r') as port, open ('id.txt', 'r') as hostid:
                for hosts, ports, hostsid in zip(host, port, hostid):
                    hosts = hosts.rstrip()
                    ports = ports.rstrip()
                    hostsid = hostsid.rstrip()
                    command1 = "nmap -sS -sV -Pn -n -p %s -oA %s/ftpbouncefor%s --script ftp-bounce %s > %s/ftpbounceoutput%s.log" % (ports, a, hostsid, hosts, a, hostsid)
                    command2 = "nmap -sS -sV -Pn -n -p %s -oA %s/ftpanonfor%s --script ftp-anon %s > %s/ftpanonoutput%s.log" % (ports, a, hostsid, hosts, a, hostsid)
                    # command2 = "nmap -sS -sV -Pn -n -p %s -oA %s/hostkeyoutputfor%s --script ftp-anon %s > %s/ftpanonoutput%s.log" % (ports, a, hostsid, hosts, a, hostsid)
                    os.system(command1)
                    os.system(command2)

    except Exception as e:
        print(e)

            ##ftp bounce,anoymous,cleartext support(check with starttls)

def ftptriage():
    a = ("ftpresults")
    b = ("ftpinstances")

    try:
        bouncehost = "cat %s/ftpbounceoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/bounce working!/p' | grep -B1 -B2 -e 'bounce working!'| grep -e 'Nmap scan' | awk '{print $5}' |tr -d '()' > %s/ftpbouncehost.txt" % (a, b)
        bounceport = "cat %s/ftpbounceoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/bounce working!/p' | grep -B1 -B2 -e 'bounce working!'| grep -e ' open  ' | awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/ftpbounceport.txt" % (a, b)
        os.system(bouncehost)
        os.system(bounceport)

        anonhost = "cat %s/ftpanonoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/Anonymous FTP login allowed/p' | grep -B1 -B2 -e 'login allowed' | grep -e 'Nmap scan' | awk '{print $5}' | tr -d '()' > %s/ftpanonhost.txt" % (a, b)
        anonport = "cat %s/ftpanonoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/Anonymous FTP login allowed/p' | grep -B1 -B2 -e 'login allowed' | grep -e ' open  ' | awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/ftpanonport.txt" % (a, b)
        os.system(anonhost)
        os.system(anonport)

    except Exception as e:
        print(e)

def ftpfilechange():
    b =('ftpinstances')
    os.chdir(b)

    try:
        with open("ftpbouncehost.txt") as xh:
            with open('ftpbounceport.txt') as yh:
                with open("finalftpbounce.txt","w") as zh:
                    #first line
                    xlines = xh.readlines()
                    #first line of second
                    ylines = yh.readlines()
                    #line by line using zip
                    for line1, line2 in zip(xlines, ylines):
                        zh.write("{}:{}\n".format(line1.rstrip(), line2.rstrip()))
    except Exception as e:
        print(e)

    try:
        with open("ftpanonhost.txt") as xh:
            with open('ftpanonport.txt') as yh:
                with open("finalftpanon.txt","w") as zh:
                    #first line
                    xlines = xh.readlines()
                    #first line of second
                    ylines = yh.readlines()
                    #line by line using zip
                    for line1, line2 in zip(xlines, ylines):
                        zh.write("{}:{}\n".format(line1.rstrip(), line2.rstrip()))
    except Exception as e:
        print(e)
    
    try:
        df1 = pd.read_csv('finalftpbounce.txt', names = ['FTP Privileged Port Bounce Scan'])
        df2 = pd.read_csv('finalftpanon.txt', names = ['FTP Anonymous Login Enabled'])
        result = pd.concat([df1,df2], axis=1)
        result.to_csv("finalftpfile.csv", index=False)
    except Exception as e:
        print(e)
        
    os.chdir('..')

def ftpscreenshots():
    b = ('ftpinstances')
    os.chdir(b)
    c = ('ftpscreenshot')
    os.mkdir(c)

    try:
        f = open("ftpbouncehost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("ftpbounceport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sS -sV -Pn -n -p %s --script ftp-bounce %s && scrot -u -d 2 %s/FTP Privileged Port Bounce Scan.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)

    try:
        f = open("ftpanonhost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("ftpanonport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sS -sV -Pn -n -p %s --script ftp-anon %s && scrot -u -d 2 %s/FTP Anonymous Login Enabled.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)

    os.chdir('..')


