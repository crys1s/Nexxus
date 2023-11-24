import os
import csv
import subprocess
import pandas as pd

def ntptest():
    print("---------------------------NTP FILES AND OUTPUTS----------------------")
    a = ("ntpresults")
    os.mkdir(a)
    b = ("ntpinstances")
    os.mkdir(b)

    try:
        command = "cat ntphost.txt | wc -l"
        j = int(subprocess.check_output([command], shell = True, stderr=subprocess.STDOUT))
        print(j)
        with open("id.txt", "w") as myfile:
            for i in range(1, j+1):
                myfile.write("%s\n" % i)
        myfile.close()

        with open('ntphost.txt', 'r') as host, open('ntpport.txt', 'r') as port, open ('id.txt', 'r') as hostid:
            for hosts, ports, hostsid in zip(host, port, hostid):
                hosts = hosts.rstrip()
                ports = ports.rstrip()
                hostsid = hostsid.rstrip()
                command1 = "nmap -sU -sV -Pn -n -p %s -oA %s/ntpoutputfor%s --script ntp-info %s > %s/ntpinfooutput%s.log" % (ports, a, hostsid, hosts, a, hostsid)
                command2 = "nmap -sU -sV -Pn -n -p %s -oA %s/ntpmonlistoutputfor%s --script ntp-monlist %s > %s/ntpmonlistoutput%s.log" % (ports, a, hostsid, hosts, a, hostsid)
                os.system(command1)
                os.system(command2)

    except Exception as e:
        print(e)

        ##use with ntpq

def ntptriaging():
    a = ('ntpresults')
    b = ('ntpinstances')

    try:
        infohost = "cat %s/ntpinfooutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/processor:/p' -e '/version: /p' -e '/system:/p' | grep -B1 -B2 -e 'version'| grep -e 'Nmap scan' | awk '{print $5}' |tr -d '()' > %s/ntpinfohost.txt" % (a, b)
        infoport = "cat %s/ntpinfooutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/processor:/p' -e '/version: /p' -e '/system:/p' | grep -B1 -B2 -e 'version'| grep -e ' open  '| awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/ntpinfoport.txt" % (a, b)
        os.system(infohost)
        os.system(infoport)
    except Exception as e:
        print(e)

    try:
        monlisthost = "cat %s/ntpmonlistoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/Private Servers/p' -e '/Public Servers/p'-e '/Private Clients /p' -e '/Public Clients/p' | grep -B1 -B2 -e 'Private Servers'| grep -e 'Nmap scan' | awk '{print $5}' |tr -d '()' > %s/ntpmonlisthost.txt" % (a, b)
        monlistport = "cat %s/ntpmonlistoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/Private Servers/p' -e '/Public Servers/p'-e '/Private Clients /p' -e '/Public Clients/p' | grep -B1 -B2 -e 'Private Servers'| grep -e ' open  '| awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/ntpmonlistport.txt" % (a, b)
        os.system(monlisthost)
        os.system(monlistport)
    except Exception as e:
        print(e)

def ntpfilechange():
    b = ('ntpinstances')

    os.chdir(b)

    try:
        with open("ntpinfohost.txt") as xh:
            with open('ntpinfoport.txt') as yh:
                with open("finalntpinfo.txt","w") as zh:
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
        with open("ntpmonlisthost.txt") as xh:
            with open('ntpmonlistport.txt') as yh:
                with open("finalntpmonlist.txt","w") as zh:
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
        df1 = pd.read_csv('finalntpinfo.txt', names=['Network Time Protocol (NTP) Mode 6 Scanner'])
        df2 = pd.read_csv('finalntpmonlist.txt', names=['NTP Monlist Enabled'])
        result = pd.concat([df1,df2], axis=1)
        result.to_csv("finalntpfile.csv", index=False)
    except Exception as e:
        print(e)

    os.chdir('..')


def ntpscreenshots():
    b = ("ntpinstances")
    os.chdir(b)
    c = ("ntpscreenshot")
    os.mkdir(c)

    try:
        f = open("ntpinfohost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("ntpinfoport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sU -sV -Pn -n -p %s --script ntp-info %s && scrot -u -d 2 %s/Network Time Protocol (NTP) Mode 6 Scanner.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)

    try:
        f = open("ntpmonlisthost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("ntpmonlistport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sU -sV -Pn -n -p %s --script ntp-monlist %s && scrot -u -d 2 %s/NTP Monlist Enabled.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)


    os.chdir('..')