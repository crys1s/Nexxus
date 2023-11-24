import os
import pandas as pd
import csv
import subprocess


def sshtest():
    print("---------------------------SSH FILES AND OUTPUTS----------------------")
    a = ('sshresults')
    os.mkdir(a)
    # a = "abcdefgh"
    b = ('sshinstances')
    os.mkdir(b)

    try:
        command = "cat sshhost.txt | wc -l"
        j = int(subprocess.check_output([command], shell = True, stderr=subprocess.STDOUT))
        print(j)
        with open("id.txt", "w") as myfile:
            for i in range(1, j+1):
                myfile.write("%s\n" % i)
        myfile.close()

        with open('sshhost.txt', 'r') as host, open('sshport.txt', 'r') as port, open ('id.txt', 'r') as hostid:
            for hosts, ports, hostsid in zip(host, port, hostid):
                hosts = hosts.rstrip()
                ports = ports.rstrip()
                hostsid = hostsid.rstrip()
                command1 = "nmap -sS -sV -Pn -n -p %s -oA %s/sshoutputfor%s --script ssh2-enum-algos %s > %s/sshoutput%s.log" % (ports, a, hostsid, hosts, a, hostsid)
                command2 = "nmap -sS -sV -Pn -n -p %s -oA %s/hostkeyoutputfor%s --script ssh-hostkey %s > %s/hostkeyoutput%s.log" % (ports, a, hostsid, hosts, a, hostsid)
                os.system(command1)
                os.system(command2)

    except Exception as e:
        print(e)



def sshtriage():
    a = ('sshresults')

    b = ('sshinstances')
    
    try:
        # MACHOST = "cat %s/sshoutputf*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/hmac-/p' | grep -B1 -B2 -e 'sha1' -e 'md5' | grep -e 'Nmap scan' | awk '{print $5 " " $6}' |tr -d '()' |  sed 's/[^1-255].[^0-9].[^0-9].[^0-9]*//g' > %s/finalmachost.txt" % (a, b)
        MACHOST = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/mac-sha1/p' -e '/md5/p' -e '/-96/p' -e '/umac-64/p'| grep -B1 -B2 -e 'mac'| grep -e 'Nmap scan' | awk '{print $5}' |tr -d '()' > %s/finalmachost.txt" % (a, b)
        MACPORT = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/mac-sha1/p' -e '/md5/p' -e '/-96/p' -e '/umac-64/p'| grep -B1 -B2 -e 'mac'| grep -e ' open  '| awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/finalmacport.txt" % (a, b)
        os.system(MACHOST)
        os.system(MACPORT)

        CBCHOST = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/-cbc/p' | grep -B1 -B2 -e '-cbc' | grep 'Nmap scan' | awk '{print $5}' | tr -d '()' > %s/finalcbchost.txt" % (a, b)
        CBCPORT = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/-cbc/p' | grep -B1 -B2 -e '-cbc' | grep ' open  ' | awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/finalcbcport.txt" % (a,b)
        os.system(CBCHOST)
        os.system(CBCPORT)

        KEYXCHANGEHOST = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open /p' -e '/-sha1/p'| grep -v 'sha256' | grep -v 'sha512' | grep -B1 -B2 -e 'diffie-hellman' | grep 'Nmap scan ' | awk '{print $5}' | tr -d '()' > %s/finalkeyxchangehost.txt" % (a, b)
        KEYXCHANGEPORT = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open /p' -e '/-sha1/p' | grep -v 'sha256' | grep -v 'sha512' | grep -B1 -B2 -e 'diffie-hellman' | grep ' open  ' | awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/finalkeyxchangeport.txt" % (a, b)
        os.system(KEYXCHANGEHOST)
        os.system(KEYXCHANGEPORT)

        ARCFOURHOST = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/arcfour/p' | grep -B1 -B2 -e 'arcfour' | grep -e 'Nmap scan' | awk '{print $5}' > %s/finalarcfourhost.txt" % (a, b)
        ARCFOURPORT = "cat %s/sshoutput*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/arcfour/p' | grep -B1 -B2 -e 'arcfour' | grep -e ' open  ' | awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/finalarcfourport.txt" % (a, b)
        os.system(ARCFOURHOST)
        os.system(ARCFOURPORT)

        HOSTKEYHOST = "cat %s/hostkeyoutpu*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/(DSA)/p' -e '/(RSA)/p' | grep -B1 -B2 -E '(256|512|1024)' | grep  'Nmap scan' | awk '{print $5}' > %s/finalsshhostkeyhost.txt" % (a, b)
        HOSTKEYPORT = "cat %s/hostkeyoutpu*.log | sed -n -e '/Nmap scan /p' -e '/ open  /p' -e '/(DSA)/p' -e '/(RSA)/p' | grep -B1 -B2 -E '(256|512|1024)' | grep  ' open  ' | awk '{print $1}' | tr -d '/tcp' | tr -d '/udp' > %s/finalsshhostkeyport.txt" % (a, b)
        os.system(HOSTKEYHOST)
        os.system(HOSTKEYPORT)

    except Exception as e:
        print(e)

def sshfilechange():

    b =('sshinstances')

    os.chdir(b)

    try:
        with open("finalmachost.txt") as xh:
            with open('finalmacport.txt') as yh:
                with open("finalmac.txt","w") as zh:
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
        with open("finalcbchost.txt") as xh:
            with open('finalcbcport.txt') as yh:
                with open("finalcbc.txt","w") as zh:
                    xlines = xh.readlines()
                    ylines = yh.readlines()
                    for line1, line2 in zip(xlines, ylines):
                        zh.write("{}:{}\n".format(line1.rstrip(), line2.rstrip()))
    except Exception as e:
        print(e)
        
    try:
        with open("finalkeyxchangehost.txt") as xh:
            with open('finalkeyxchangeport.txt') as yh:
                with open("finalkeyxchange.txt","w") as zh:
                    xlines = xh.readlines()
                    ylines = yh.readlines()
                    for line1, line2 in zip(xlines, ylines):
                        zh.write("{}:{}\n".format(line1.rstrip(), line2.rstrip()))
    except Exception as e:
        print(e)

    try:    
        with open("finalarcfourhost.txt") as xh:
            with open('finalarcfourport.txt') as yh:
                with open("finalarcfour.txt","w") as zh:
                    xlines = xh.readlines()
                    ylines = yh.readlines()
                    for line1, line2 in zip(xlines, ylines):
                        zh.write("{}:{}\n".format(line1.rstrip(), line2.rstrip()))
    except Exception as e:
        print(e)

    try:    
        with open("finalsshhostkeyhost.txt") as xh:
            with open('finalsshhostkeyport.txt') as yh:
                with open("finalhostkey.txt","w") as zh:
                    xlines = xh.readlines()
                    ylines = yh.readlines()
                    for line1, line2 in zip(xlines, ylines):
                        zh.write("{}:{}\n".format(line1.rstrip(), line2.rstrip()))
    except Exception as e:
        print(e)

    try:
        df1 = pd.read_csv('finalmac.txt', names=['SSH Weak MAC Algorithms Enabled'])
        df2 = pd.read_csv('finalcbc.txt', names=['SSH Server CBC Mode Ciphers Enabled'])
        df3 = pd.read_csv('finalkeyxchange.txt', names =['Weak SSH Key Exchange Algorithm'])
        df4 = pd.read_csv('finalarcfour.txt', names= ['SSH Server CBC Mode Ciphers Enabled and RC4 mode Ciphers Enabled'])
        df5 = pd.read_csv('finalhostkey.txt', names=['Weak SSH Host Keys Algorithm'])
        result = pd.concat([df1,df2,df3,df4,df5], axis=1)
        result.to_csv("finalsshfile.csv", index=False)
    except Exception as e:
        print(e)

    os.chdir('..')

def sshscreenshots():
    b = ("sshinstances")
    os.chdir(b)
    c = ("sshscreenshots")
    os.mkdir(c)

    try:
        f = open("finalarcfourhost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("finalarcfourport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sS -sV -Pn -n -p %s --script ssh2-enum-algos %s  | grep -e "Nmap " -e "PORT" -e "open " -e "arcfour" && scrot -u -d 2 %s/SSH Server CBC Mode Ciphers Enabled and RC4 mode Ciphers Enabled.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)
 
    try:
        f = open("finalcbchost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("finalcbcport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sS -sV -Pn -n -p %s --script ssh2-enum-algos %s | grep -e "Nmap " -e "PORT" -e "open " -e "cbc"&& scrot -u -d 2 %s/SSH Server CBC Mode Ciphers Enabled.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)

    try:
        f = open("finalmachost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("finalmacport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sS -sV -Pn -n -p %s --script ssh2-enum-algos %s | grep -e "Nmap " -e "PORT" -e "open " -e "mac" && scrot -u -d 2 %s/SSH Weak MAC Algorithms Enabled.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)

    try:
        f = open("finalkeyxchangehost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("finalkeyxchangeport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear & nmap -sS -sV -Pn -n -p %s --script ssh2-enum-algos %s | grep -e "Nmap " -e "PORT" -e "open " -e "diffie-hellman" && scrot -u -d 2 %s/Weak SSH Key Exchange Algorithm.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)

    try:
        f = open("finalsshhostkeyhost.txt", "r")
        cont = f.readlines()

        h = cont[0].rstrip()
        
        f = open("finalsshhostkeyport.txt", "r")
        cont = f.readlines()
        p = cont[0].rstrip()

        clientscr = """clear && nmap -sS -sV -Pn -n -p %s --script ssh-hostkey %s && scrot -u -d 2 %s/Weak SSH Host Keys Algorithm.png """ % (p, h, c)
        os.system(clientscr)

    except Exception as e:
        print(e)


    os.chdir('..')

    

