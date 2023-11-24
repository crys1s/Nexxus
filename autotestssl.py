import os
import pandas as pd
import csv




def testssl():
    print("---------------------------SSL FILES AND OUTPUTS----------------------")
    a = ('sslresults')
    os.mkdir(a)
    # a = "abcdefgh"
    b =('sslinstances')
    os.mkdir(b)
    command = "bash /root/testssl.sh/./testssl.sh --parallel --mode parallel --quiet -iL ssl.txt -oL %s/output.log -oH %s/output.html" % (a , a)
    os.system(command)

    try:
        command2 = "bash /root/testssl.sh/./testssl.sh --parallel --mode parallel -t=smtp -iL sslsmtp.txt -oL %s/outputsmtp.log -oH %s/outputsmtps.html" % (a, a)
        os.system(command2)

    except Exception as e:
        print(e)




def extract():
    a = ('sslresults')
    b =('sslinstances')

    SSLV2 = "cat %s/output*.log | sed -n -e '/Start/p' -e '/SSLv2/p' | grep -B1 'offered (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/SSLV2.txt" % (a, b)
    os.system(SSLV2)

    TLSV1 = "cat %s/output*.log | sed -n -e '/Start/p' -e '/TLS 1 /p' | grep -B1 'offered' | grep -B1 '(deprecated)' | grep 'Start' | awk '{print $6}' > %s/TLSV1.txt" % (a, b)
    os.system(TLSV1)

    SSLV3 = "cat %s/output*.log | sed -n -e '/Start/p' -e '/SSLv3 /p' | grep -B1 'offered (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/SSLV3.txt" % (a, b)
    os.system(SSLV3)

    Signature = "cat %s/output*.log | sed -n -e '/Start/p' -e '/Signature Algorithm /p' | grep -B1 -E '(SHA1|MD5)' | grep 'Start' | awk '{print $6}' > %s/Signature.txt" % (a, b)
    os.system(Signature)

    # Keysize = "cat %s/output*.log | sed -n -e '/Start/p' -e '/Server key size /p' | grep -B1 -E '(1024|512|256)' | grep 'Start' | awk '{print $6}'" % (a) 
    Keysize = "cat %s/output*.log | sed -n -e '/Start/p' -e '/Server key size  /p' -e '/Signature Algorithm /p' | grep -B1 -A1 -E '(SHA1 with RSA|MD5 with RSA)' | grep -B1 -B2 -E '(1024|256|512)' | grep 'Start' | awk '{print $6}' > %s/keysize.txt"  % (a, b)
    os.system(Keysize)

    CertExpired = "cat %s/output*.log | sed -n -e '/Start/p' -e '/Certificate Validity (UTC)/p' | grep -B1 'expired' | grep 'Start' | awk '{print $6}' > %s/CertExpired.txt" % (a, b)
    os.system(CertExpired)

    Certabttoexpire = "cat %s/output*.log | sed -n -e '/Start/p' -e '/Certificate Validity (UTC)/p' | grep -B1 'expires' | grep 'Start' | awk '{print $6}' > %s/Certabttoexpire.txt" % (a, b)
    os.system(Certabttoexpire)

    CCSInjection = "cat %s/output*.log | sed -n -e '/Start/p' -e '/(CVE-2014-0224) /p' | grep -B1 'VULNERABLE' | grep -B1 '(NOT ok)' | grep 'Start' | awk '{print $6}' > %s/CCSInjection.txt" % (a, b)
    os.system(CCSInjection)

    HeartBleed = "cat %s/output*.log | sed -n -e '/Start/p' -e '/(CVE-2014-0160)/p' | grep -B1 'VULNERABLE (NOT ok)' | grep -B1 'Start' | awk '{print $6}' > %s/HeartBleed.txt" % (a, b)
    os.system(HeartBleed)

    TicketBleed = "cat %s/output*.log | sed -n -e '/Start/p' -e '/(CVE-2016-9244)/p' | grep -B1 'VULNERABLE (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/TicketBleed.txt" % (a, b)
    os.system(TicketBleed)

    ROBOT = "cat %s/output*.log | sed -n -e '/Start/p' -e '/ROBOT/p' | grep -B1 'VULNERABLE (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/ROBOT.txt" % (a, b)
    os.system(ROBOT)

    SECURERENE = "cat %s/output*.log | sed -n -e '/Start/p' -e '/(RFC 5746)/p' | grep -B1 'VULNERABLE (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/SECURESERVER.txt" % (a, b)
    os.system(SECURERENE)

    SecureClient = "cat %s/output*.log | sed -n -e '/Start/p' -e '/Secure Client-Initiated Renegotiation/p' | grep -B1 'VULNERABLE (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/SECURECLIENT.txt" % (a, b)
    os.system(SecureClient)

    CRIME = "cat %s/output*.log | sed -n -e '/Start/p' -e '/CVE-2012-4929/p' | grep -B1 'VULNERABLE (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/CRIME.txt" % (a, b)
    os.system(CRIME)

    POODLE = "cat %s/output*.log | sed -n -e '/Start/p' -e '/CVE-2014-3566/p' | grep -B1 'VULNERABLE (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/POODLE.txt" % (a, b)
    os.system(POODLE)

    TLSFALLBACK = "cat %s/output*.log | sed -n -e '/Start/p' -e '/RFC 7507/p' | grep -B1 'Downgrade attack prevention NOT supported' | grep 'Start' | awk '{print $6}' > %s/TLSFALLBACK.txt" % (a, b)
    os.system(TLSFALLBACK)

    SWEET32 = "cat %s/output*.log | sed -n -e '/Start/p' -e '/CVE-2016-2183/p' | grep -B1 'VULNERABLE' | grep 'Start' | awk '{print $6}' > %s/SWEET32.txt" % (a, b)
    os.system(SWEET32)

    LOGJAM = "cat %s/output*.log | sed -n -e '/Start/p' -e '/CVE-2015-4000/p' | grep -B1 'VULNERABLE (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/LOGJAM.txt" % (a, b)
    os.system(LOGJAM)

    BEAST = "cat %s/output*.log | sed -n -e '/Start/p' -e '/CVE-2011-3389/p' | grep -B1 -e 'TLS1:' -e 'SSL3:' | grep 'Start' | awk '{print $6}' > %s/BEAST.txt" % (a, b)
    os.system(BEAST)

    RC4 = "cat %s/output*.log | sed -n -e '/Start/p' -e '/CVE-2013-2566/p' | grep -B1 'VULNERABLE (NOT ok): ' | grep 'Start' | awk '{print $6}' > %s/RC4.txt" % (a, b)
    os.system(RC4)

    ISSUER = "cat %s/output*.log | sed -n -e '/Start/p' -e '/Issuer/p' | grep -B1 'self-signed (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/SELFSIGNED.txt" % (a, b)
    os.system(ISSUER)

    Anonymous = "cat %s/output.log | sed -n -e '/Start/p' -e '/Anonymous NULL/p' | grep -B1 'offered (NOT ok)' | grep 'Start' | awk '{print $6}' > %s/Anonymous.txt" % (a, b)
    os.system(Anonymous)



def filechange():
    b =('sslinstances')
    p = "%s" % (b)
    df1 = pd.read_csv('%s/SSLV2.txt' % (p), names=['SSL v2 Supported'])
    df2 = pd.read_csv('%s/SSLV3.txt' % (p), names=['WEAK SSL-TLS CONFIGURATION[SSLV3 Supported]'])
    df3 = pd.read_csv('%s/TLSV1.txt' % (p), names=['TLSv1.0 Supported'])
    df4 = pd.read_csv('%s/BEAST.txt' % (p), names=['HTTPS BEAST Information Leakage (SSL-TLS)'])
    df5 = pd.read_csv('%s/TLSFALLBACK.txt' % (p), names=['TLS Fallback Downgrade Attack Prevention Not Supported'])
    df6 = pd.read_csv('%s/LOGJAM.txt' % (p), names=['SSL-TLS Logjam Information Leakage'])
    df7 = pd.read_csv('%s/CertExpired.txt' % (p), names=['X.509 Certificate Expired (SSL-TLS)'])
    df8 = pd.read_csv('%s/CCSInjection.txt' % (p), names=["OpenSSL 'ChangeCipherSpec' MiTM Vulnerability"])
    df9 = pd.read_csv('%s/keysize.txt' % (p), names=['X.509 Certificate Chain Contains RSA Keys Less Than 2048 Bits (SSL-TLS)'])
    df10 = pd.read_csv('%s/POODLE.txt' % (p), names=['SSL-TLS Configuration Vulnerable to POODLE'])
    df11 = pd.read_csv('%s/HeartBleed.txt' % (p), names=['OpenSSL Memory Buffer Over-read (Heartbleed)'])
    df12 = pd.read_csv('%s/CRIME.txt' % (p), names=['HTTPS/SPDY CRIME Information Leakage'])
    df13 = pd.read_csv('%s/Certabttoexpire.txt' % (p), names=['X.509 Certificate About to Expire (SSL-TLS)'])
    df14 = pd.read_csv('%s/RC4.txt' % (p), names=['Weak SSL-TLS Configuration][RC4 AND MD5 SUPPORTED]'])
    df15 = pd.read_csv('%s/ROBOT.txt' % (p), names=['ROBOTS Supported'])
    df16 = pd.read_csv('%s/SECURECLIENT.txt' % (p), names=['SSL-TLS Client-Initiated Renegotiation'])
    df17 = pd.read_csv('%s/SECURESERVER.txt' % (p), names=['SSL-TLS Insecure Renegotiation'])
    df18 = pd.read_csv('%s/SELFSIGNED.txt' % (p), names=['Self-Signed X.509 Certificate (SSL-TLS)'])
    df19 = pd.read_csv('%s/Signature.txt' % (p), names=['Weak X.509 Certificate Signature Hashing Algorithm (SSL-TLS)'])
    df20 = pd.read_csv('%s/SWEET32.txt' % (p), names=['Weak SSL-TLS Configuration[SWEET32]'])
    df21 = pd.read_csv('%s/TicketBleed.txt' % (p), names=['Ticketbleed Supported'])
    df22 = pd.read_csv('%s/Anonymous.txt' % (p), names=['Anonymous SSL-TLS Ciphers Supported'])
    result = pd.concat([df1,df2,df3,df4,df5,df6,df7,df8,df9,df10,df11,df12,df13,df14,df15,df16,df17,df18,df19,df20,df21,df22], axis=1)
    result.to_csv("%s/finalsslfile.csv" % (b), index=False)


def sslscreenshots():
    b =('sslinstances')
    os.chdir(b)
    c = ('sslscreenshots')
    os.mkdir(c)

    try:
        f = open("SSLV2.txt", "r")
        cont = f.readlines()
        fn = open("sslv2.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -p -iL sslv2.txt && scrot -u -d 2 -f "%s/SSL v2 Supported.png" """ % (c)
        os.system(clientscr)
        os.remove("sslv2.txt")

    except Exception as e:
        print(e)

    try:
        f = open("SSLV3.txt", "r")
        cont = f.readlines()
        fn = open("sslv3.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -p -iL sslv3.txt && scrot -u -d 2 -f "%s/WEAK SSL-TLS CONFIGURATION[SSLV3 Supported].png" """ % (c)
        os.system(clientscr)
        os.remove("sslv3.txt")

    except Exception as e:
        print(e)

    try:
        f = open("TLSV1.txt", "r")
        cont = f.readlines()
        fn = cont[0].rstrip()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -p %s && scrot -u -d 2 -f "%s/TLSv1.0 Supported.png" """ % (fn, c)
        os.system(clientscr)
        
    except Exception as e:
        print(e)

    try:
        f = open("Signature.txt", "r")
        cont = f.readlines()
        fn = open("sign.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -S -iL sign.txt && scrot -u -d 2 -f "%s/Weak X.509 Certificate Signature Hashing Algorithm (SSL-TLS).png" """ % (c)
        os.system(clientscr)
        os.remove("sign.txt")

    except Exception as e:
        print(e)

    try:
        f = open("keysize.txt", "r")
        cont = f.readlines()
        fn = open("ksze.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -S -iL ksze.txt && scrot -u -d 2 -f "%s/X.509 Certificate Chain Contains RSA Keys Less Than 2048 Bits (SSL-TLS).png" """ % (c)
        os.system(clientscr)
        os.remove("ksze.txt")

    except Exception as e:
        print(e)

    try:
        f = open("CertExpired.txt", "r")
        cont = f.readlines()
        fn = open("expired.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -S -iL expired.txt && scrot -u -d 2 -f "%s/X.509 Certificate Expired (SSL-TLS).png" """ % (c)
        os.system(clientscr)
        os.remove("expired.txt")

    except Exception as e:
        print(e)

    try:
        f = open("Certabttoexpire.txt", "r")
        cont = f.readlines()
        fn = open("expires.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -S -iL expires.txt && scrot -u -d 2 -f "%s/X.509 Certificate About to Expire (SSL-TLS).png" """ % (c)
        os.system(clientscr)
        os.remove("expires.txt")

    except Exception as e:
        print(e)

    try:
        f = open("CCSInjection.txt", "r")
        cont = f.readlines()
        fn = open("ccs.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL ccs.txt && scrot -u -d 2 -f "%s/OpenSSL 'ChangeCipherSpec' MiTM Vulnerability.png" """ % (c)
        os.system(clientscr)
        os.remove("ccs.txt")

    except Exception as e:
        print(e)

    try:    
        f = open("HeartBleed.txt", "r")
        cont = f.readlines()
        fn = open("bleed.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL bleed.txt && scrot -u -d 2 -f "%s/OpenSSL Memory Buffer Over-read (Heartbleed).png" """ % (c)
        os.system(clientscr)
        os.remove("bleed.txt")

    except Exception as e:
        print(e)


    try:
        f = open("TicketBleed.txt", "r")
        cont = f.readlines()
        fn = open("ticket.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL ticket.txt && scrot -u -d 2 -f "%s/Ticketbleed Supported.png" """ % (c)
        os.system(clientscr)
        os.remove("ticket.txt")

    except Exception as e:
        print(e)

    try:
        f = open("ROBOT.txt", "r")
        cont = f.readlines()
        fn = open("robot.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL robot.txt && scrot -u -d 2 -f "%s/ROBOTS Supported.png" """ % (c)
        os.system(clientscr)
        os.remove("robot.txt")

    except Exception as e:
        print(e)

    try:
        f = open("SECURESERVER.txt", "r")
        cont = f.readlines()
        fn = open("server.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL server.txt && scrot -u -d 2 -f "%s/SSL-TLS Insecure Renegotiation.png" """ % (c)
        os.system(clientscr)
        os.remove("server.txt")
    
    except Exception as e:
        print(e)

    try:    
        f = open("SECURECLIENT.txt", "r")
        cont = f.readlines()
        fn = open("client.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL client.txt && scrot -u -d 2 -f "%s/SSL-TLS Client-Initiated Renegotiation.png" """ % (c)
        os.system(clientscr)
        os.remove("client.txt")

    except Exception as e:
        print(e)

    try:
        f = open("CRIME.txt", "r")
        cont = f.readlines()
        fn = open("crime.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL crime.txt && scrot -u -d 2 -f "%s/HTTPS/SPDY CRIME Information Leakage.png" """ % (c)
        os.system(clientscr)
        os.remove("crime.txt")

    except Exception as e:
        print(e)

    try:
        f = open("POODLE.txt", "r")
        cont = f.readlines()
        fn = open("poodle.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL poodle.txt && scrot -u -d 2 -f "%s/SSL-TLS Configuration Vulnerable to POODLE.png" """ % (c)
        os.system(clientscr)
        os.remove("poodle.txt")

    except Exception as e:
        print(e)

    try:
        f = open("TLSFALLBACK.txt", "r")
        cont = f.readlines()
        fn = open("fallback.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL fallback.txt && scrot -u -d 2 -f "%s/TLS Fallback Downgrade Attack Prevention Not Supported.png" """ % (c)
        os.system(clientscr)
        os.remove("fallback.txt")
    
    except Exception as e:
        print(e)

    try:
        f = open("SWEET32.txt", "r")
        cont = f.readlines()
        fn = open("sweet32.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL sweet32.txt && scrot -u -d 2 -f "%s/Weak SSL-TLS Configuration[SWEET32].png" """ % (c)
        os.system(clientscr)
        os.remove("sweet32.txt")

    except Exception as e:
        print(e)

    try:    
        f = open("LOGJAM.txt", "r")
        cont = f.readlines()
        fn = open("logjam.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL logjam.txt && scrot -u -d 2 -f "%s/SSL-TLS Logjam Information Leakage.png" """ % (c)
        os.system(clientscr)
        os.remove("logjam.txt")

    except Exception as e:
        print(e)

    try:
        f = open("BEAST.txt", "r")
        cont = f.readlines()
        fn = open("beast.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL beast.txt && scrot -u -d 2 -f "%s/HTTPS BEAST Information Leakage (SSL-TLS).png" """ % (c)
        os.system(clientscr)
        os.remove("beast.txt")

    except Exception as e:
        print(e)

    try:
        f = open("RC4.txt", "r")
        cont = f.readlines()
        fn = open("rc4.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -U -iL rc4.txt && scrot -u -d 2 -f "%s/Weak SSL-TLS Configuration][RC4 AND MD5 SUPPORTED].png" """ % (c)
        os.system(clientscr)
        os.remove("rc4.txt")

    except Exception as e:
        print(e)

    try:    
        f = open("SELFSIGNED.txt", "r")
        cont = f.readlines()
        fn = open("selfsign.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -S -iL selfsign.txt && scrot -u -d 2 -f "%s/Self-Signed X.509 Certificate (SSL-TLS).png" """ % (c)
        os.system(clientscr)
        os.remove("selfsign.txt")

    except Exception as e:
        print(e)

    try:    
        f = open("Anonymous.txt", "r")
        cont = f.readlines()
        fn = open("anon.txt", "w")
        fn.write(cont[0])
        f.close()
        fn.close()
        clientscr = """clear && bash /root/testssl.sh/./testssl.sh --quiet -s -iL anon.txt && scrot -u -d 2 -f "%s/Anonymous SSL-TLS Ciphers Supported.png" """ % (c)
        os.system(clientscr)
        os.remove("anon.txt")

    except Exception as e:
        print(e)
    
    os.chdir("..")
    os.system("pwd")
