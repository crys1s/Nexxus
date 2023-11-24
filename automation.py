#-------------------------as converting the dataframe back into some csv file---------------------------
import csv
import pandas as pd
import os as d
from libnmap.process import NmapProcess
import csv
import sys
import os
import autotestssl as autot
import ssh as spy
import ftp as ftp
import ntp as ntp
import cvetest as cve
import http as http
import ldap as ldap
import info as info
import ssl as ssl
import rdp as rdp
import dns as dns
import ike as ike



number = int(input("Enter the number of CSV files to be parsed: "))


for i in range(1, number+1):
    csv1_file = pd.read_csv(input("CSV file name: "))
    
    path = ('Assessment[%d]' % i)
    os.mkdir(path)
    os.chdir(path)
    csv1_file.to_csv("input.csv", sep = ",", index=False)
    os.chdir('..')


for i in range(1, number+1):

    path = ('Assessment[%d]' % i)
    os.chdir(path)
    os.system("pwd")

    def nmaptesting():
        # for nmap
        csv_file = pd.read_csv("input.csv", usecols=[4, 6])
        
        #removing boug value such as port =0
        indexname = csv_file[csv_file["Port"] == 0].index
        csv_file.drop(indexname, inplace=True)

        #SORTING THE PORT
        csv_file.sort_values(["Port"], axis=0, ascending=[True], inplace=True)

        #removing duplicates
        csv_file.drop_duplicates(inplace=True)

        #imported back to csv
        csv_file.to_csv("sorted.csv", sep=",", index=False)
        csv_file = pd.read_csv("sorted.csv", usecols=[0], skiprows=1)
        csv2_file = pd.read_csv("sorted.csv", usecols=[1], skiprows=1)
        csv_file.to_csv("host.csv", sep=",", index=False)
        csv2_file.to_csv("port.csv", sep=",", index=False)

        # for nmap
        with open("nmaphost.txt", "w") as my_output_file:
            with open("host.csv", "r") as my_input_file:
                [my_output_file.write(" ".join(row)+'\n')
                for row in csv.reader(my_input_file)]
        
        my_output_file.close()
        # print(a_string)
    # df2['capt'] = df2['capt'].str.get(0)close()

        with open("nmap.txt", "w") as my_output_file2:
            with open("port.csv", "r") as my_input_file2:
                [my_output_file2.write(" ".join(row)+'\n')
                for row in csv.reader(my_input_file2)]
                
        my_output_file.close()

        # d.remove("sorted.csv")
        # d.remove("host.csv")
        # d.remove("port.csv")




    def ssltesting():

        #sslcsvoutput for plugin ID 56984
        sslcsv_file = pd.read_csv("input.csv", usecols=[0, 4, 6])
        sslcsvsmtp_file = pd.read_csv("input.csv", usecols=[0, 4, 6])

        #  Removing data of other plugin ID (ONLY FOR SSL)
        indexnamessl = sslcsv_file[sslcsv_file["Plugin ID"] != 56984].index
        sslcsv_file.drop(indexnamessl, inplace=True)

        indexnamesslsmtp = sslcsvsmtp_file[sslcsvsmtp_file["Plugin ID"] != 42088].index
        sslcsvsmtp_file.drop(indexnamesslsmtp, inplace=True)

        print (sslcsv_file.empty)
        #ssl imported back to csv
        if not sslcsv_file.empty:
            sslcsv_file.to_csv("ssl.csv", sep=",", index=False)
            sslcsv_file = pd.read_csv("ssl.csv", usecols=[1, 2], skiprows=1)
            d.remove("ssl.csv")
            sslcsv_file.to_csv("ssl.csv", sep=",", index=False)

            # for ssl

            with open("ssl.txt", "w") as my_output_file3:
                with open("ssl.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
            my_output_file3.close()

            d.remove("ssl.csv")

        if not sslcsvsmtp_file.empty:
            sslcsvsmtp_file.to_csv("sslsmtp.csv", sep=",", index=False)
            sslcsvsmtp_file = pd.read_csv("sslsmtp.csv", usecols=[1, 2], skiprows=1)
            d.remove("sslsmtp.csv")
            sslcsvsmtp_file.to_csv("sslsmtp.csv", sep=",", index=False)

            with open("sslsmtp.txt", "w") as my_output_file4:
                with open("sslsmtp.csv", "r") as my_input_file4:
                    [my_output_file4.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file4)]

            my_output_file4.close()

            d.remove("sslsmtp.csv")

        autot.testssl()
        autot.extract()
        autot.filechange()
        autot.sslscreenshots()

        

    def sshtesting():
        #sshcsvoutput
        sshcsv_file = pd.read_csv("input.csv", usecols=[0, 4, 6])

        # Removing data of other plugin ID (ONLY FOR SSH)
        indexnamessh = sshcsv_file[(sshcsv_file["Plugin ID"] != 10267) & (sshcsv_file["Plugin ID"] != 70657) & (sshcsv_file["Plugin ID"] != 10881)].index
        sshcsv_file.drop(indexnamessh, inplace=True)

        #ssh imported back to csv
        sshcsv_file.to_csv("ssh.csv", sep=",", index=False)
        sshcsv_file = pd.read_csv("ssh.csv", usecols=[1,2])
        sshcsv_file.drop_duplicates(inplace=True)
        print(sshcsv_file.empty)
        if not sshcsv_file.empty:
            sshcsv_file.to_csv("ssh.csv", sep=",", index=False)
            sshcsvhost_file = pd.read_csv("ssh.csv", usecols=[0], skiprows=1)
            sshcsvport_file = pd.read_csv("ssh.csv", usecols=[1], skiprows=1)
            sshcsvhost_file.to_csv("sshhost.csv", sep=",", index=False)
            sshcsvport_file.to_csv("sshport.csv", sep=",", index=False)

            # # For SSH
            with open("sshhost.txt", "w") as my_output_file:
                with open("sshhost.csv", "r") as my_input_file:
                    [my_output_file.write(" ".join(row)+'\n')
                    for row in csv.reader(my_input_file)]
            my_output_file.close()

            with open("sshport.txt", "w") as my_output_file2:
                with open("sshport.csv", "r") as my_input_file2:
                    [my_output_file2.write(" ".join(row)+'\n')
                    for row in csv.reader(my_input_file2)]
            my_output_file.close()

            spy.sshtest()
            spy.sshtriage()
            spy.sshfilechange()
            spy.sshscreenshots()
    

    def ftptesting():
        #ftp csv output
        ftpcsv_file = pd.read_csv("input.csv", usecols=[0, 4, 6])

        # Removing data of other plugin ID (ONLY FOR FTP)
        indexnameftp = ftpcsv_file[(ftpcsv_file["Plugin ID"] != 10092)].index
        ftpcsv_file.drop(indexnameftp, inplace=True)

        #ftp imported back to csv
        ftpcsv_file.to_csv("ftp.csv", sep=",", index=False)
        ftpcsv_file = pd.read_csv("ftp.csv", usecols=[1,2])
        ftpcsv_file.drop_duplicates(inplace=True)
        print(ftpcsv_file.empty)
        if not ftpcsv_file.empty:
            ftpcsv_file.to_csv("ftp.csv", sep=",", index=False)
            ftpcsvhost_file = pd.read_csv("ftp.csv", usecols=[0], skiprows=1)
            ftpcsvport_file = pd.read_csv("ftp.csv", usecols=[1], skiprows=1)
            ftpcsvhost_file.to_csv("ftphost.csv", sep=",", index=False)
            ftpcsvport_file.to_csv("ftpport.csv", sep=",", index=False)

            # # For FTP
            with open("ftphost.txt", "w") as my_output_file:
                with open("ftphost.csv", "r") as my_input_file:
                    [my_output_file.write(" ".join(row)+'\n')
                    for row in csv.reader(my_input_file)]
            my_output_file.close()

            with open("ftpport.txt", "w") as my_output_file2:
                with open("ftpport.csv", "r") as my_input_file2:
                    [my_output_file2.write(" ".join(row)+'\n')
                    for row in csv.reader(my_input_file2)]
            my_output_file.close()

            ftp.ftptest()
            ftp.ftptriage()
            ftp.ftpfilechange()
            ftp.ftpscreenshots()



    def ntptesting():
        #ntp csv output
        ntpcsv_file = pd.read_csv("input.csv", usecols=[0, 4, 6])

        # Removing data of other plugin ID (ONLY FOR NTP)
        indexnamentp = ntpcsv_file[(ntpcsv_file["Plugin ID"] != 10884) & (ntpcsv_file["Plugin ID"] != 97861)].index
        ntpcsv_file.drop(indexnamentp, inplace=True)

        #ntp imported back to csv
        ntpcsv_file.to_csv("ntp.csv", sep=",", index=False)
        ntpcsv_file = pd.read_csv("ntp.csv", usecols=[1,2])
        ntpcsv_file.drop_duplicates(inplace=True)
        print(ntpcsv_file.empty)
        if not ntpcsv_file.empty:
            ntpcsv_file.to_csv("ntp.csv", sep=",", index=False)
            ntpcsvhost_file = pd.read_csv("ntp.csv", usecols=[0], skiprows=1)
            ntpcsvport_file = pd.read_csv("ntp.csv", usecols=[1], skiprows=1)
            ntpcsvhost_file.to_csv("ntphost.csv", sep=",", index=False)
            ntpcsvport_file.to_csv("ntpport.csv", sep=",", index=False)

            # # For NTP
            with open("ntphost.txt", "w") as my_output_file:
                with open("ntphost.csv", "r") as my_input_file:
                    [my_output_file.write(" ".join(row)+'\n')
                    for row in csv.reader(my_input_file)]
            my_output_file.close()

            with open("ntpport.txt", "w") as my_output_file2:
                with open("ntpport.csv", "r") as my_input_file2:
                    [my_output_file2.write(" ".join(row)+'\n')
                    for row in csv.reader(my_input_file2)]
            my_output_file.close()

            ntp.ntptest()
            ntp.ntptriaging()
            ntp.ntpfilechange()
            ntp.ntpscreenshots()


    def httptesting():
                #http csv output

        httpcsv_file = pd.read_csv("input.csv", usecols=[0,4,6])

        # Removing the duplicate values
        httpcsv_file.drop_duplicates(inplace=True)


        # Removing data of other plugin ID (Only for HTTP)

        indexnamehttp = httpcsv_file[(httpcsv_file["Plugin ID"] != 10107) & (httpcsv_file["Plugin ID"] != 20089) & (httpcsv_file["Plugin ID"] != 84502)].index
        httpcsv_file.drop(indexnamehttp, inplace=True)


        #http imported back to csv
        if not httpcsv_file.empty:
            httpcsv_file.to_csv("http.csv", sep=",", index=False)
            httpcsv_file = pd.read_csv("http.csv", usecols=[1, 2], skiprows=1)
            os.remove("http.csv")
            httpcsv_file.to_csv("http.csv", sep=",", index=False)

                # for http
            with open("http_input.txt", "w") as my_output_file3:
                with open("http.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
                
            my_output_file3.close()
            
            os.remove("http.csv")   

            command1 = "cp http_input.txt ../"
            os.system(command1)


            http.httptest()
            http.httpfilearrangement()

        else:
            print("\n\n\tNo Targets present for HTTP Testing")



    def ssltesting2():
        #sslcsvoutput for plugin ID 56984
        sslcsv_file = pd.read_csv("input.csv", usecols=[0, 4, 6])

        # Removing the duplicate values
        sslcsv_file.drop_duplicates(inplace=True)
        
            #  Removing data of other plugin ID (ONLY FOR SSL)
        indexnamessl = sslcsv_file[sslcsv_file["Plugin ID"] != 56984].index
        sslcsv_file.drop(indexnamessl, inplace=True)


        # print (sslcsv_file.empty)
            #ssl imported back to csv
        if not sslcsv_file.empty:
            sslcsv_file.to_csv("ssl1.csv", sep=",", index=False)
            sslcsv_file = pd.read_csv("ssl1.csv", usecols=[1, 2], skiprows=1)
            os.remove("ssl1.csv")
            sslcsv_file.to_csv("ssl1.csv", sep=",", index=False)

                # for ssl

            with open("ssl_input.txt", "w") as my_output_file3:
                with open("ssl1.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
            my_output_file3.close()

            os.remove("ssl1.csv")
    
            command1 = "cp ssl_input.txt ../"
            os.system(command1)

            ssl.ssltest()
            ssl.sslfilearrangement()

        else:
            print("\n\n\tNo Targets present for SSL testing")


    def dnstesting():
        #dnscsvoutput for plugin ID 11002
        dnscsv_file = pd.read_csv("input.csv", usecols=[0, 4, 6])

        # Removing the duplicate values
        dnscsv_file.drop_duplicates(inplace=True)

            #  Removing data of other plugin ID (ONLY FOR DNS)
        indexnamedns = dnscsv_file[dnscsv_file["Plugin ID"] != 11002].index
        dnscsv_file.drop(indexnamedns, inplace=True)



        # print (dnscsv_file.empty)
            #dns imported back to csv
        if not dnscsv_file.empty:
            dnscsv_file.to_csv("dns.csv", sep=",", index=False)
            dnscsv_file = pd.read_csv("dns.csv", usecols=[1, 2], skiprows=1)
            os.remove("dns.csv")
            dnscsv_file.to_csv("dns.csv", sep=",", index=False)

                # for dns

            with open("dns_input.txt", "w") as my_output_file3:
                with open("dns.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
            my_output_file3.close()

            os.remove("dns.csv")    

            command1 = "cp dns_input.txt ../"
            os.system(command1)

            dns.dnstest()
            dns.dnsfilearrangement()
        else:
            print("\n\n\tNo Targets present for DNS testing")

    


    def infotesting():
        #infocsvoutput for plugin IDs of info_disclose
        infocsv_file = pd.read_csv("input.csv", usecols=[0, 4, 6])
            
        # Removing the duplicate values
        infocsv_file.drop_duplicates(inplace=True)      
    
        #  Removing data of other plugin ID (ONLY FOR Info disclose)
        indexnameinfo = infocsv_file[(infocsv_file["Plugin ID"] != 22319) & (infocsv_file["Plugin ID"] != 26197) & (infocsv_file["Plugin ID"] != 25342) & (infocsv_file["Plugin ID"] != 10719) & (infocsv_file["Plugin ID"] != 77026) & (infocsv_file["Plugin ID"] != 10891)].index
        infocsv_file.drop(indexnameinfo, inplace=True)


        # print (infocsv_file.empty)
            #dns imported back to csv
        if not infocsv_file.empty:
            infocsv_file.to_csv("info.csv", sep=",", index=False)
            infocsv_file = pd.read_csv("info.csv", usecols=[1, 2], skiprows=1)
            os.remove("info.csv")
            infocsv_file.to_csv("info.csv", sep=",", index=False)

                    # for dns

            with open("info_input.txt", "w") as my_output_file3:
                with open("info.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                        for row in csv.reader(my_input_file3)]
            my_output_file3.close()

            os.remove("info.csv")


            command1 = "cp info_input.txt ../"
            os.system(command1)

            info.information_disclosure_test()
            info.information_disclosure_filearrangement()
        else:
            print("\n\n\tNo Targets present for Testing for Information Disclosure")    


    def cvetesting():
        #cvecsvoutput for plugin IDs of CVEs
        cvecsv_file = pd.read_csv("input.csv", usecols=[0,4,6])

        # Removing the duplicate values
        cvecsv_file.drop_duplicates(inplace=True)
        

        # Removing data other plugin ID
        indexnamecve = cvecsv_file[(cvecsv_file["Plugin ID"] != 55976) & (cvecsv_file["Plugin ID"] != 73533) & (cvecsv_file["Plugin ID"] != 82828) & (cvecsv_file["Plugin ID"] != 96906) & (cvecsv_file["Plugin ID"] != 97210)].index
        cvecsv_file.drop(indexnamecve, inplace=True)        
        
        # print(cvecsv_file.empty)
        #cve imported back to csv

        if not cvecsv_file.empty:
            cvecsv_file.to_csv("cve.csv", sep=",", index=False)
            cvecsv_file = pd.read_csv("cve.csv", usecols=[1,2], skiprows=1)
            os.remove("cve.csv")
            cvecsv_file.to_csv("cve.csv",sep=",", index=False)

            # for cves

            with open("cve_input.txt", "w") as my_output_file3:
                with open("cve.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
            my_output_file3.close()
            os.remove("cve.csv")


            command1 = "cp cve_input.txt ../"
            os.system(command1)
            cve.cvetest()
            cve.cvefilearrangement()
        else:
            print("\n\n\tNo Targets for CVE Testing present")


    def ldaptesting():
        #ldapcsvoutput for plugin IDs of LDAPtest
        ldapcsv_file = pd.read_csv("input.csv", usecols=[0,4,6])

        # Removing the duplicate values
        ldapcsv_file.drop_duplicates(inplace=True)

        # Removing data other plugin ID
        indexnameldap = ldapcsv_file[ldapcsv_file["Plugin ID"] != 20870].index
        ldapcsv_file.drop(indexnameldap, inplace=True)

        
        # print(ldapcsv_file.empty)
        #ldap imported back to csv

        if not ldapcsv_file.empty:
            ldapcsv_file.to_csv("ldap.csv", sep=",", index=False)
            ldapcsv_file = pd.read_csv("ldap.csv", usecols=[1,2], skiprows=1)
            os.remove("ldap.csv")
            ldapcsv_file.to_csv("ldap.csv",sep=",", index=False)

            # for ldap

            with open("ldap_input.txt", "w") as my_output_file3:
                with open("ldap.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
            my_output_file3.close()
            os.remove("ldap.csv")


            command1 = "cp ldap_input.txt ../"
            os.system(command1)
            ldap.ldaptest()
            ldap.ldapfilearrangement()
        else:
            print("\n\n\tNo Targets for LDAP Testing present")


    def rdptesting():
        #rdpcsvoutput for plugin IDs of RDPtest
        rdpcsv_file = pd.read_csv("input.csv", usecols=[0,4,6])

        # Removing the duplicate values
        rdpcsv_file.drop_duplicates(inplace=True)

        # Removing data other plugin ID
        indexnamerdp = rdpcsv_file[rdpcsv_file["Plugin ID"] != 18405].index
        rdpcsv_file.drop(indexnamerdp, inplace=True)



        # print(rdpcsv_file.empty)
        #rdp imported back to csv

        if not rdpcsv_file.empty:
            rdpcsv_file.to_csv("rdp.csv", sep=",", index=False)
            rdpcsv_file = pd.read_csv("rdp.csv", usecols=[1,2], skiprows=1)
            os.remove("rdp.csv")
            rdpcsv_file.to_csv("rdp.csv",sep=",", index=False)

            # for rdp

            with open("rdp_input.txt", "w") as my_output_file3:
                with open("rdp.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
            my_output_file3.close()
            os.remove("rdp.csv")


            command1 = "cp rdp_input.txt ../"
            os.system(command1)
            rdp.rdptest()
            rdp.rdpfilearrangement()
        else:
            print("\n\n\tNo Targets for RDP encryption Testing present")
            
            
    def iketesting():
        #ikecsvoutput for plugin ID of IKEtest
        ikecsv_file = pd.read_csv("input.csv", usecols=[0,4,6])
        
        # Removing the duplicate values
        ikecsv_file.drop_duplicates(inplace=True)
        
        # Removing data other plugin ID
        indexnameike = ikecsv_file[ikecsv_file["Plugin ID"] != 62694].index
        ikecsv_file.drop(indexnameike, inplace=True)
        
        #ike imported back to csv
        if not ikecsv_file.empty:
            ikecsv_file.to_csv("ike.csv", sep=",", index=False)
            ikecsv_file = pd.read_csv("ike.csv", usecols=[1,2], skiprows=1)
            os.remove("ike.csv")
            ikecsv_file.to_csv("ike.csv",sep=",", index=False)

            # for ike

            with open("ike_input.txt", "w") as my_output_file3:
                with open("ike.csv", "r") as my_input_file3:
                    [my_output_file3.write(":".join(row)+'\n')
                    for row in csv.reader(my_input_file3)]
            my_output_file3.close()
            os.remove("ike.csv")


            command1 = "cp ike_input.txt ../"
            os.system(command1)
            ike.ike_scan_test()
            ike.ikefilearrangement()
        else:
            print("\n\n\tNo Targets for IKE-SCAN Testing present")


    nmaptesting()
    ssltesting()
    sshtesting()
    ftptesting()
    ntptesting()
    httptesting()
    ssltesting2()
    dnstesting()
    infotesting()
    cvetesting()
    ldaptesting()
    rdptesting()
    iketesting()

    os.chdir("..")
    os.system("pwd")
    os.system("rm *input.txt")