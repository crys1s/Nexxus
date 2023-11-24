#!/bin/bash

ifile=$1
rm -rf *.log &> /dev/null

#SSL - Client initiated renegotiation 
ssl_cir(){
rm -rf Vuls-ssl-cir.txt
echo -e "\e[93m[+] Checking For Client initiated renegotiation (56984)\e[0m"
while IFS= read -r line; do
tar=$(echo "$line" | cut -d ":" -f 2)

for i in {1..16}; do (echo "R"); sleep 0.75; done | openssl s_client -connect  $line &> r_$tar.log
if cat r_$tar.log | grep ":err" &> /dev/null
then
echo -e "\e[32m[-] $line => Not Vulnerable\e[0m"
else
echo -e "\e[31m[+] $line => Vulnerable\e[0m" && echo "$line" >> Vuls-ssl-cir.txt
fi
rm -rf r_$tar.log
done < $ifile
}


#SSL - heartbleed
ssl_hb(){
rm -rf Vuls-ssl-hb.txt
echo -e "\n\n\e[93m[+] Checking For Heartbleed (56984)\e[0m"
while IFS= read -r tar; do
	h=$(echo "$tar" | cut -d ":" -f 1)
	p=$(echo "$tar" | cut -d ":" -f 2)
        if nmap -Pn -p $p --script ssl-heartbleed $h | grep "State: VULNERABLE"
                then "$tar is Vulnerable to OpenSSL HeartBleed" && echo "$tar" >> Vuls-ssl-hb.txt
        else
                echo "$tar is not Vulnerable"
        fi
done < $ifile
}


#SSL - ROBOTS Vulnerabilities
ssl_robots(){
rm -rf Vuls-ssl-robots.txt
echo -e "\n\n\e[93m[+] Checking For ROBOTS Vulnerabilities (56984)\e[0m"
while IFS= read -r tar; do
	h=$(echo "$tar" | cut -d ":" -f 1)
        echo -e "\e[32m[+] $tar\e[0m"
        a=$(robot-detect $h)
        echo -e "\n\e[33m======================================================================================================\e[0m\n"
        echo -e "$a"
        
         if echo  "$a" | grep -E "NOT VULNERABLE|Server does not seem to allow connections with TLS_RSA|There seems to be no TLS on this host/port|[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]|There seems to be no TLS on this host/port." &> /dev/null
               then echo -e "$tar is not Vulnerable\n"
        else
                echo -e "\e[31m$tar \t Vulnerable\e[0m\n" && echo "$tar" >> Vuls-ssl-robots.txt
        fi
done < $ifile
}


#main
ssl_cir | tee ssl.log
ssl_hb | tee -a ssl.log
ssl_robots | tee -a ssl.log
