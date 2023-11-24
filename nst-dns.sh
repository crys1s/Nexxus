#!/bin/bash

ifile=$1
rm -rf *.tmp &> /dev/null
rm -rf Vuls-DNS-CS.txt &> /dev/null

#DNS - Cache Snoop
dns_cs(){
while IFS= read -r tar; do
	h=$(echo "$tar" | cut -d ':' -f 1)
	p=$(echo "$tar" | cut -d ':' -f 2)
        a=$(nmap -sU -Pn -p $p --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=nonrecursive' $h)
        echo -e "$a"

        if echo "$a" | grep ': 0 of 100' &> /dev/null; then
            echo -e "\n\e[32m[-] $tar Is Not Vulnerable\e[0m\n"

        else
                echo -e "\n\e[31m[+] $tar Is Vulnerable\e[0m\n" && echo "$tar" >> Vuls-DNS-CS.txt 
        fi
done < $ifile
}


#DNS - Zone transfer 
dns_zt(){
while IFS= read -r tar;
  do 
    h=$(echo "$tar" | cut -d ':' -f 1)
    a=$(dig ns @8.8.8.8 $h +short | sed 's/\.$//');
        for i in $a; 
          do 
            dig axfr @$i $h | if grep -i 'Transfer failed\|network unreachable\|connection reset' &> /dev/null; 
                then echo -e "\e[32m[-] $h <- $i ->\t Is Not Vulnerable\e[0m"; 
                else echo -e "\e[31m[+] $h <- $i ->\t Is Vulnerable\e[0m" && echo "$tar" | sort -u >> tmp-DNS-ZT.txt; fi &
                          done
        
wait 

done < $ifile
}

Aadd(){
cat tmp-DNS-ZT.txt | sort -u > Vuls-DNS-ZT.txt
rm -rf tmp-DNS-ZT.txt &> /dev/null
}

#main
dns_cs | tee dns.log
#dns_zt | tee -a dns.log
#Aadd