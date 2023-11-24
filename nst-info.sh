#!/bin/bash

ifile=$1


#Checking For MEMChache (26197)
mcache(){
rm -rf Vuls-memcached-info.txt
echo -e "\e[93m[+] Checking For MEMChache (26197)\e[0m"
while IFS= read -r tar; do
        h=$(echo "$tar" | cut -d ":" -f 1)
        p=$(echo "$tar" | cut -d ":" -f 2)
   if nmap -Pn -p $p --script memcached-info $h | grep memcache | grep open
        then "$tar is Vulnerable and leaking Memcache Info" && echo "$tar" >> Vuls-memcached-info.txt
   else 
        echo "$tar is not Vulnerable" 
   fi
done < $ifile
} 


#Checking For MySql (10719)
msql(){
rm -rf Vuls-mysql-info.txt
echo -e "\n\n\e[93m[+] Checking For MySql (10719)\e[0m"
while IFS= read -r tar; do
        h=$(echo "$tar" | cut -d ":" -f 1)
        p=$(echo "$tar" | cut -d ":" -f 2)
        a=$(nmap -Pn -sV -sC -p $p $h)
        if echo "$a" | grep 'Version: ' &> /dev/null; then
          echo -e "\e[31m[+] $tar Is Vulnerable\e[0m"
          echo -e "$a\n" && echo "$tar" >> Vuls-mysql-info.txt
        else
          echo -e "\e[32m[-] $tar Is Not Vulnerable\e[0m"
          echo "$a\n"
        fi
done < $ifile 
}


#Checking For RPC Info (22319)
rpci(){
rm -rf Vuls-rpc-info.txt
echo -e "\n\n\e[93m[+] Checking For RPC Info (22319)\e[0m"
while IFS= read -r tar; do
        h=$(echo "$tar" | cut -d ":" -f 1)
        p=$(echo "$tar" | cut -d ":" -f 2)
   if nmap -Pn -sV $h -p $p | grep rpcbind | grep open
        then "$tar is Vulnerable" && echo "$tar" >> Vuls-rpc-info.txt
   else 
        echo "$tar is not Vulnerable"
   fi
done < $ifile
}


#Checking For XMPP Info (25342)
xmppi(){
rm -rf Vuls-xmpp-info.txt
echo -e "\n\n\e[93m[+] Checking For XMPP Info (25342)\e[0m"
while IFS= read -r tar; do
        h=$(echo "$tar" | cut -d ":" -f 1)
        p=$(echo "$tar" | cut -d ":" -f 2)
        a=$(nmap -Pn -sV -sC -p $p $h)
        if echo "$a" | grep 'xmpp-info: ' &> /dev/null; then
          echo -e "\e[31m[+] $tar Is Vulnerable\e[0m"
          echo -e "$a\n" && echo "$tar" >> tee Vuls-xmpp-info.txt
        else
          echo -e "\e[32m[-] $tar Is Not Vulnerable\e[0m"
          echo "$a\n"
        fi
done < $ifile
}


#main
mcache | tee info.log
msql | tee -a info.log
rpci | tee -a info.log
xmppi | tee -a info.log

