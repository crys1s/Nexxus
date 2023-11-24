#!/bin/bash

inmain=$1
ifile=./i-http.tmp

rfresh(){
rm -rf *.tmp &> /dev/null
}

#checking for alive hosts
http_x(){
echo -e "\e[93m[+] Checking For Alive Hosts\e[0m"
while IFS= read -r tar;
	do 
	h=$(echo "$tar" | cut -d ":" -f 1)
	p=$(echo "$tar" | cut -d ":" -f 2)
	echo "$h" | ~/go/bin/httpx -ports $p -silent | tee -a i-http.tmp
	done < $inmain
}

#HTTP header - HSTS
http_hsts(){
echo -e "\n\n\e[93m[+] Checking For HSTS (10107)\e[0m"
rm -rf Vuls-http-hsts.txt &> /dev/null
while IFS= read -r tar 
  do
    if curl -k1sI $tar | grep -i 'strict-transport-security:' &> /dev/null
      then
        echo -e "$tar \t=> HSTS Enabled"
    else 
        echo -e "$tar \t=> HSTS Not Enabled" && echo "$tar" | sed -E 's/^\s*.*:\/\///g' >> Vuls-http-hsts.txt
    fi
  done < $ifile
}


#HTTP header - verbose server banner
http_vsb(){
rm -rf Vuls-http-vsb.txt &> /dev/null
echo -e "\n\n\e[93m[+] Checking For Verbose Server Banner (10107)\e[0m"
s_keys="Server: X-Powered-By:"
while IFS= read -r tar; 
    do
     for Ftr in $s_keys;
     do
        a=$(curl -Isk1 "$tar" | grep "${Ftr}" | cut -d " " -f 2)

        if [[ ! -z "$a" ]];
          then
            if [[ $a =~ [0-9] ]];
              then 
                echo -e "$tar \t=> $a" && echo "$tar" | sed -E 's/^\s*.*:\/\///g' >> Vuls-http-vsb.txt
                fi
        else
          echo -e "$tar Not Vulnerable"
        fi
     done
   done < $ifile
}


#HTTP Header - vulnerable software/server version
http_sv(){
rm -rf Vuls-http-sv.txt &> /dev/null
echo -e "\n\n\e[93m[+] Checking Vulnerable Software/Server Version (10107)\e[0m"
while IFS= read -r tar; do

a=$(wappalyzer $tar --pretty | grep -B 2 '"version":' | grep -v 'confidence')
b=$(echo "$a" | grep -B 2 '[0-9]')

if echo "$b" | grep '[0-9]' &> /dev/null
        then
                echo -e "\e[31m[+] $tar Is Vulnerable\e[0m" && echo -e "$a\n" && echo "$tar" | sed -E 's/^\s*.*:\/\///g' >> Vuls-http-sv.txt
else
        echo -e "\e[32m[-] $tar Is Not Vulnerable\e[0m"
        echo -e "$a\n"
fi 
done < $ifile
}


#F5 BIG-IP Cookie Information Disclosure
http_bigip(){
rm -rf Vuls-http-bigip.txt &> /dev/null
echo -e "\n\n\e[93m[+] Checking For F5 BIG-IP Cookie Information Disclosure\e[0m"
while IFS= read -r tar; do
        a=$(curl -ksI1 "$tar" | grep -i "BIGipServer" | cut -d "=" -f 2 | cut -d ";" -f 1)
        if echo "$a" | grep '.' &> /dev/null; then 
          echo -e "$tar \t=> Vulnerbale" && echo "$tar" | sed -E 's/^\s*.*:\/\///g' >> Vuls-http-bigip.txt
        else
          echo -e "$tar \t=> Not Vulnerable"
        fi 
done < $ifile
}


#main
rfresh

http_x | tee http.log

http_hsts | tee -a http.log

http_vsb | tee -a http.log

http_sv | tee -a http.log

http_bigip | tee -a http.log

rfresh
