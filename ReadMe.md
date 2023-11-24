NOTE : Screenshots will only work if you run in your own linux machine, screenshot are not possible on Portianer

install scrot for screenshots in your linux

"apt-get update && apt-get install scrot"

Note: Keep the Testssl in the root Directory (/root/testssl)

------------------------Keep the Testssl in the root directory.-----------------------------

1.Copy the Folder in your Linux Machine
2.Update the Python to Python > 3.5
3.Run the following command : 
	"python3 -m pip install -r requirements.txt" && "python -m pip install -r requirements.txt"
4. keep the Nessus CSV file in the "Automation" folder
5. After that, Run the Following Command:
      "Python3 automation.py"
6. It will ask for the number of CSV OUTPUT. (CSV OUTPUT: these are nessus csv output files).
7. then, It will ask for csv file name
8. Write the name of the csv file. eg - output.csv
9. Wait for testssl and other serivces to get completed then just collect the csv file in Instances folder for SSL and other services Related Findings (SSH, FTP, NTP). 





----------------------------------------------------------------------------------------

Currently can test and triage for ssh,ftp,ntp,ssl.

dns, ike, http-headers will give later on, there is some confusion will nesssus plugins.