#This code relies on the  beauitfulsoup and requests library
#If you do not have these libraries, the code WILL NOT WORK 
#I reccomend pip for installing them

import urllib
import BeautifulSoup
import time
import requests
import socket
from contextlib import closing
import subprocess
import sys
from datetime import datetime
import os 


#Will be used to count number of exploits/vulnerabilities.
exploitNum = 0 
vulnNum = 0
dirNum = 0

#Used for checking whether wordpress is being used 
wordpress = False

#Function to check if website is returning connection code
def checkAccess(request): 
	if request.status_code == 200:
		return True
	else: 
		return False

#Function to check indexing on a directory at the host name
def checkIndexing(host, dirToCheck): 
	
	indexing = False 
	#Request the path then save its contents to readPath
	requestPath = requests.get(host + "/" + dirToCheck + "/")
	readPath = urllib.urlopen(host + "/" + dirToCheck + "/").read().decode('utf-8')
	
	#Check if site is open, then check for indexing
	if requestPath.status_code == 200:
		
		#Checks if generic indexing page is there 
		if "Index of" in readPath: 
			print("- VULNERABILITY - Indexing on /" + dirToCheck + "/")
			indexing = True
		else: 
			print dirToCheck + " is open and returning status code 200"
		
		#Checks if wordpress is being used	
		if "wp-" in dirToCheck: 
			wordpress = True
	
	
	return indexing 
		
			

#Function for checking indexing on robots.txt directories
def checkIndexingRobots(host, dirToCheck): 
	indexing = False 
	requestPath = requests.get(host + "/" + dirToCheck + "/")
	
	#Set readPath to content on page being checked
	try: 
		readPath = urllib.urlopen(host + "/" + dirToCheck + "/").read().decode('utf-8')
	except:
		return False
	
	#Check if path is reachable, then check if its being indexed 
	if requestPath.status_code == 200:
		if "Index of" in readPath: 
			print("	+ VULNERABILITY - Indexing on /" + dirToCheck + "/")
			indexing = True
	return indexing 
		
				
	




    


banner = "---------------------------------------------"







print "\nSylvia Exploit Scanner v1.01\nWritten by Aiden Calvert" 
print banner


url = raw_input("\nEnter a URL or IP:\n> ")



#Cut http/https out of the URL string, for checking purposes
resolved = True 
if url[:8] == "https://":
	urlIp = url[8:]
	
elif url[:7] == "http://":
	urlIp = url[7:]
	
else:
	resolved = False 
	urlIp = "Unresolvable"
	
	
#Checks to see what the IP is and saves it to websiteIP
if resolved == False: 
	websiteIp = "Unresolvable"  
else: 
	websiteIp = socket.gethostbyname(urlIp)
		
	
#Check if site can be connected to
try:
	requestSite = requests.get(url) 
except:
	print "Website refusing connections, did you enter the URL correctly?"
	sys.exit()
	
	
	
#Checks what server site is running on 
try:
	response = urllib.urlopen(url)
	serverType = response.headers['Server']
except: 
	serverType = "Unresolvable"
	
websiteIp = socket.gethostbyname(urlIp)


time.sleep(1)


#Displays Info on target site/ip
print(banner)
print("IP: " + websiteIp)
print("Hostname: " + url) 
print("Server: " + serverType) 
print(banner)

	


time.sleep(1)
print "Scanning for directory indexing..." 


#Check indexing on common directories
directoriesToCheck = ["img", "css", "admin", "wp-content", 
					"wp-includes", "wp-content/uploads", "wp-content/css", 
					"wp-conent/js", "images", "wp-login"]
	
for direc in directoriesToCheck: 
	if checkIndexing(url, direc):
		vulnNum = vulnNum + 1 
		dirNum = dirNum + 1 
		
		
	

wordpressLogin = requests.get(url + "/wp-login.php")

if wordpressLogin.status_code == 200 or wordpress == True: 
	print "- Site running on Wordpress template"
	vulnNum = vulnNum + 1
	if wordpressLogin.status_code == 200: 
		print "- Wordpress login found on " + url +  "/wp-login.php" 
		
time.sleep(1) 
	
print banner
	
print "Scanning for CGI..."
		
	
#Sets conditional booleans and requests cgi-bin and sys
requestCgiBin = requests.get(url + "/cgi-bin/")
requestCgiSys = requests.get(url + "/cgi-sys/")

cgiDetected = False
cgiVuln = False

	

#Checks if CGI-BIN 
if requestCgiBin.status_code == 200 or requestCgiBin.status_code == 403: 
	
	print("- CGI-BIN detected and returning code " + str(requestCgiBin.status_code))
	cgiDetected = True
	
	requestHtmlScript = requests.get(url + "/cgi-bin/htmlscript")
	
	#Check for HTMLSCRIPT vulnerability on CGI
	if checkAccess(requestHtmlScript):
		print("	+ CGI VULNERABILITY - HtmlScript found, this could be used for possible exploitation.")
		vulnNum = vulnNum + 1
		cgiVuln = True
	
	requestDumpEnv = requests.get(url + "/cgi-bin/dumpenv") 
		
	#Check for DumpEnv vulnerability
	if checkAccess(requestDumpEnv):
		print("	+ CGI VULNERABILITY - DumpEnv found, can reveal info on server.")
		vulnNum = vulnNum + 1
		cgiVuln = True
		
	requestScriptDir = requests.get(url + "/cgi-bin/scripts")
	
	#Check for /cgi-bin/scripts indexability
	if checkAccess(requestScriptDir):
		print("	+ EXPLOIT - /cgi-bin/scripts/ may be indexable and/or readable!")
		exploitNum = exploitNum + 1
		cgiVuln = True
	
	requestCounter = requests.get(url + "/cgi-bin/counterfiglet/")
	
	if checkAccess(requestCounter): 
		print("	+ CGI VULNERABILITY - CounterFiglet accessible, possible hazard.")
		vulnNum = vulnNum + 1
	 
	
	
	
	
if cgiDetected == True and cgiVuln == False: 
	print("	+ No CGI Vulnerabilities found on CGI-BIN.") 


time.sleep(1)

#Check CGI-SYS
cgiVuln = False
if requestCgiSys.status_code == 200 or requestCgiSys.status_code == 403: 
	print("- CGI-SYS detected and returning code " + str(requestCgiSys.status_code))
	cgiDetected = True 
	requestHtmlScript = requests.get(url + "/cgi-sys/htmlscript")
	
	#Check for HTMLSCRIPT vulnerability on CGI
	if checkAccess(requestHtmlScript):
		print("	+ CGI VULNERABILITY - HtmlScript found, this could be used for possible exploitation.")
		vulnNum = vulnNum + 1
		cgiVuln = True
	
	requestDumpEnv = requests.get(url + "/cgi-sys/dumpenv") 
		
	#Check for DumpEnv vulnerability
	if checkAccess(requestDumpEnv):
		print("	+ CGI VULNERABILITY - DumpEnv found, can reveal info on server.")
		vulnNum = vulnNum + 1
		cgiVuln = True
		
	requestScriptDir = requests.get(url + "/cgi-sys/scripts")
	
	#Check for /cgi-bin/scripts indexability
	if checkAccess(requestScriptDir):
		print("	+ EXPLOIT - /cgi-sys/scripts/ may be indexable and/or readable!")
		exploitNum = exploitNum + 1
		cgiVuln = True
	
	requestCounter = requests.get(url + "/cgi-sys/counterfiglet/")
	
	if checkAccess(requestCounter): 
		print("	+ CGI VULNERABILITY - CounterFiglet accessible, possible hazard.")
		vulnNum = vulnNum + 1
		cgiVuln = True
		
		
#Checks if any vulns have been detected 
if cgiDetected == True and cgiVuln == False: 
	print("	+ No CGI Vulnerabilities found on CGI-SYS.")
	
	
	
#Checks if any CGI was detected, if not, it continues program
if cgiDetected == False: 
	print("- No CGI Detected. Skipping these steps.") 

print banner




requestRobotsTxt = requests.get(url + "/robots.txt") 


#Checks if robots.txt exists, and requests if user would like to see the contents
if checkAccess(requestRobotsTxt):
		 
	#Downloads robots.txt
	#Converts it to readable text
	print("- Downloading robots.txt...")
	with open('robots.txt','wb') as f:
		f.write(urllib.urlopen(url + "/robots.txt").read())
		f.close()
	print("- Download Complete.")
	
	
	with open('robots.txt', 'r') as f:
		first_line_robots = f.readline()
			
	#Reads robots.txt and saves it to variable readRobots
	robots = urllib.urlopen(url + "/robots.txt")
	readRobots = robots.read().decode('utf-8') 
		
	#Formats robots.txt to attempt to only have directory names
	newString = readRobots.replace("Allow:", "")
	newString = readRobots.replace("\n", "")
	newString = readRobots.replace("User-agent: *", "")
	newString = newString.replace("Disallow:", "") 
	newString = newString.replace(first_line_robots, "")
	newString = newString.replace(" ", "") 
		
			
		
	tempList = [] 
	#Cycles through formatted robots.txt
	for char in newString:
		#Adds characters of directory name to tempList 
		if char != "\n": 
			tempList.append(char)
		else: 
			#Joins directory name into string
			tempDir = ''.join(tempList)
			tempDir = str(tempDir)
			#Clear list and start over if not a valid link 
			try: 
				if tempDir[0] != "/": 
					tempList = []
					continue
			#Error catching if string is nothing
			except IndexError: 
				tempList = []
				continue
						
						
			#Tries connecting with formatted directory, if it doesnt work, clear list and move on	
			try: 
				dirConnect = requests.get(url + tempDir) 
			except: 
				tempList = [] 
				continue
		
			#Prints out status code and checks if indexing is available on link
			#Will only check indexing if directory exists (i.e not 404ing) 
					
					
			#Wont display URL if its 404ing
			if dirConnect.status_code == 404: 
				tempList = []		
				continue 
			print("- " + tempDir + " returning status code " + str(dirConnect.status_code))
			#Checks indexing on directories
			if dirConnect.status_code == 200: 
				checkIndexing(url,tempDir)
			tempList = [] 
				
				
				
else: 
	print " - Robots.txt not found. Skipping this step..."
	

#Removes robots.txt from current directory
os.remove("robots.txt") 
		
		
		

print banner			
print "Scan completed.\n" 
print str(exploitNum) + " exploits detected." 
print str(vulnNum) + " vulnerabilities detected."
print str(dirNum) + " directories scanned."  	
