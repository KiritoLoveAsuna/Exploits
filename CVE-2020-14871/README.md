# CVE 2020-14871 Solaris exploit

This is a basic ROP based exploit for CVE 2020-14871. CVE 2020-14871 is a vulnerability in Sun Solaris systems.
The actual vulnerability is a classic stack-based buffer overflow located in the PAM parse_user_name function. 
It can be reached by manipulating SSH client settings to force Keyboard-Interactive authentication to prompt 
for the username, an attacker can then pass unlimited input to the PAM parse_user_name function. At 512 bytes
the username buffer will overflow. It was discovered in the wild as part of a compromise assesment performed 
by mandiant, where it was used as the initial exploit to gain entry to a system.

More info here:
https://www.mandiant.com/resources/critical-buffer-overflow-vulnerability-in-solaris-can-allow-remote-takeover

This version was developed using sun-solaris 10 on VMWare, and tested on a bare-metal production machine. The
location on stack may vary based on versions of libpam. This version worked for me. You may have success by
spraying the base address, as crashing the exploited ssh process is without consequence.

The exploit will execute shell commands on the system. In the version provided, it will create a python based
reverse shell and execute it with 'disown'.


