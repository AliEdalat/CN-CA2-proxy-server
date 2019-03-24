import thread
import socket
import json
import sys
import base64
import time


#********* CONSTANT VARIABLES *********
PENDINGNUM = 50 # how many pending connections queue will hold
MAX_DATA_RECV = 999999  # max number of bytes we receive at once


class ProxyServer(object):
	def __init__(self, configFilePath):
		super(ProxyServer, self).__init__()
		self.config = json.loads(open(configFilePath).read())
		try:
			host = ''
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.s.bind((host, self.config['port']))
			self.s.listen(PENDINGNUM)
			print self.config['restriction']
			print "Proxy Server Running on ",host,":",self.config['port']
		except socket.error, (value, message):
			if self.s:
				self.s.close()
			print "Could not open socket:", message
			sys.exit(1)

	def run(self):
		while True:
			conn, client_addr = self.s.accept()
			thread.start_new_thread(self.proxyThread, (conn, client_addr))
		self.s.close()


	def sendMail(self, msg):
		msg = "\r\n " + msg
		endmsg = "\r\n.\r\n"
		mailserver = ("smtp.mailtrap.io", 25) #Fill in start #Fill in end
		clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		clientSocket.connect(mailserver)
		recv = clientSocket.recv(1024)
		recv = recv.decode()
		print("Message after connection request:" + recv)
		if recv[:3] != '220':
			print('220 reply not received from server.')
		heloCommand = 'EHLO mailtrap.com\r\n'
		clientSocket.send(heloCommand.encode())
		recv1 = clientSocket.recv(1024)
		recv1 = recv1.decode()
		print("Message after EHLO command:" + recv1)
		if recv1[:3] != '250':
			print('250 reply not received from server.')

		#Info for username and password
		username = "29bdcadbf25359"
		password = "cfe325ded6e45f"
		base64_str = ("\x00"+username+"\x00"+password).encode()
		base64_str = base64.b64encode(base64_str)
		authMsg = "AUTH PLAIN ".encode()+base64_str+"\r\n".encode()
		clientSocket.send(authMsg)
		recv_auth = clientSocket.recv(1024)
		print(recv_auth.decode())

		mailFrom = "MAIL FROM:<test@mailtrap.com>\r\n"
		clientSocket.send(mailFrom.encode())
		recv2 = clientSocket.recv(1024)
		recv2 = recv2.decode()
		print("After MAIL FROM command: "+recv2)
		rcptTo = "RCPT TO:<ali.edalat@ut.ac.ir>\r\n"
		clientSocket.send(rcptTo.encode())
		recv3 = clientSocket.recv(1024)
		recv3 = recv3.decode()
		print("After RCPT TO command: "+recv3)
		data = "DATA\r\n"
		clientSocket.send(data.encode())
		recv4 = clientSocket.recv(1024)
		recv4 = recv4.decode()
		print("After DATA command: "+recv4)
		subject = "Subject: testing my client\r\n\r\n" 
		clientSocket.send(subject.encode())
		date = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
		date = date + "\r\n\r\n"
		clientSocket.send(date.encode())
		clientSocket.send(msg.encode())
		clientSocket.send(endmsg.encode())
		recv_msg = clientSocket.recv(1024)
		print("Response after sending message body:"+recv_msg.decode())
		quit = "QUIT\r\n"
		clientSocket.send(quit.encode())
		recv5 = clientSocket.recv(1024)
		print(recv5.decode())
		clientSocket.close()

	def parseRequest():
		pass

	def proxyThread(self, conn, client_addr):
		while True:
			request = conn.recv(MAX_DATA_RECV)
			if not request:
				continue
			lines = request.split('\r\n')
			first_line = lines[0]
			if self.config['restriction']['enable']:
				for x in lines:
					print x
					if len(x.split(' ')) > 1:
						header = x.split(' ')[0]
						value = x.split(' ')[1]
						for y in self.config['restriction']['targets']:
							# print y['URL']
							if header == 'Host:' and value == y['URL']:
								if y['notify']:
									self.sendMail(request)		
								print '<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'
								print value
								conn.close()
								return

			if self.config['privacy']['enable']:
				for x in range(0,len(lines)):
					if len(lines[x].split(' ')) > 0:
						header = lines[x].split(' ')[0]
						if header == 'User-Agent:':
							lines[x] = header + ' ' + self.config['privacy']['userAgent'].encode('utf-8')
					lines[x] = lines[x] + '\r\n'
					# print lines[x]
			else:
				for x in range(0,len(lines)):
					lines[x] = lines[x] + '\r\n'
			# get url
			print first_line
			url = first_line.split(' ')[1]

			http_pos = url.find("://")          # find pos of ://
			if (http_pos==-1):
				temp = url
			else:
				temp = url[(http_pos+3):]       # get the rest of url
		    
			port_pos = temp.find(":")           # find the port pos (if any)

			# find end of web server
			webserver_pos = temp.find("/")
			if webserver_pos == -1:
				webserver_pos = len(temp)

			# print temp[webserver_pos:]
			version = first_line.split(' ')[2][:len(first_line.split(' ')[2])-2]+'0'
			newRequest = first_line.split(' ')[0] + ' ' + temp[webserver_pos:] + ' ' + first_line.split(' ')[2] + '\r\n'
			newRequest = newRequest + ''.join(lines[1:])
			print newRequest

			webserver = ""
			port = -1
			if (port_pos==-1 or webserver_pos < port_pos):      # default port
				port = 80
				webserver = temp[:webserver_pos]
			else:       # specific port
				port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
				webserver = temp[:port_pos]

			try:
				# create a socket to connect to the web server
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
				s.connect((webserver, port))
				# print ("".join(request.split('\n')[1:]))
				# s.send(request)         # send request to webserver
				s.send(newRequest)

				while 1:
					# receive data from web server
					data = s.recv(MAX_DATA_RECV)
		            
					if (len(data) > 0):
						# send to browser
						conn.send(data)
					else:
						break
				s.close()
				print first_line.split(' ')[2]
				if first_line.split(' ')[2] == 'HTTP/1.0':
					conn.close()
					return
			except socket.error, (value, message):
				if s:
					s.close()
				if conn:
					conn.close()
				# self.printout("Peer Reset",first_line,client_addr)
				sys.exit(1)    


proxy = ProxyServer('config.json')
proxy.run()