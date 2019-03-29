import thread
import socket
import json
import sys
import base64
import time
import logging
import zlib
import gzip
import StringIO
from bs4 import BeautifulSoup
#********* CONSTANT VARIABLES *********
PENDINGNUM = 50 # how many pending connections queue will hold
MAX_DATA_RECV = 999999  # max number of bytes we receive at once

class Response(object):
	def __init__(self, response):
		super(Response, self).__init__()
		self.response = response
		self.header = {}
		self.responseHeader = ''
		self.responseData = ''
		# TODO: read response header to dict :)
		lines = response.split('\r\n')
		for x in range(0,len(lines)):
			parts = lines[x].split(' ')
			if len(parts) > 1:
				if parts[1].find(';') >= 0:
					parts[1] = parts[1][:parts[1].find(';')]
				self.header[parts[0]] = parts[1]
			if lines[x] == '':
				self.responseData = ''.join(lines[x+1:])
				self.responseHeader += lines[x] + '\r\n'
				break
			self.responseHeader += lines[x] + '\r\n'

	def hasContentType(self, value):
		if not 'Content-Type:' in list(self.header.keys()):
			return True
		return self.header['Content-Type:'] == value

	def deCompress(self):
		if not 'Content-Encoding:' in list(self.header.keys()):
			return
		order = self.header['Content-Encoding:'] + ','
		compresslist = order.split(' ')
		compresslist = reversed(compresslist)
		for x in compresslist:
			if x == 'deflate,':
				self.responseData = zlib.decompress(self.responseData)
			elif x == 'gzip,':
				# self.responseData = zlib.decompress(self.responseData, 16+zlib.MAX_WBITS)
				self.responseData = gzip.GzipFile(fileobj=StringIO.StringIO(self.responseData)).read()

	def compress(self):
		if not 'Content-Encoding:' in list(self.header.keys()):
			return
		order = self.header['Content-Encoding:'] + ','
		compresslist = order.split(' ')
		for x in compresslist:
			if x == 'deflate,':
				self.responseData = zlib.compress(self.responseData)
			elif x == 'gzip,':
				out = StringIO.StringIO()
				try:
					gzip.GzipFile(fileobj=out, mode="w").write(self.responseData)
					self.responseData = out.getvalue()
				except Exception as e:
					gzip.GzipFile(fileobj=out, mode="w").write(self.responseData.encode('utf-8'))
					self.responseData = out.getvalue()

	def injectNav(self, text):
		soup = BeautifulSoup(self.responseData, 'html.parser')
		new_tag = soup.new_tag('nav', id='MyFnavbar')
		new_tag['class'] = new_tag.get('class', []) + ['navbar', 'navbar-expand-lg', 'fixed-top', 'navbar-light', 'bg-light', 'shadow-sm']
		new_tag.string = '' + text
		if soup.body is not None:
			soup.body.insert(0, new_tag)
			self.responseData = soup.prettify().encode('utf-8')

	def getResponseText(self):
		return self.responseHeader + self.responseData



class ProxyServer(object):
	def __init__(self, configFilePath):
		super(ProxyServer, self).__init__()
		self.config = json.loads(open(configFilePath).read())
		logging.basicConfig(filename='myproxy.log', format='[%(asctime)s] %(message)s', datefmt='%d/%b/%Y:%H:%M:%S', level=logging.DEBUG)
		self.logger('Proxy launched')
		try:
			host = ''
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.logger('Creating server socket...')
			self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.s.bind((host, self.config['port']))
			self.logger('Binding socket to port %s...', self.config['port'])
			self.s.listen(PENDINGNUM)
			self.logger('Listening for incoming requests...\n')
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

	def logger(self, text, *args, **kwargs):
		if self.config['logging']['enable']:
			logging.info(text, *args, **kwargs)

	def inject(self, response):
		current = Response(response)
		if self.config['HTTPInjection']['enable'] and current.hasContentType('text/html'):
			current.deCompress()
			current.injectNav('' + self.config['HTTPInjection']['post']['body'].encode('utf-8'))
			current.compress()
			return current.getResponseText()
		return response

	def proxyThread(self, conn, client_addr):
		while True:
			request = conn.recv(MAX_DATA_RECV)
			if not request:
				continue
			lines = request.split('\r\n')
			first_line = lines[0]
			# print first_line
			if self.config['restriction']['enable']:
				for x in lines:
					if len(x.split(' ')) > 1:
						header = x.split(' ')[0]
						value = x.split(' ')[1]
						for y in self.config['restriction']['targets']:
							if header == 'Host:' and value == y['URL']:
								if y['notify']:
									self.sendMail(request)
								conn.close()
								return

			if self.config['privacy']['enable']:
				for x in range(0,len(lines)):
					if len(lines[x].split(' ')) > 0:
						header = lines[x].split(' ')[0]
						if header == 'User-Agent:':
							lines[x] = header + ' ' + self.config['privacy']['userAgent'].encode('utf-8')
						if header == 'Proxy-Connection:':
							lines[x] = ''
							continue
					lines[x] = lines[x] + '\r\n'
			else:
				for x in range(0,len(lines)):
					if len(lines[x].split(' ')) > 0:
						header = lines[x].split(' ')[0]
						if header == 'Proxy-Connection:':
							lines[x] = ''
							continue
					lines[x] = lines[x] + '\r\n'
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

			version = first_line.split(' ')[2][:len(first_line.split(' ')[2])-1]+'0'
			newRequest = first_line.split(' ')[0] + ' ' + temp[webserver_pos:] + ' ' + version + '\r\n'
			newRequest = newRequest + ''.join(lines[1:])
			# print newRequest
			# print ''
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
				s.send(newRequest)
				res = ''
				while 1:
					# receive data from web server
					data = s.recv(MAX_DATA_RECV)
					if (len(data) > 0):
						res += data
					else:
						break
				s.close()
				# if temp[webserver_pos:] == '/':
				# 	print res
				conn.send(self.inject(res))
				# if first_line.split(' ')[2] == 'HTTP/1.0':
				# 	conn.close()
				# 	return
				conn.close()
				return
			except socket.error, (value, message):
				if s:
					s.close()
				if conn:
					conn.close()
				sys.exit(1)    


proxy = ProxyServer('config.json')
proxy.run()