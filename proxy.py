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

class Request(object):
	def __init__(self, request, privacy, userAgent):
		super(Request, self).__init__()
		self.request = request
		self.header = {}
		lines = request.split('\r\n')
		first_line = lines[0]

		for x in range(0,len(lines)):
			if len(lines[x].split(' ')) > 1:
				header = lines[x].split(' ')[0]
				value = lines[x].split(' ')[1]
				if header == 'User-Agent:' and privacy:
					lines[x] = header + ' ' + userAgent
					value = userAgent
				if header == 'Proxy-Connection:':
					lines[x] = ''
					continue
				self.header[header] = value
			lines[x] = lines[x] + '\r\n'

		url = first_line.split(' ')[1]
		http_pos = url.find("://")
		if (http_pos==-1):
			temp = url
		else:
			temp = url[(http_pos+3):]
		port_pos = temp.find(":")
		webserver_pos = temp.find("/")
		if webserver_pos == -1:
			webserver_pos = len(temp)
		version = first_line.split(' ')[2][:len(first_line.split(' ')[2])-1]+'0'
		self.newRequest = first_line.split(' ')[0] + ' ' + temp[webserver_pos:] + ' ' + version + '\r\n'
		self.newRequest = self.newRequest + ''.join(lines[1:])
		self.webserver = ""
		self.port = -1
		if (port_pos==-1 or webserver_pos < port_pos):
			self.port = 80
			self.webserver = temp[:webserver_pos]
		else:
			self.port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
			self.webserver = temp[:port_pos]

	def getNewRequest(self):
		return self.newRequest

	def getWebserver(self):
		return self.webserver

	def getPort(self):
		return self.port

	def getValue(self, key):
		if not key in list(self.header.keys()):
			return ''
		return self.header[key]

		

class ProxyServer(object):
	def __init__(self, configFilePath):
		super(ProxyServer, self).__init__()
		self.config = json.loads(open(configFilePath).read())
		# TODO: add thread number with %(threadName)s to format
		logging.basicConfig(filename='myproxy.log', format='[%(asctime)s] %(threadName)s %(message)s', datefmt='%d/%b/%Y:%H:%M:%S', level=logging.DEBUG)
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
			self.logger('Accepted a request from client!')
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
		self.logger("Message after connection request:" + recv)
		if recv[:3] != '220':
			self.logger('220 reply not received from server.')
		heloCommand = 'EHLO mailtrap.com\r\n'
		clientSocket.send(heloCommand.encode())
		recv1 = clientSocket.recv(1024)
		recv1 = recv1.decode()
		self.logger("Message after EHLO command:" + recv1)
		if recv1[:3] != '250':
			self.logger('250 reply not received from server.')

		#Info for username and password
		username = "29bdcadbf25359"
		password = "cfe325ded6e45f"
		base64_str = ("\x00"+username+"\x00"+password).encode()
		base64_str = base64.b64encode(base64_str)
		authMsg = "AUTH PLAIN ".encode()+base64_str+"\r\n".encode()
		clientSocket.send(authMsg)
		recv_auth = clientSocket.recv(1024)
		self.logger(recv_auth.decode())

		mailFrom = "MAIL FROM:<test@mailtrap.com>\r\n"
		clientSocket.send(mailFrom.encode())
		recv2 = clientSocket.recv(1024)
		recv2 = recv2.decode()
		self.logger("After MAIL FROM command: "+recv2)
		rcptTo = "RCPT TO:<ali.edalat@ut.ac.ir>\r\n"
		clientSocket.send(rcptTo.encode())
		recv3 = clientSocket.recv(1024)
		recv3 = recv3.decode()
		self.logger("After RCPT TO command: "+recv3)
		data = "DATA\r\n"
		clientSocket.send(data.encode())
		recv4 = clientSocket.recv(1024)
		recv4 = recv4.decode()
		self.logger("After DATA command: "+recv4)
		subject = "Subject: testing my client\r\n\r\n" 
		clientSocket.send(subject.encode())
		date = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
		date = date + "\r\n\r\n"
		clientSocket.send(date.encode())
		clientSocket.send(msg.encode())
		clientSocket.send(endmsg.encode())
		recv_msg = clientSocket.recv(1024)
		self.logger("Response after sending message body:"+recv_msg.decode())
		quit = "QUIT\r\n"
		clientSocket.send(quit.encode())
		recv5 = clientSocket.recv(1024)
		self.logger(recv5.decode())
		clientSocket.close()

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
			self.logger('Client sent request to proxy with headers:')
			self.logger('connect to [127.0.0.1] from localhost [%s] %s', client_addr[0], client_addr[1])
			self.logger('\n----------------------------------------------------------------------\n' + request +\
				'\n----------------------------------------------------------------------\n')

			currentRequest = Request(request, self.config['privacy']['enable'], self.config['privacy']['userAgent'].encode('utf-8'))
			if self.config['restriction']['enable']:
				for y in self.config['restriction']['targets']:
					if currentRequest.getValue('Host:') == y['URL']:
						if y['notify']:
							self.sendMail(request)
						conn.close()
						return

			try:
				# create a socket to connect to the web server
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
				s.connect((currentRequest.getWebserver(), currentRequest.getPort()))
				self.logger('Proxy opening connection to server %s [%s]... Connection opened.', currentRequest.getWebserver(), socket.gethostbyname(currentRequest.getWebserver()))
				s.send(currentRequest.getNewRequest())
				self.logger('Proxy sent request to server [%s] with headers:', currentRequest.getWebserver())
				self.logger('\n----------------------------------------------------------------------\n' + currentRequest.getNewRequest() +\
				'\n----------------------------------------------------------------------\n')
				res = ''
				while 1:
					# receive data from web server
					data = s.recv(MAX_DATA_RECV)
					if (len(data) > 0):
						res += data
					else:
						break
				s.close()
				self.logger('Server [%s] sent response to proxy with headers:', currentRequest.getWebserver())
				self.logger('\n----------------------------------------------------------------------\n' + res +\
				'\n----------------------------------------------------------------------\n')
				# if temp[webserver_pos:] == '/':
				# 	print res
				newRes = self.inject(res)
				conn.send(newRes)
				self.logger('Proxy sent response to client [%s] port: %s with headers:', client_addr[0], client_addr[1])
				self.logger('\n----------------------------------------------------------------------\n' + newRes +\
				'\n----------------------------------------------------------------------\n')
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