import thread
import socket
import json
import sys

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
			self.s.bind((host, self.config['port']))
			self.s.listen(PENDINGNUM)
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


	def proxyThread(self, conn, client_addr):
		request = conn.recv(MAX_DATA_RECV)
		first_line = request.split('\n')[0]
		# get url
		url = first_line.split(' ')[1]
		# print url
		# for i in range(0,len(BLOCKED)):
		# 	if BLOCKED[i] in url:
		# 		printout("Blacklisted",first_line,client_addr)
		# 		conn.close()
		# 		sys.exit(1)

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

		print url[webserver_pos+1:]

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
			s.send(request)         # send request to webserver

			while 1:
				# receive data from web server
				data = s.recv(MAX_DATA_RECV)
	            
				if (len(data) > 0):
					# send to browser
					conn.send(data)
				else:
					break
			s.close()
			conn.close()
		except socket.error, (value, message):
			if s:
				s.close()
			if conn:
				conn.close()
			self.printout("Peer Reset",first_line,client_addr)
			sys.exit(1)    


proxy = ProxyServer('config.json')
proxy.run()