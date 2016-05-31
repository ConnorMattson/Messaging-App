import socket
import os
from threading import *

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('127.0.0.1', 3600))
serversocket.listen(10)
usersOnline = {}

print ('*****************************************************************************\n\nserver running...')

class client(Thread):

	def __init__(self, socket, adress):
		Thread.__init__(self)
		self.socket = socket
		self.address = address
		user = ''
		self.start()

	def run(self):
		while True:
			dataSize = self.socket.recv(4).decode()
			data = self.socket.recv(int(dataSize)).decode()
			print (self.address, data)
			splitData = data.split(' ')
			messageType = splitData[0]

			# when recieve close message
			if splitData[0] == 'messageTypeClose':
				try:
					usersOnline.pop(user, None)
				except UnboundLocalError:
					pass
				break

			# when recieve logout message
			if splitData == 'messageTypeLogout':
				usersOnline.pop(user, None)
				user = ''

			# when recieve message
			elif splitData[0] == 'messageTypeMessage':
				messageFrom = splitData[1]
				messageTo = splitData[2]
				messageData = ' '.join(splitData[3:])

				if messageTo in usersOnline:
					messageLength = str(len(data))
					while len(messageLength) != 4:
						messageLength = '0' + messageLength
					usersOnline[messageTo].send(messageLength.encode())
					usersOnline[messageTo].send(data.encode())

				else:
					try:
						with open('data\\messages\\' + messageTo + '.txt', 'x') as messageCache:
							messageCache.write(data)
					except FileExistsError:
						with open('data\\messages\\' + messageTo + '.txt', 'a') as messageCache:
							messageCache.write('\n'+data)

			# when recieve new message request
			elif splitData[0] == 'messageTypeStartConversation':
				print('new message request')
				if (splitData[1]+'.txt') in os.listdir('data\\userCredentials'):
					message = 'messageTypeStartConversation True '+splitData[1]
				else:
					message = 'messageTypeStartConversation False'
				messageLength = str(len(message))
				while len(messageLength) != 4:
					messageLength = '0' + messageLength
				self.socket.send(messageLength.encode())
				self.socket.send(message.encode())
				print(message)

			# when recieve login request
			elif splitData[0] == 'messageTypeLogin':
				username = splitData[1] + '.txt'
				try:
					userCredentials = open('data\\userCredentials\\' + username)
					for i in userCredentials:
						if i == ' '.join(splitData[2:]):
							usersOnline[splitData[1]] = self.socket
							user = splitData[1]
							messageLength = str(len('messageTypeLogin True'))
							while len(messageLength) != 4:
								messageLength = '0' + messageLength
							self.socket.send(messageLength.encode())
							self.socket.send('messageTypeLogin True'.encode())

							try:
								with open('data\\messages\\' + user + '.txt', 'r') as messageCache:
									waitingOnMessage = 0
									for line in messageCache:
										line = line.rstrip('\n')
										messageLength = str(len(line))
										while len(messageLength) != 4:
											messageLength = '0' + messageLength
										self.socket.send(messageLength.encode())
										self.socket.send(line.encode())
								os.remove('data\\messages\\' + user + '.txt')
							except FileNotFoundError:
								pass
						else:
							messageLength = str(len('messageTypeLogin False'))
							while len(messageLength) != 4:
								messageLength = '0' + messageLength
							self.socket.send(messageLength.encode())
							self.socket.send('messageTypeLogin False'.encode())
				except FileNotFoundError:
					messageLength = str(len('messageTypeLogin False'))
					while len(messageLength) != 4:
						messageLength = '0' + messageLength
					self.socket.send(messageLength.encode())
					self.socket.send('messageTypeLogin False'.encode())

			# when recieve create account request
			elif splitData[0] == 'messageTypeCreateAccount':
				username = splitData[1]+'.txt'
				print(username)
				if username in os.listdir('data\\userCredentials'):
					message = 'messageTypeCreateAccount False'
				else:
					message = 'messageTypeCreateAccount True'
					with open('data\\userCredentials\\' + username, 'a') as userCredentials:
						userCredentials.write(' '.join(splitData[2:]))
				messageLength = str(len(message))
				while len(messageLength) != 4:
					messageLength = '0' + messageLength
				self.socket.send(messageLength.encode())
				self.socket.send(message.encode())
				print('message sent')	

while True:
	clientsocket, address = serversocket.accept()
	client(clientsocket, address)
	