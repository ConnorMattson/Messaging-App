import math
import socket
import tkinter
import shutil
from tkinter import font, messagebox
from tkinter.filedialog import *
from os import listdir
from threading import *

# stores the widgets in the canvas to easily delete them and clear the window
toDelete = []
clientName = ''
waitingOnResponse = 0

# Used to close the window and stop root.mainloop repeating
def on_closing():
	if messagebox.askokcancel("Quit", "Do you want to quit?"):
		global clientSocket
		global socketOpen
		socketOpen = False
		messageLength = str(len('messageTypeClose'))
		while len(messageLength) != 4:
			messageLength = '0' + messageLength
		clientSocket.send(messageLength.encode())
		clientSocket.send('messageTypeClose'.encode())
		clientSocket.shutdown(socket.SHUT_RDWR)
		clientSocket.close()
		root.destroy()

# Loop to recieve and process messages
class recieveMessageThread(Thread):

	def __init__(self):
		Thread.__init__(self)
		self.start()

	def run(self):
		global socketOpen
		global clientSocket
		global waitingOnResponse

		while socketOpen == True:
			dataSize = clientSocket.recv(4).decode()
			print(dataSize)
			data = clientSocket.recv(int(dataSize)).decode()
			print(data)
			splitData = data.split(' ')
			print(splitData)

			# recieved message
			if splitData[0] == 'messageTypeMessage':
				message = str(splitData[1]) + ': ' + ' '.join(splitData[3:])
				with open('data\\' + splitData[2] + '\\messages\\' + splitData[1] + '.txt', 'a') as pastMessages:
					pastMessages.write('\n' + message)
				try:
					print(toDelete)
					if toDelete[1]['text'] == splitData[1]:
						toDelete[2].config(state=NORMAL)
						toDelete[2].insert(END, '\n' + str(message))
						toDelete[2].see(END)
						toDelete[2].config(state=DISABLED)
				except:
					pass

			# recieved new message response
			elif splitData[0] == 'messageTypeStartConversation':
				waitingOnResponse = splitData[1]

			# recieved login response
			elif splitData[0] == 'messageTypeLogin':
				waitingOnResponse = splitData[1]

			# recieved create account response
			elif splitData[0] == 'messageTypeCreateAccount':
				waitingOnResponse = splitData[1]

# Creates the GUI Interface
class App:

	def __init__(self, master):

		# Initialise window
		root.title('PLACEHOLDER NAME')
		root.geometry()
		root.minsize(width=appWidth,height=appHeight)
		self.rootCanvas = Canvas(root, bd=0)
		self.rootCanvas.pack()

	def loginCallback(self, username, password):
		global waitingOnResponse
		global clientName
		clientName = username

		message = 'messageTypeLogin ' + clientName + ' ' + password
		messageLength = str(len(message))
		while len(messageLength) != 4:
			messageLength = '0' + messageLength
		waitingOnResponse = 1
		clientSocket.send(messageLength.encode())
		clientSocket.send(message.encode())

		while waitingOnResponse == 1:
			pass
		
		if waitingOnResponse == 'True':
			self.chooseRoom()
		
		elif waitingOnResponse == 'False':
			self.rootCanvas.password['entry'].delete(0, END)
			self.rootCanvas.wrongPassword = Label(self.rootCanvas, text='Username or password incorrect', fg='RED')
			self.rootCanvas.wrongPassword.grid(row=3, columnspan=2)
			toDelete.extend([self.rootCanvas.wrongPassword])

	def createAccount(self):
		global toDelete
		for i in toDelete:
			i.destroy()
		toDelete = []

		def limitInputUsername(event):
			if event.char in ('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '_', ''):
				toRemove = len(self.rootCanvas.usernameEntry.get()) - 32
				if toRemove >= 0:
					self.rootCanvas.usernameEntry.delete((int(self.rootCanvas.usernameEntry.index(END)) - int(toRemove)), END)
					if event.char != '':
						return "break"
			else:
				return "break"

		def limitInputPassword(event, widget):
			toRemove = len(widget.get()) - 128
			if toRemove >= 0:
				widget.delete((int(widget.index(END)) - int(toRemove)), END)
				if event.char != '':
					return "break"

		def createAccountCallback():
			global waitingOnResponse
			username = self.rootCanvas.usernameEntry.get()
			password1 = self.rootCanvas.passwordEntry1.get()
			if password1 != self.rootCanvas.passwordEntry2.get():
				self.rootCanvas.passwordEntry1.delete(0, END)
				self.rootCanvas.passwordEntry2.delete(0, END)
				self.rootCanvas.errorWarning.config(text='Passwords do not match')

			elif len(password1) < 8:
				self.rootCanvas.passwordEntry1.delete(0, END)
				self.rootCanvas.passwordEntry2.delete(0, END)
				self.rootCanvas.errorWarning.config(text='Password too short')

			elif username == '':
				self.rootCanvas.passwordEntry1.delete(0, END)
				self.rootCanvas.passwordEntry2.delete(0, END)
				self.rootCanvas.errorWarning.config(text='A username is required')

			else:
				message = 'messageTypeCreateAccount ' + username + ' ' + password1
				messageLength = str(len(message))
				while len(messageLength) != 4:
					messageLength = '0' + messageLength
				waitingOnResponse = 1
				clientSocket.send(messageLength.encode())
				clientSocket.send(message.encode())

				while waitingOnResponse == 1:
					pass
				
				if waitingOnResponse == 'True':
					if not os.path.exists('data\\' + username):
						pass
					else:
						shutil.rmtree('data\\' + username)

					os.makedirs('data\\' + username)
					os.makedirs('data\\' + username + '\\messages')
					
					self.loginCallback(username, password1)


				elif waitingOnResponse == 'False':
					self.rootCanvas.usernameEntry.delete(0, END)
					self.rootCanvas.errorWarning.config(text='Username is in use')

		self.rootCanvas.back = Button(self.rootCanvas, text='<--', command=self.home)
		self.rootCanvas.back.grid(row=0, columnspan=2)

		self.rootCanvas.usernameLabel = Label(self.rootCanvas, text='Username:')
		self.rootCanvas.usernameLabel.grid(row=1, column=0)
		self.rootCanvas.usernameEntry = Entry(self.rootCanvas)
		self.rootCanvas.usernameEntry.bind('<Key>', limitInputUsername)
		self.rootCanvas.usernameEntry.grid(row=1, column=1)
		self.rootCanvas.usernameInstructions = Label(self.rootCanvas, text='Username can be up to 32 characters')
		self.rootCanvas.usernameInstructions.grid(row=2, columnspan=2)
		self.rootCanvas.usernameInstructions2 = Label(self.rootCanvas, text='and can contain letters, numbers, \'_\', or \'-\'.')
		self.rootCanvas.usernameInstructions2.grid(row=3, columnspan=2)

		self.rootCanvas.passwordLabel1 = Label(self.rootCanvas, text='Password')
		self.rootCanvas.passwordLabel1.grid(row=4, column=0)
		self.rootCanvas.passwordEntry1 = Entry(self.rootCanvas, show='*')
		self.rootCanvas.passwordEntry1.bind('<Key>', lambda event: limitInputPassword(event, self.rootCanvas.passwordEntry1))
		self.rootCanvas.passwordEntry1.grid(row=4, column=1)
		self.rootCanvas.passwordLabel2 = Label(self.rootCanvas, text='Confirm password')
		self.rootCanvas.passwordLabel2.grid(row=5, column=0)
		self.rootCanvas.passwordEntry2 = Entry(self.rootCanvas, show='*')
		self.rootCanvas.passwordEntry2.bind('<Key>', lambda event: limitInputPassword(event, self.rootCanvas.passwordEntry2))
		self.rootCanvas.passwordEntry2.grid(row=5, column=1)
		self.rootCanvas.passwordInstructions = Label(self.rootCanvas, text='Password must be at least 8 characters (limit 128)')
		self.rootCanvas.passwordInstructions.grid(row=6, columnspan=2)
		self.rootCanvas.passwordInstructions2 = Label(self.rootCanvas, text='Do not forget it as I have not yet programmed account recovery')
		self.rootCanvas.passwordInstructions2.grid(row=7, columnspan=2)

		self.rootCanvas.createAccountButton = Button(self.rootCanvas, text='Create account', command=createAccountCallback)
		self.rootCanvas.createAccountButton.grid(row=8, columnspan=2)
		self.rootCanvas.errorWarning = Label(self.rootCanvas, text='', fg='red')
		self.rootCanvas.errorWarning.grid(row=9, columnspan=2)

		toDelete.extend([self.rootCanvas.back, self.rootCanvas.usernameLabel, self.rootCanvas.usernameEntry, self.rootCanvas.usernameInstructions, self.rootCanvas.usernameInstructions2, self.rootCanvas.passwordLabel1, self.rootCanvas.passwordEntry1, self.rootCanvas.passwordLabel2, self.rootCanvas.passwordEntry2, self.rootCanvas.passwordInstructions, self.rootCanvas.passwordInstructions2, self.rootCanvas.createAccountButton, self.rootCanvas.errorWarning])

	# Creates the home screen within app
	def home(self):
		global toDelete
		for i in toDelete:
			i.destroy()
		toDelete = []

		def createLoginBox(caption, position, **options):
			label = Label(self.rootCanvas, text=caption)
			label.grid(row=position[1], column=(position[0]-1))
			entry = Entry(self.rootCanvas, **options)
			entry.grid(row=position[1], column=(position[0]))
			return {'entry': entry, 'label': label} 

		self.rootCanvas.username = createLoginBox('Username:', [1,0])
		self.rootCanvas.password = createLoginBox('Password:', [1,1], show='*')

		self.rootCanvas.loginButton = Button(self.rootCanvas, text='Login', command=lambda: self.loginCallback(self.rootCanvas.username['entry'].get(),self.rootCanvas.password['entry'].get()))
		self.rootCanvas.loginButton.grid(row=2, column=0)
		self.rootCanvas.createAccountButton = Button(self.rootCanvas, text='Create Account', command=self.createAccount)
		self.rootCanvas.createAccountButton.grid(row=2, column=1)
		toDelete.extend([self.rootCanvas.username['entry'], self.rootCanvas.username['label'], self.rootCanvas.password['entry'], self.rootCanvas.password['label'], self.rootCanvas.loginButton, self.rootCanvas.createAccountButton])

	def logout(self):
		messageLength = str(len('messageTypeLogout'))
		while len(messageLength) != 4:
			messageLength = '0' + messageLength
		clientSocket.send(messageLength.encode())
		clientSocket.send('messageTypeLogout'.encode())
		clientName = ''
		self.home()

	# Creates the message screen within app
	def chooseRoom(self):
		global toDelete
		for i in toDelete:
			i.destroy()
		toDelete = []

		userContacts = (listdir('data\\' + clientName + '\\messages'))
		rowCounter = 2

		self.rootCanvas.newMessage = Button(self.rootCanvas, text='New Message', command=self.newMessage)
		self.rootCanvas.newMessage.grid(row=0, column = 0)

		self.rootCanvas.logout = Button(self.rootCanvas, text='Logout', command=self.logout)
		self.rootCanvas.logout.grid(row=0, column=2)

		self.rootCanvas.spacer = Frame(self.rootCanvas, height=20)
		self.rootCanvas.spacer.grid(row=1, columnspan=3)

		toDelete.extend([self.rootCanvas.newMessage, self.rootCanvas.spacer, self.rootCanvas.logout])

		for i in userContacts:
			self.rootCanvas.contactButton = Button(self.rootCanvas, text=str(i[:-4]), command=lambda user=i:self.messageRoom(user))
			self.rootCanvas.contactButton.grid(row=rowCounter, column=1)
			toDelete.extend([self.rootCanvas.contactButton])
			rowCounter += 1

	# if the user wants to start a new conversation
	def newMessage(self):
		global toDelete
		global waitingOnResponse
		for i in toDelete:
			i.destroy()
		toDelete = []

		def startConversation(user):
			global waitingOnResponse
			message = 'messageTypeStartConversation ' + str(user)
			messageLength = str(len(message))
			while len(messageLength) != 4:
				messageLength = '0' + messageLength
			waitingOnResponse = 1
			clientSocket.send(messageLength.encode())
			clientSocket.send(message.encode())

			while waitingOnResponse == 1:
				pass

			if waitingOnResponse == 'True':
				waitingOnResponse = 0
				user = user + '.txt'
				with open('data\\' + clientName + '\\messages\\' + user, 'a') as pastMessages:
					pass
				self.messageRoom(user)

			elif waitingOnResponse == 'False':
				toDelete[5].grid(row=5)
				toDelete[3].delete(0, END)
				waitingOnResponse = 0

		self.rootCanvas.back = Button(self.rootCanvas, text='<--', command=self.chooseRoom)
		self.rootCanvas.back.grid(row=0)

		self.rootCanvas.spacer = Frame(self.rootCanvas, height=20)
		self.rootCanvas.spacer.grid(row=1)

		self.rootCanvas.sendMessageTo = Label(self.rootCanvas, text='Who do you want to message?')
		self.rootCanvas.sendMessageTo.grid(row=2)

		self.rootCanvas.sendMessageToEntry = Entry(self.rootCanvas)
		self.rootCanvas.sendMessageToEntry.grid(row=3)

		self.rootCanvas.startConversationButton = Button(self.rootCanvas, text='Start conversation!', command=lambda: startConversation(self.rootCanvas.sendMessageToEntry.get()))
		self.rootCanvas.startConversationButton.grid(row=4)

		self.rootCanvas.userDoesNotExist = Label(self.rootCanvas, text='User does not exist', fg='red')

		toDelete.extend([self.rootCanvas.back, self.rootCanvas.spacer, self.rootCanvas.sendMessageTo, self.rootCanvas.sendMessageToEntry, self.rootCanvas.startConversationButton, self.rootCanvas.userDoesNotExist])


	# Creates the messaging screen within App
	def messageRoom(self, sendingTo):
		global toDelete
		for i in toDelete:
			i.destroy()
		toDelete = []

		def limitInput(event):
			if event.char == '':
				toPaste = root.clipboard_get()
				pasteDifference = len(toPaste) + len(self.rootCanvas.textBox.get(1.0, END)) - 999
				if pasteDifference > 0:
					self.rootCanvas.textBox.insert(END, toPaste[0:len(toPaste)-pasteDifference])

			toRemove = len(self.rootCanvas.textBox.get(1.0, END)) - 999
			if toRemove >= 0:
				self.rootCanvas.textBox.delete("%s-%sc" % (INSERT, toRemove), INSERT)
				if event.char != '':
					return "break"

		# First row, back button and who the user is talking to
		self.rootCanvas.back = Button(self.rootCanvas, text='<--', command=self.chooseRoom)
		self.rootCanvas.back.grid(row=0, column=0)
		self.rootCanvas.title = Label(self.rootCanvas, text=(sendingTo[:-4]))
		self.rootCanvas.title.grid(row=0, column=1)

		# messages and scrollbar
		pastMessages = open('data\\' + clientName + '\\messages\\' + sendingTo)

		self.rootCanvas.pastMessages = Text(self.rootCanvas, width=math.floor(appWidth*0.15))
		for line in pastMessages:
			self.rootCanvas.pastMessages.insert(END, str(line))
		pastMessages.close()

		self.rootCanvas.pastMessages.grid(row=1, columnspan=2)
		self.rootCanvas.messageScrollbar = Scrollbar(self.rootCanvas, orient=VERTICAL)
		self.rootCanvas.messageScrollbar.grid(row=1,column=2, sticky=N+S)
		self.rootCanvas.messageScrollbar.config(command=self.rootCanvas.pastMessages.yview)
		self.rootCanvas.pastMessages.see(END)
		self.rootCanvas.pastMessages.config(yscrollcommand=self.rootCanvas.messageScrollbar.set, state=DISABLED)

		# text box for typing messages to send and send button
		self.rootCanvas.textBox = Text(self.rootCanvas, height=3)
		self.rootCanvas.textBox.grid(row=2, column=0, columnspan=2)
		self.rootCanvas.textBox.bind('<Key>', limitInput)
		self.rootCanvas.sendButton = Button(self.rootCanvas, text='Send', command=lambda: self.writeMessage(self.rootCanvas.textBox.get("1.0",END), sendingTo))
		self.rootCanvas.sendButton.grid(row=2, column=2)

		toDelete.extend([self.rootCanvas.back, self.rootCanvas.title, self.rootCanvas.pastMessages, self.rootCanvas.messageScrollbar, self.rootCanvas.textBox, self.rootCanvas.sendButton])

	def writeMessage(self, text, sendingTo):
		# writes the message in correct syntax for saving
		message = '\n' + clientName + ': ' + text.rstrip('\n')
		
		# edits local files
		self.rootCanvas.textBox.delete('1.0', END)
		with open('data\\' + clientName + '\\messages\\' + sendingTo, 'a') as pastMessages:
			pastMessages.write(message)
		self.rootCanvas.pastMessages.config(state=NORMAL)
		self.rootCanvas.pastMessages.insert(END, message)
		self.rootCanvas.pastMessages.see(END)
		self.rootCanvas.pastMessages.config(state=DISABLED)

		self.sendMessage(text.rstrip('\n'), sendingTo)

	def sendMessage(self, message, sendingTo):
		message = 'messageTypeMessage ' + clientName + ' ' + sendingTo[:-4] + ' ' + message
		messageLength = str(len(message))
		while len(messageLength) != 4:
			messageLength = '0' + messageLength
		clientSocket.send(messageLength.encode())
		clientSocket.send(message.encode())


# Create the base window
root = Tk()

# Create global variables for use in sizing
screenWidth, screenHeight = root.winfo_screenwidth(), root.winfo_screenheight()
appWidth, appHeight = math.floor(screenWidth*0.3), math.floor(screenHeight*0.6)
font = tkinter.font.Font(family='arial', size=16)

# Connects to the message server and creates a thread looping for packets
root.protocol("WM_DELETE_WINDOW", on_closing)
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect(('127.0.0.1', 3600))
socketOpen = True
recieveMessageThread()

# Creates an instance of the interface within the base window
app = App(root)

app.home()

# Begins checking the event loop until quit() is called - this handles events from the user
root.mainloop()

# Destroys the base window in the event it did not close with quit()
try: root.destroy()
except:	pass