#!/usr/bin/env python3

import math
import threading
import socket
import tkinter
import shutil
import gnupg
import _winapi
import tkinter.ttk as tkk
from tkinter import font, messagebox
from tkinter.filedialog import *
from os import listdir
from threading import *

# stores the widgets in the canvas to easily delete them and clear the window
toDelete = []

# global variables
clientName = ''
waitingOnResponse = 0
password = ''
inMessageRoom = False
detailsOpen = False

# Used to close the window and stop root.mainloop repeating
def onClosing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        global detailsOpen
        global clientSocket
        global socketOpen
        global clientName
        global inMessageRoom
        global informationWindow
        socketOpen = False

        if detailsOpen:
            informationWindow.destroy()

        # checks if a conersation is currently open and needs to be re-encrypted
        if inMessageRoom != False:
            gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + clientName + '\\GPGKey')
            f = open('data\\' + clientName + '\\messages\\' + inMessageRoom, 'r+b')
            encrypted = gpg.encrypt_file(f, clientName)

            with open('data\\' + clientName + '\\messages\\' + inMessageRoom, 'w') as f2:
                f2.write(str(encrypted))

            clientName = ''
        else:
            gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='lib')

        message = 'messageTypeClose'
        encryptedMessage = str(gpg.encrypt(message, 'Team_Shielded', always_trust=True))
        messageLength = str(len(encryptedMessage))
        while len(messageLength) != 4:
            messageLength = '0' + messageLength
        clientSocket.send(messageLength.encode())
        clientSocket.send(encryptedMessage.encode())
        clientSocket.shutdown(socket.SHUT_RDWR)
        clientSocket.close()

        root.destroy()


# loop to recieve and process messages
class recieveMessageThread(Thread):

    def __init__(self):
        Thread.__init__(self)
        self.start()

    def run(self):
        global clientName
        global socketOpen
        global clientSocket
        global waitingOnResponse
        global password
        gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='lib')

        while socketOpen == True:
            dataSize = clientSocket.recv(4).decode()
            data = clientSocket.recv(int(dataSize)).decode()

            print('*************************************************')
            print(data)

            splitData = data.split('\n')

            # checks if the message is signed or encrypted
            if splitData[0].rstrip('\r') == '-----BEGIN PGP SIGNED MESSAGE-----':
                print('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')

                # if the message is signed...
                keyWord = splitData[3].rstrip('\r')
                keyWord = keyWord.split(' ')

                # recieved login response
                if keyWord[0] == 'messageTypeLogin':
                    verified = gpg.verify(data)
                    if not verified and keyWord[1] == 'True':
                        waitingOnResponse = 'error'
                    else:
                        waitingOnResponse = keyWord[1]

                # recieved create account response
                elif keyWord[0] == 'messageTypeCreateAccount':
                    verified = gpg.verify(data)
                    if not verified and keyWord[1] == 'True':
                        waitingOnResponse = 'error'
                    else:
                        waitingOnResponse = keyWord[1]

            else:
                print('yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy')
                # if the message is encrypted...
                gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + clientName + '\\GPGKey')
                data = str(gpg.decrypt(data, passphrase=password))
                splitData = data.split(' ')

                print(data)

                # recieved message
                if splitData[0] == 'messageTypeMessage':
                    encryptedMessage = ' '.join(splitData[3:])
                    decryptedText = str(gpg.decrypt(encryptedMessage, passphrase=password))
                    message = str(splitData[1]) + ': ' + decryptedText
                    
                    if inMessageRoom == splitData[2]:
                        # if the conversation is currently open
                        with open('data\\' + splitData[2] + '\\messages\\' + splitData[1] + '.txt', 'a') as pastMessages:
                            pastMessages.write('\n'+message)
                        try:
                            if toDelete[1]['text'] == splitData[1]:
                                toDelete[2].config(state=NORMAL)
                                toDelete[2].insert(END, '\n' + str(message))
                                toDelete[2].see(END)
                                toDelete[2].config(state=DISABLED)
                        except:
                            pass
                    else:
                        # unencrypts the conversation, appends the message, then re-encrypts the conversation
                        gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + clientName + '\\GPGKey')
                        try:
                            with  open('data\\' + clientName + '\\messages\\' + splitData[1] + '.txt', 'r+b') as f:
                                decrypted = gpg.decrypt_file(f, passphrase=password)
                            with open('data\\' + clientName + '\\messages\\' + splitData[1] + '.txt', 'w') as f2:
                                f2.write(str(decrypted))
                                f2.write('\n'+message)
                            with  open('data\\' + clientName + '\\messages\\' + splitData[1] + '.txt', 'r+b') as f3:
                                encrypted = gpg.encrypt_file(f3, clientName)

                            with open('data\\' + clientName + '\\messages\\' + splitData[1] + '.txt', 'w') as f4:
                                f4.write(str(encrypted))

                        # if this is the first message recieved from that user, creates a conversation
                        except FileNotFoundError:
                            with open('data\\' + clientName + '\\messages\\' + splitData[1] + '.txt', 'a') as f2:
                                f2.write('\n'+message)
                            with  open('data\\' + clientName + '\\messages\\' + splitData[1] + '.txt', 'r+b') as f3:
                                encrypted = gpg.encrypt_file(f3, clientName)

                            with open('data\\' + clientName + '\\messages\\' + splitData[1] + '.txt', 'w') as f4:
                                f4.write(str(encrypted))

                # recieved new message response
                elif splitData[0] == 'messageTypeStartConversation':
                    if splitData[1] == 'True':
                        keyData = ' '.join(splitData[3:])
                        importResult = gpg.import_keys(keyData)
                        waitingOnResponse = splitData[1]
                    else:
                        waitingOnResponse = splitData[1]

                # someone else started a new conversation
                elif splitData[0] == 'messageTypeNewMessage':
                    user = splitData[1] + '.txt'
                    if os.path.exists('data\\' + clientName + '\\messages\\' + user):
                        pass
                    else:
                        with open('data\\' + clientName + '\\messages\\' + user, 'a') as pastMessages:
                            pass
                        keyData = ' '.join(splitData[2:])
                        importResult = gpg.import_keys(keyData)


# Creates the GUI Interface
class App:

    def __init__(self, master):

        # Initialise window
        root.title('Shielded')
        root.geometry()
        root.minsize(width=appWidth, height=appHeight)
        self.rootCanvas = Canvas(root, bd=0)
        self.rootCanvas.pack()

    def loginCallback(self, username, proposedPassword):
        global waitingOnResponse
        global clientName
        global password
        clientName = username
        gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='lib')

        message = 'messageTypeLogin ' + clientName + ' ' + proposedPassword
        encryptedMessage = gpg.encrypt(message, 'Team_Shielded', always_trust=True)
        encryptedMessage = str(encryptedMessage)
        messageLength = str(len(encryptedMessage))
        while len(messageLength) != 4:
            messageLength = '0' + messageLength
        waitingOnResponse = 1
        clientSocket.send(messageLength.encode())
        clientSocket.send(encryptedMessage.encode())

        while waitingOnResponse == 1:
            pass

        if waitingOnResponse == 'error':
            self.rootCanvas.password['entry'].delete(0, END)
            self.rootCanvas.wrongPassword = Label(self.rootCanvas, text='An error occured, please try again', fg='RED')
            self.rootCanvas.wrongPassword.grid(row=3, columnspan=2)
            toDelete.extend([self.rootCanvas.wrongPassword])
            message = 'messageTypeLoginError'
            encryptedMessage = gpg.encrypt(message, 'Team_Shielded', always_trust=True)
            encryptedMessage = str(encryptedMessage)
            messageLength = str(len(encryptedMessage))
            while len(messageLength) != 4:
                messageLength = '0' + messageLength
            clientSocket.send(messageLength.encode())
            clientSocket.send(encryptedMessage.encode())
            clientName = ''

        if waitingOnResponse == 'True':
            message = 'messageTypeLoginSuccess'
            encryptedMessage = gpg.encrypt(message, 'Team_Shielded', always_trust=True)
            encryptedMessage = str(encryptedMessage)
            messageLength = str(len(encryptedMessage))
            while len(messageLength) != 4:
                messageLength = '0' + messageLength
            clientSocket.send(messageLength.encode())
            clientSocket.send(encryptedMessage.encode())
            gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + clientName + '\\GPGKey')
            gpg.list_keys()
            password = proposedPassword
            if not os.path.exists('data\\' + clientName + '\\messages'):
                os.makedirs('data\\' + clientName + '\\messages')
            self.chooseRoom()

        elif waitingOnResponse == 'False':
            self.rootCanvas.password['entry'].delete(0, END)
            self.rootCanvas.wrongPassword = Label(self.rootCanvas, text='Username or password incorrect', fg='RED')
            self.rootCanvas.wrongPassword.grid(row=3, columnspan=2)
            toDelete.extend([self.rootCanvas.wrongPassword])
            clientName = ''

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
            gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='lib')
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
                # if all client side checks are passed
                message = 'messageTypeCreateAccount ' + username + ' ' + password1
                encryptedMessage = str(gpg.encrypt(message, 'Team_Shielded', always_trust=True))
                messageLength = str(len(encryptedMessage))
                while len(messageLength) != 4:
                    messageLength = '0' + messageLength
                waitingOnResponse = 1
                encryptedMessage = str(gpg.encrypt(message, 'Team_Shielded', always_trust=True))
                clientSocket.send(messageLength.encode())
                clientSocket.send(str(encryptedMessage).encode())

                while waitingOnResponse == 1:
                    pass

                if waitingOnResponse == 'True':
                    message = 'messageTypeCreateAccountSuccess'
                    encryptedMessage = gpg.encrypt(message, 'Team_Shielded', always_trust=True)
                    encryptedMessage = str(encryptedMessage)
                    messageLength = str(len(encryptedMessage))
                    while len(messageLength) != 4:
                        messageLength = '0' + messageLength
                    clientSocket.send(messageLength.encode())
                    clientSocket.send(encryptedMessage.encode())

                    self.rootCanvas.errorWarning.config(text='Generating encryption key, please wait')

                    # Making directories
                    if not os.path.exists('data\\' + username):
                        pass
                    else:
                        shutil.rmtree('data\\' + username)

                    os.makedirs('data\\' + username)
                    os.makedirs('data\\' + username + '\\messages')

                    # generate GPG key
                    gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + username + '\\GPGKey')

                    inputData = gpg.gen_key_input(key_type="RSA", key_length=4096, passphrase=password1, name_email=username, name_real=username)
                    key = gpg.gen_key(inputData)

                    publicKey = gpg.export_keys(username)
                    try:
                        with open('data\\' + username + '\\GPGKey\\publicKeyBlock.txt', 'w') as publicKeyBlockFile:
                            publicKeyBlockFile.write(publicKey)

                    except FileNotFoundError:
                        with open('data\\' + username + '\\GPGKey\\publicKeyBlock.txt', 'a') as publicKeyBlockFile:
                            publicKeyBlockFile.write(publicKey)
                            
                    privateKey = gpg.export_keys(username, secret=True)

                    serverKey = '''-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (MingW32)

mQINBFeVeo0BEAD0E8yMR8ehOhGtYhc/8bB6o6MQSGPBtGAEbfxOR3nH7YaVodJw
rzpNU6HEPYhR1OW3SzamutlY5OUQC1leRbvhzt6mTAOsPsLHAfyNPvj45sk7VqkL
wTvpKADuCm5grs/4343zGMgE+bYrR2RAx0PNVForhVWn8WjDRmgiWJwaSkyhtwOJ
TAXM+QwTDXKPWnOuZqqJc0TpJVV3CAoih2YJ2hRK0urTIgg2g0uKy/DCvEtln5Zz
t2Xfaswa/jO1FKl+B1CDukaPu+/+qz4A/SV0tTSDy9xtJUd31NMNRLIuiqmJmYmr
l4pcEo23Z82xYSag54pqlMwCOFQ5Jq9d8IstooNyu6kSaAV5Zv0yFplihMUKbH1P
FSZivtPE/ALUOkxAy7MMFoqaLdBK3ABol8oDXTSz1/z9MiYNfea/g4BEOYcsI9c/
0w+i9Svt2JZF1JmM2rknkjwWYl0Vo5hsJO1LSnVeJs+L9sTrVcWG8l0V+yjpUWsP
SVq+mYpwpblS5v7A2ocziwAvyUB1WXgZNTK6Ny2nBEg2t7Qr46RgI9S46Qoi18YW
YHl5/S0ZL68bAnj7naSWSBYv2/WBTtlONxQnARBSTCnoSimfwBYCrZEq5zXR1ahM
Bb8j6pIQsmNaQ41Vhr60mCUE4cxvX7bg/1gKnD+sHzzHWqd9SdSEZj/cKwARAQAB
tB1UZWFtX1NoaWVsZGVkIDxUZWFtX1NoaWVsZGVkPokCNgQTAQIAIAUCV5V6jQIb
LwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEHJ0Pcvv/1I2WPgP/RVnx/qaXySG
/2FQx0QQR52VNjkjdDBlTZ7JvTSe0aS9P2nf/f87ROY/OUWiQL6uRPLK+b9v7h4p
5EVUKwefAjBJ+QXJzdA1Fk05GqcBDKUHEWHc9ZJ/YFS4u56p70VNgjhhIpRGlNwt
cu67Eu755ldY5RVJo2Zi7pjiO0yTeFpXgGPY1O9oMd9vO1kExiTdTYGj0ugePW9q
R++BZy1F4Y5LwR57SKF7uWV4IwSDn/4g40uAmY2yYFbS0PxSjwP9ItwzcgrMtR8k
AYjx4A1yVUfnHoWkjW0/bQIqSp9W7EQjTfsb3W/8v+ActzXlSOUTwIr6PVzno3/a
jxRnqrEtIsnm25Wc9/fYuCIMrnoXsM0LIfZPP077hjiEFuKUSLosqqjsgUK5tQh2
eIMbsNLslQnsawRA3QcDx6SIH7JzqlOgXcQ3i7K2JNROEGOrKfgzEnJNVNVOP3YH
HMnZXd7M5ukzwFTw/bZpA3Jl2s6Q9QktDD5HfdSrP6VRL9v9tOROVnSREyoDaqcX
duKuOeBLnpDqMHe7YXVvXwwS/6CbrYyZPHV7wr6msjZ0oLSW6TwUtWJSEY0c4J6h
XimebvRgNHWKtx0J5UgCU9+4cwSG5+DxEk2kuK47Bi7kGjC+T400VzhNk+TKM+UZ
WSdiJLeroQFjuM06urj1EaPcmGCfO/91
=xpqQ
-----END PGP PUBLIC KEY BLOCK-----'''

                    import_result = gpg.import_keys(serverKey)

                    message = 'messageTypeKey ' + username + ' ' + publicKey
                    encryptedMessage = str(gpg.encrypt(message, 'Team_Shielded', always_trust=True))
                    messageLength = str(len(str(encryptedMessage)))
                    while len(messageLength) != 4:
                        messageLength = '0' + messageLength
                    waitingOnResponse = 1

                    clientSocket.send(messageLength.encode())
                    clientSocket.send(str(encryptedMessage).encode())

                    loadingBarRunning = False
                    self.loginCallback(username, password1)

                elif waitingOnResponse == 'error':
                    message = 'messageTypeCreateAccountError'
                    encryptedMessage = gpg.encrypt(message, 'Team_Shielded', always_trust=True)
                    encryptedMessage = str(encryptedMessage)
                    messageLength = str(len(encryptedMessage))
                    while len(messageLength) != 4:
                        messageLength = '0' + messageLength
                    clientSocket.send(messageLength.encode())
                    clientSocket.send(encryptedMessage.encode())

                    self.rootCanvas.usernameEntry.delete(0, END)
                    self.rootCanvas.errorWarning.config(text='An error occured, please try again')

                elif waitingOnResponse == 'False':
                    self.rootCanvas.usernameEntry.delete(0, END)
                    self.rootCanvas.errorWarning.config(text='Username is in use')

        self.rootCanvas.back = Button(self.rootCanvas, text='<--', command=self.home)
        self.rootCanvas.back.grid(row=0, columnspan=2)
        self.rootCanvas.back.bind('<Return>', lambda event: self.home())

        self.rootCanvas.usernameLabel = Label(self.rootCanvas, text='Username:')
        self.rootCanvas.usernameLabel.grid(row=1, column=0)
        self.rootCanvas.usernameEntry = Entry(self.rootCanvas)
        self.rootCanvas.usernameEntry.grid(row=1, column=1)
        self.rootCanvas.usernameInstructions = Label(self.rootCanvas, text='Username can be up to 32 characters')
        self.rootCanvas.usernameInstructions.grid(row=2, columnspan=2)
        self.rootCanvas.usernameInstructions2 = Label(self.rootCanvas, text='and can contain letters, numbers, \'_\', or \'-\'.')
        self.rootCanvas.usernameInstructions2.grid(row=3, columnspan=2)

        self.rootCanvas.passwordLabel1 = Label(self.rootCanvas, text='Password')
        self.rootCanvas.passwordLabel1.grid(row=4, column=0)
        self.rootCanvas.passwordEntry1 = Entry(self.rootCanvas, show='*')
        self.rootCanvas.passwordEntry1.grid(row=4, column=1)
        self.rootCanvas.passwordLabel2 = Label(self.rootCanvas, text='Confirm password')
        self.rootCanvas.passwordLabel2.grid(row=5, column=0)
        self.rootCanvas.passwordEntry2 = Entry(self.rootCanvas, show='*')
        self.rootCanvas.passwordEntry2.grid(row=5, column=1)
        self.rootCanvas.passwordInstructions = Label(self.rootCanvas, text='Password must be at least 8 characters (limit 128)')
        self.rootCanvas.passwordInstructions.grid(row=6, columnspan=2)
        self.rootCanvas.passwordInstructions2 = Label(self.rootCanvas, text='Do not forget it as I have not yet programmed account recovery')
        self.rootCanvas.passwordInstructions2.grid(row=7, columnspan=2)

        self.rootCanvas.createAccountButton = Button(self.rootCanvas, text='Create account', command=createAccountCallback)
        self.rootCanvas.createAccountButton.grid(row=8, columnspan=2)
        self.rootCanvas.errorWarning = Label(self.rootCanvas, text='', fg='red')
        self.rootCanvas.errorWarning.grid(row=9, columnspan=2)

        self.rootCanvas.usernameEntry.bind('<Return>', lambda event: createAccountCallback())
        self.rootCanvas.usernameEntry.bind('<Tab>', lambda event: self.rootCanvas.passwordEntry1.focus_set())
        self.rootCanvas.usernameEntry.bind('<Key>', limitInputUsername)
        self.rootCanvas.passwordEntry1.bind('<Return>', lambda event: createAccountCallback())
        self.rootCanvas.passwordEntry1.bind('<Key>', lambda event: limitInputPassword(event, self.rootCanvas.passwordEntry1))
        self.rootCanvas.passwordEntry2.bind('<Return>', lambda event: createAccountCallback())
        self.rootCanvas.passwordEntry2.bind('<Tab>', lambda event: self.rootCanvas.passwordEntry2.focus_set())
        self.rootCanvas.passwordEntry2.bind('<Key>', lambda event: limitInputPassword(event, self.rootCanvas.passwordEntry2))

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

        self.rootCanvas.username = createLoginBox('Username:', [1, 0])
        self.rootCanvas.username['entry'].bind('<Return>', lambda event: self.loginCallback(self.rootCanvas.username['entry'].get(), self.rootCanvas.password['entry'].get()))
        self.rootCanvas.password = createLoginBox('Password:', [1, 1], show='*')
        self.rootCanvas.password['entry'].bind('<Return>', lambda event: self.loginCallback(self.rootCanvas.username['entry'].get(), self.rootCanvas.password['entry'].get()))
        self.rootCanvas.loginButton = Button(self.rootCanvas, text='Login', command=lambda: self.loginCallback(self.rootCanvas.username['entry'].get(), self.rootCanvas.password['entry'].get()))
        self.rootCanvas.loginButton.grid(row=2, column=0)
        self.rootCanvas.loginButton.bind('<Return>', lambda event: self.loginCallback(self.rootCanvas.username['entry'].get(), self.rootCanvas.password['entry'].get()))
        self.rootCanvas.createAccountButton = Button(self.rootCanvas, text='Create Account', command=self.createAccount)
        self.rootCanvas.createAccountButton.grid(row=2, column=1)
        self.rootCanvas.createAccountButton.bind('<Return>', lambda event: self.createAccount())
        toDelete.extend([self.rootCanvas.username['entry'], self.rootCanvas.username['label'], self.rootCanvas.password['entry'], self.rootCanvas.password['label'], self.rootCanvas.loginButton, self.rootCanvas.createAccountButton])

    def logout(self):
        gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='lib')
        message = 'messageTypeLogout'
        encryptedMessage = str(gpg.encrypt(message, 'Team_Shielded', always_trust=True))
        messageLength = str(len(encryptedMessage))
        while len(messageLength) != 4:
            messageLength = '0' + messageLength
        clientSocket.send(messageLength.encode())
        clientSocket.send(encryptedMessage.encode())
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
        self.rootCanvas.newMessage.bind('<Return>', lambda event: self.newMessage())
        self.rootCanvas.newMessage.grid(row=0, column=0)

        self.rootCanvas.logout = Button(self.rootCanvas, text='Logout', command=self.logout)
        self.rootCanvas.logout.bind('<Return>', lambda event: self.logout())
        self.rootCanvas.logout.grid(row=0, column=2)

        self.rootCanvas.spacer = Frame(self.rootCanvas, height=20)
        self.rootCanvas.spacer.grid(row=1, columnspan=3)

        toDelete.extend([self.rootCanvas.newMessage, self.rootCanvas.spacer, self.rootCanvas.logout])

        for i in userContacts:
            self.rootCanvas.contactButton = Button(self.rootCanvas, text=str(i[:-4]), command=lambda user=i: self.messageRoom(user))
            self.rootCanvas.contactButton.grid(row=rowCounter, column=1)
            self.rootCanvas.contactButton.bind('<Return>', lambda event, user=i: self.messageRoom(user))
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
            if user+'.txt' in os.listdir('data\\' + clientName + '\\messages'):
                self.messageRoom(user+'.txt')
            else:
                global waitingOnResponse
                gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + clientName + '\\GPGKey')
                message = 'messageTypeStartConversation ' + str(user)
                encryptedMessage = str(gpg.encrypt(message, 'Team_Shielded', always_trust=True))
                messageLength = str(len(encryptedMessage))
                while len(messageLength) != 4:
                    messageLength = '0' + messageLength
                waitingOnResponse = 1

                clientSocket.send(messageLength.encode())
                clientSocket.send(encryptedMessage.encode())

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
        self.rootCanvas.back.bind('<Return>', lambda event: self.chooseRoom())
        self.rootCanvas.back.grid(row=0)

        self.rootCanvas.spacer = Frame(self.rootCanvas, height=20)
        self.rootCanvas.spacer.grid(row=1)

        self.rootCanvas.sendMessageTo = Label(self.rootCanvas, text='Who do you want to message?')
        self.rootCanvas.sendMessageTo.grid(row=2)

        self.rootCanvas.sendMessageToEntry = Entry(self.rootCanvas)
        self.rootCanvas.sendMessageToEntry.bind('<Return>', lambda event: startConversation(self.rootCanvas.sendMessageToEntry.get()))
        self.rootCanvas.sendMessageToEntry.grid(row=3)

        self.rootCanvas.startConversationButton = Button(self.rootCanvas, text='Start conversation!', command=lambda: startConversation(self.rootCanvas.sendMessageToEntry.get()))
        self.rootCanvas.startConversationButton.bind('<Return>', lambda event: startConversation(self.rootCanvas.sendMessageToEntry.get()))
        self.rootCanvas.startConversationButton.grid(row=4)

        self.rootCanvas.userDoesNotExist = Label(self.rootCanvas, text='User does not exist', fg='red')

        toDelete.extend([self.rootCanvas.back, self.rootCanvas.spacer, self.rootCanvas.sendMessageTo, self.rootCanvas.sendMessageToEntry, self.rootCanvas.startConversationButton, self.rootCanvas.userDoesNotExist])


    # Creates the messaging screen within App
    def messageRoom(self, sendingTo):
        global toDelete
        global inMessageRoom
        inMessageRoom = sendingTo
        global password
        for i in toDelete:
            i.destroy()
        toDelete = []

        gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + clientName + '\\GPGKey')
        f = open('data\\' + clientName + '\\messages\\' + sendingTo, 'r+b')
        decrypted = gpg.decrypt_file(f, passphrase=password)
        with open('data\\' + clientName + '\\messages\\' + sendingTo, 'w') as f2:
            f2.write(str(decrypted))

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

        def deleteConversation(conversationToDelete):
            global inMessageRoom
            if messagebox.askokcancel("Delete", "Are you sure you wish to delete this conversation? The other user will still have a copy"):
                inMessageRoom = False
                os.remove('data\\' + clientName + '\\messages\\' + conversationToDelete)
                self.chooseRoom()

        def showConversationDetails(detailsToShow):  
            global detailsOpen          
            yourFingerprint = ''
            theirFingerprint = ''
            detailsToShow = detailsToShow[:-4]

            def closeInformationWindow():
                informationWindow.destroy()
                detailsOpen = False

            keys = gpg.list_keys(keys=['<' + clientName + '>', '<' + detailsToShow + '>'])
            for i in keys:
                if i['uids'][0] == clientName + ' <' + clientName + '>':
                    yourFingerprint = i['fingerprint']
                elif i['uids'][0] == detailsToShow + ' <' + detailsToShow + '>':
                    theirFingerprint = i['fingerprint']

            informationWindow = Toplevel()
            informationWindow.title('Details')
            global informationWindow

            information = Message(informationWindow, text='You are currently talking to ' + detailsToShow + '.\nTheir fingerprint is: ' + theirFingerprint + '\nYour fingerprint is: ' + yourFingerprint + '\nIf this matches what ' + detailsToShow + ' can see, then the conversation is secure.\nCheck this through another medium such as Facebook or talking to them in person.\nNote: this only needs to be checked once, it will never change.')
            information.pack()

            closeWindow = Button(informationWindow, text='Close', command=closeInformationWindow)
            closeWindow.pack()
            detailsOpen = True


        def encryptFile(fileToEncrypt):
            global inMessageRoom
            f = open('data\\' + clientName + '\\messages\\' + fileToEncrypt, 'r+b')
            encrypted = gpg.encrypt_file(f, clientName)

            with open('data\\' + clientName + '\\messages\\' + fileToEncrypt, 'w') as f2:
                f2.write(str(encrypted))

            inMessageRoom = False
            self.chooseRoom()

        # First row, back button and who the user is talking to
        self.rootCanvas.back = Button(self.rootCanvas, text='<--', command=lambda: encryptFile(sendingTo))
        self.rootCanvas.back.grid(row=0, column=0)
        self.rootCanvas.title = Label(self.rootCanvas, text=(sendingTo[:-4]))
        self.rootCanvas.title.grid(row=0, column=1)
        self.rootCanvas.showDetails = Button(self.rootCanvas, text='Details', command=lambda: showConversationDetails(sendingTo))
        self.rootCanvas.showDetails.grid(row=0, column=2)
        self.rootCanvas.deleteButton = Button(self.rootCanvas, text="Delete", command=lambda: deleteConversation(sendingTo))
        self.rootCanvas.deleteButton.grid(row=0, column=3)

        # messages and scrollbar
        pastMessages = open('data\\' + clientName + '\\messages\\' + sendingTo)

        self.rootCanvas.pastMessages = Text(self.rootCanvas, width=math.floor(appWidth*0.15))
        for line in pastMessages:
            self.rootCanvas.pastMessages.insert(END, str('\n'+line).rstrip('\n'))
        pastMessages.close()

        self.rootCanvas.pastMessages.grid(row=1, columnspan=4)
        self.rootCanvas.messageScrollbar = Scrollbar(self.rootCanvas, orient=VERTICAL)
        self.rootCanvas.messageScrollbar.grid(row=1, column=4, sticky=N+S)
        self.rootCanvas.messageScrollbar.config(command=self.rootCanvas.pastMessages.yview)
        self.rootCanvas.pastMessages.see(END)
        self.rootCanvas.pastMessages.config(yscrollcommand=self.rootCanvas.messageScrollbar.set, state=DISABLED)

        # text box for typing messages to send and send button
        self.rootCanvas.textBox = Text(self.rootCanvas, height=3)
        self.rootCanvas.textBox.grid(row=2, column=0, columnspan=4)
        self.rootCanvas.textBox.bind('<Return>', lambda event: self.writeMessage(self.rootCanvas.textBox.get("1.0", END), sendingTo))
        self.rootCanvas.textBox.bind('<Key>', limitInput)
        self.rootCanvas.sendButton = Button(self.rootCanvas, text='Send', command=lambda: self.writeMessage(self.rootCanvas.textBox.get("1.0", END), sendingTo))
        self.rootCanvas.sendButton.grid(row=2, column=4)

        toDelete.extend([self.rootCanvas.title, self.rootCanvas.pastMessages, self.rootCanvas.messageScrollbar, self.rootCanvas.textBox, self.rootCanvas.sendButton, self.rootCanvas.back, self.rootCanvas.showDetails, self.rootCanvas.deleteButton])

    def writeMessage(self, text, sendingTo):
        global clientName
        # writes the message in correct syntax for saving
        message = clientName + ': ' + text.rstrip('\n')

        # edits local files
        self.rootCanvas.textBox.delete('1.0', END)
        with open('data\\' + clientName + '\\messages\\' + sendingTo, 'a') as pastMessages:
            pastMessages.write('\n'+message)
        self.rootCanvas.pastMessages.config(state=NORMAL)
        self.rootCanvas.pastMessages.insert(END, '\n'+message)
        self.rootCanvas.pastMessages.see(END)
        self.rootCanvas.pastMessages.config(state=DISABLED)

        self.sendMessage(text.rstrip('\n'), sendingTo)

    def sendMessage(self, message, sendingTo):
        global clientName
        gpg = gnupg.GPG(verbose=True, gpgbinary='lib\\gpg.exe', gnupghome='data\\' + clientName + '\\GPGKey')
        message = str(gpg.encrypt(message, str(sendingTo[:-4]), always_trust=True))
        message = 'messageTypeMessage ' + clientName + ' ' + sendingTo[:-4] + ' ' + message
        encryptedMessage = str(gpg.encrypt(message, 'Team_Shielded', always_trust=True))
        messageLength = str(len(encryptedMessage))
        while len(messageLength) != 4:
            messageLength = '0' + messageLength
        clientSocket.send(messageLength.encode())
        clientSocket.send(encryptedMessage.encode())


# Create the base window
root = Tk()

# Create global variables for use in sizing
screenWidth, screenHeight = root.winfo_screenwidth(), root.winfo_screenheight()
appWidth, appHeight = math.floor(screenWidth*0.3), math.floor(screenHeight*0.6)
font = tkinter.font.Font(family='arial', size=16)

# Connects to the message server and creates a thread looping for packets
root.protocol("WM_DELETE_WINDOW", onClosing)
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# socket set to loopback ip address for local use, to use online, update with a real IP, or DNS address.
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
except: pass
