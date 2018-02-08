import socket
import os
import gnupg
from threading import *

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server socket is bound to the loopback ip address, for proper out of network use, bind to the default gateway IP with assigned NAT ports
serverSocket.bind(('127.0.0.1', 3600))
serverSocket.listen(10)
usersOnline = {}

gpg = gnupg.GPG(verbose=True, gpgbinary='lib\gpg.exe', gnupghome='data\\GPGKey')
if not os.path.exists('data\\messages'):
    os.makedirs('data\\messages')

print ('*****************************************************************************\n\nserver running...')

gpg.list_keys()

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
            data = str(gpg.decrypt(data, always_trust=True, passphrase='teeth troops someone passed time bursts gates'))
            splitData = data.split(' ')
            messageType = splitData[0]
            print(data)

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

                print('Message received.\nMessage From: '+messageFrom+'\nMessage To: '+messageTo)

                if messageTo in usersOnline:
                    encryptedMessage = str(gpg.encrypt(data, messageTo, always_trust=True))
                    messageLength = str(len(encryptedMessage))
                    while len(messageLength) != 4:
                        messageLength = '0' + messageLength
                    usersOnline[messageTo].send(messageLength.encode())
                    usersOnline[messageTo].send(encryptedMessage.encode())

                else:
                    try:
                        with open('data\\messages\\' + messageTo + '.txt', 'x') as messageCache:
                            messageCache.write(data)
                    except FileExistsError:
                        with open('data\\messages\\' + messageTo + '.txt', 'a') as messageCache:
                            messageCache.write('\n'+data)

            # when recieve new message request
            elif splitData[0] == 'messageTypeStartConversation':
                success = False
                if (splitData[1]+'.txt') in os.listdir('data\\userCredentials'):
                    keyToSend = gpg.export_keys('<' + splitData[1] + '>')
                    message = 'messageTypeStartConversation True ' + splitData[1] + ' ' + keyToSend
                    success = True
                else:
                    message = 'messageTypeStartConversation False'
                    success = False
                
                encryptedMessage = str(gpg.encrypt(message, user, always_trust=True))
                messageLength = str(len(encryptedMessage))
                while len(messageLength) != 4:
                    messageLength = '0' + messageLength
                self.socket.send(messageLength.encode())
                self.socket.send(encryptedMessage.encode())

                if success == True:
                    keyToSend = gpg.export_keys('<' + user + '>')
                    message = 'messageTypeNewMessage ' + user + ' ' + keyToSend

                    if splitData[1] in usersOnline:
                        encryptedMessage = str(gpg.encrypt(message, splitData[1], always_trust=True))
                        messageLength = str(len(encryptedMessage))
                        while len(messageLength) != 4:
                            messageLength = '0' + messageLength
                        usersOnline[splitData[1]].send(messageLength.encode())
                        usersOnline[splitData[1]].send(encryptedMessage.encode())

                    else:
                        try:
                            with open('data\\messages\\' + splitData[1] + '.txt', 'x') as messageCache:
                                messageCache.write(message)
                        except FileExistsError:
                            with open('data\\messages\\' + splitData[1] + '.txt', 'a') as messageCache:
                                messageCache.write('\n'+message)

            # when recieve login request
            elif splitData[0] == 'messageTypeLogin':
                username = splitData[1] + '.txt'
                try:
                    userCredentials = open('data\\userCredentials\\' + username, 'r+b')
                    decrypted = gpg.decrypt_file(userCredentials, passphrase='teeth troops someone passed time bursts gates')

                    if str(decrypted) == str(' '.join(splitData[2:])):
                        message = 'messageTypeLogin True'
                        signedMessage = str(gpg.sign(message, passphrase='teeth troops someone passed time bursts gates'))
                        messageLength = str(len(signedMessage))
                        while len(messageLength) != 4:
                            messageLength = '0' + messageLength
                        self.socket.send(messageLength.encode())
                        self.socket.send(signedMessage.encode())

                        dataSize = self.socket.recv(4).decode()
                        data = self.socket.recv(int(dataSize)).decode()
                        data = str(gpg.decrypt(data, always_trust=True, passphrase='teeth troops someone passed time bursts gates'))

                        if data == 'messageTypeLoginSuccess':
                            usersOnline[splitData[1]] = self.socket
                            user = splitData[1]
                            try:
                                with open('data\\messages\\' + user + '.txt', 'r') as messageCache:
                                    # todo: fix the message sending (cant send by lines now that some messages take multiple lines)
                                    waitingOnMessage = 0
                                    message = ''
                                    for line in messageCache:
                                        if '-----END' in line:
                                            message += line.rstrip('\n')
                                            encryptedMessage = str(gpg.encrypt(message, user, always_trust=True))
                                            messageLength = str(len(encryptedMessage))
                                            while len(messageLength) != 4:
                                                messageLength = '0' + messageLength
                                            self.socket.send(messageLength.encode())
                                            self.socket.send(encryptedMessage.encode())
                                            message = ''

                                        elif '(MingW32)' in line:
                                            message += line + '\n'
                                        elif line != '\n':
                                            message += line

                                os.remove('data\\messages\\' + user + '.txt')
                            except FileNotFoundError:
                                pass
                    else:
                        message = 'messageTypeLogin False'
                        signedMessage = str(gpg.sign(message, passphrase='teeth troops someone passed time bursts gates'))
                        messageLength = str(len(signedMessage))
                        while len(messageLength) != 4:
                            messageLength = '0' + messageLength
                        self.socket.send(messageLength.encode())
                        self.socket.send(signedMessage.encode())
                except FileNotFoundError:
                    message = 'messageTypeLogin False'
                    signedMessage = str(gpg.sign(message, passphrase='teeth troops someone passed time bursts gates'))
                    messageLength = str(len(signedMessage))
                    while len(messageLength) != 4:
                        messageLength = '0' + messageLength
                    self.socket.send(messageLength.encode())
                    self.socket.send(signedMessage.encode())

            # when recieve create account request
            elif splitData[0] == 'messageTypeCreateAccount':
                username = splitData[1]+'.txt'
                if username == '.txt' or len(' '.join(splitData[2:])) < 8:
                    message = 'messageTypeCreateAccount False'
                    success = 'False'
                elif username in os.listdir('data\\userCredentials'):
                    message = 'messageTypeCreateAccount False'
                    success = 'False'
                else:
                    message = 'messageTypeCreateAccount True'
                    success = 'True'
                signedMessage = str(gpg.sign(message, passphrase='teeth troops someone passed time bursts gates'))
                messageLength = str(len(signedMessage))
                while len(messageLength) != 4:
                    messageLength = '0' + messageLength
                self.socket.send(messageLength.encode())
                self.socket.send(signedMessage.encode())

                if success == 'True':

                    dataSize = self.socket.recv(4).decode()
                    data = self.socket.recv(int(dataSize)).decode()
                    data = str(gpg.decrypt(data, always_trust=True, passphrase='teeth troops someone passed time bursts gates'))

                    if data == 'messageTypeCreateAccountSuccess':
                        with open('data\\userCredentials\\' + username, 'a') as userCredentials:
                            userCredentials.write(' '.join(splitData[2:]))

                        f = open('data\\userCredentials\\' + username, 'r+b')
                        encrypted = gpg.encrypt_file(f, 'Team_Shielded')

                        with open('data\\userCredentials\\' + username, 'w') as f2:
                            f2.write(str(encrypted))

            # When recieve public key submition
            elif splitData[0] == 'messageTypeKey':
                keyData = ' '.join(splitData[2:])
                importResult = gpg.import_keys(keyData)


while True:
    clientsocket, address = serverSocket.accept()
    client(clientsocket, address)
    
