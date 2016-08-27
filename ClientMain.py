import socket
import sys
import time
import hashlib
import random
import string
import linecache
import threading
import os

#import pickle
#import PySide

from Crypto.Cipher import AES
from OpenSSL import SSL, crypto

fileDirectory = "files_client/"
debugMode = 0


endMarker = "!!--!-$%$#(*#@"
uniqueKey = "1A4F428BB6AA987E075C92A4"
# Converts key to 32 bytes for AES encryption
uniqueKey = "{: <32}".format(uniqueKey).encode("utf-8")
# Generate IV for AES encryption
ivKey = '#%F--?PstR71'
ivKey = "{: <16}".format(ivKey).encode("utf-8")


def verify_cb(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    print 'C> GOT CERT: %s' % cert.get_subject()
    return ok

def encryptString(string, key, iv):
    encryptedString = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad string to be a multiple of 16 bytes
    multiplier = len(string) / 16
    remainderCheck = len(string) % 16
    padAmount = 16 - remainderCheck
    if remainderCheck > 0:
        multiplier += 1
    for i in range(padAmount):
        string += str("-")
    
    return encryptedString.encrypt(string)
    
def decryptString(string, key, iv):
    decryptedString = ""
    try:
        decryptedString = AES.new(key, AES.MODE_CBC, iv)
        return decryptedString.decrypt(string).rstrip("-")
    except:
        print "C> AES Error."
    return ""

def randomString(length):
    tempRandom = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return tempRandom

def PrintException(errorReporting):
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print 'C> EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


def receiverThread(connection, numBytesPerRequest):
    # Seed the RNG
    random.seed(time.time())
    
    command = ""
    
    try:

        # Receive the data in small chunks and process it
        while True:
            try:
                encryptedString = connection.recv(numBytesPerRequest)
            except:
                break
            
            command = command + encryptedString
            tempDecrypt = decryptString(command, uniqueKey, ivKey)

            if tempDecrypt[0] == "/" and endMarker in tempDecrypt:
                command = tempDecrypt
                command = command.replace(endMarker, "")
                pieces = command.split(" ")
                requestType = pieces[0][1:].lower()
                
                data = ""
                
                if len(pieces) > 2:
                    for i in range(len(pieces)):
                        if i != 0:
                            data = data + " " + pieces[i]
                
                if requestType == "chat":
                    command = command[6:]
                    print command
                elif requestType == "download":
                    testDownloadFilename = fileDirectory + "test-down.txt"
                    
                    data = command[9:].strip(" ")
                    
                    downloaded_file = open(testDownloadFilename, "w+")
                    downloaded_file.write(data)
                    downloaded_file.close()
                elif requestType == "ls":
                    data = command[11:]
                    print data
                
                    
            

                # Clear out command after full function executes
                command = ""
    except:
        PrintException(debugMode)
        #print >>sys.stderr, '.CLIENT. Closing within receiverThread()'
        connection.shutdown()
        connection.close()




# Generate a file of hashes to send if it does not exist
def createLargeFile(numLines, username):
    try:
        # Create file name
        test_file_name = fileDirectory + "c-testup.txt"
        # Open a file in write mode
        test_file = open(test_file_name, "w+")

        if test_file == True:
            print "C> Opened File: " + str(test_file.name)
        else:
            print "C> Generating File " + str(test_file.name) + "..."

            for i in range(numLines):
                test_file.write(hashlib.sha512(str(time.time()/(i+1))).hexdigest()[:20] + "\n")

        test_file.close()
        print "C> Created and Saved: " + str(test_file_name)

        return test_file_name
    except:
        PrintException(debugMode)






def main(argv):
    try:
        largeFileSize = 8192
        serverAddress = "localhost"
        username = ""

        if argv.__len__() < 1 or argv.__len__() > 3:
            print "C> -----------------------------"
            print "C> USAGE: <script>.py [<username>] [<port>]"
            print "C> USAGE: ClientMain.py Clownfat 9001"
            print "C> -----------------------------"
            sys.exit()

        if argv.__len__() == 1:
            if username == "":
                username = randomString(10)
            portTCP = 9001
        elif argv.__len__() == 2:
            username = argv[1]
            portTCP = 9001
        elif argv.__len__() == 3:
            username = argv[1]
            portTCP = argv[2]


        # Seed the RNG
        random.seed(time.time())
        
        dir = os.path.dirname(sys.argv[0])
        if dir == "":
            dir = os.curdir
            
        
        # Initialize context
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, verify_cb) # Demand a certificate
        ctx.use_privatekey_file (os.path.join(dir, 'keys/client/client.pkey'))
        ctx.use_certificate_file(os.path.join(dir, 'keys/client/client.cert'))
        ctx.load_verify_locations(os.path.join(dir, 'keys/client/CA.cert'))

        # Create a TCP/IP socket
        sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

        sock_server_address = (serverAddress, portTCP)
        print >>sys.stderr, "C> CONNECTING TO: " + str(sock_server_address)
        # Connect the socket to the port where the server is listening
        sock.connect((serverAddress, portTCP))

        # START: Pre-loop processing
        sock.sendall(encryptString(username, uniqueKey, ivKey))

        # END:   Pre-loop processing
        # -----
        # START: Listener Thread
        t = threading.Thread(target=receiverThread, args=(sock, largeFileSize))
        t.daemon = True
        t.start()
        # q.put(t)

        # END:   Listener Thread

        print "C> Connected to: " + str(serverAddress) + " - port: " + str(portTCP) + " - name: " + username

        while True:
            # Send data
            message = raw_input("")
            pieces = message.split(" ")
            
            # If the message is a function, prepare the message format before sending
            if message != "" and pieces != "" and pieces[0][0] == "/" :
                requestType = pieces[0][1:].lower()
                
                # Catch a quit request using multiple synonyms
                if requestType == "q" or requestType == "quit" or requestType == "exit" or requestType == "close":
                    raise ValueError("C> '/q' or '/quitZ', entered, closing inner client loop...")
                # Open/generate file and message string for uploading a test file to the server
                elif requestType == "testupload":
                    test_file_name = createLargeFile(largeFileSize,username)

                    send_file = open(test_file_name, 'rb')
                    data = send_file.read() 
                    #print data
                    message = pieces[0] + " " + data
                    send_file.close()
                # Handle multiple request types to list directories
                elif requestType == "ls" or requestType == "dir":
                    message = "/ls"
                elif requestType == "download":
                    if len(pieces) > 1:
                        placeholder = ""
                    else:
                        message = ""
            elif message != "":
                message = "/chat " + message
            
            # If the fully prepared message is not blank, send the message to the server
            if message != "":
                message = encryptString(message+endMarker, uniqueKey, ivKey)
                sock.sendall(message)
                

    except:
        PrintException(debugMode)
        sock.shutdown()
        sock.close()


#
# Main Process
#

if __name__ == "__main__":
    try:
        main(sys.argv)
    except:
        PrintException(debugMode)
    finally:
        print "C> Goodbye!"