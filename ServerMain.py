#!/usr/bin/python

import Queue
import socket
import sys
import threading
import linecache
import os
import select

from Crypto.Cipher import AES
from OpenSSL import SSL, crypto

# REST Imports
import web
import xml.etree.ElementTree as ET


# Server specific
exitFlag = 0
messageStorage = []
connectionArray = {}
connectionNames = {}
numBytesPerRequest = 8192
port = 9001

# Consistent between Client and Server
fileDirectory = "files_server/"
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
    print 'S> GOT CERT: %s' % cert.get_subject()
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
        string += str(" ")
    
    return encryptedString.encrypt(string)


def decryptString(string, key, iv):
    decryptedString = ""
    try:
        decryptedString = AES.new(key, AES.MODE_CBC, iv)
        return decryptedString.decrypt(string).rstrip("-")
    except:
        print "S> AES Decrypt Error."
    return ""


def PrintException(errorReporting):
    if errorReporting == 1:
        exc_type, exc_obj, tb = sys.exc_info()
        f = tb.tb_frame
        lineno = tb.tb_lineno
        filename = f.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, f.f_globals)
        print 'S> EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


def clientThread (username, connection, client_ip, numBytesPerRequest):

    connectionArray[client_ip] = connection
    connectionNames[client_ip] = username
    
    # Placed outside inner loop to expand usage
    command = ""
    encryptedString = ""
    
    try:
        print "S> Client from " + str(client_ip) + " has connected: " + str(username)

        # Receive the data in chunks set by numBytesPerRequest, keep looping until no data is being sent
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
                request_type = pieces[0][1:].lower()

                if request_type == "upload":
                    file_name = pieces[1]
                    print "S> " + str(client_ip) + " - " + username + ": " + command[0:29].replace("\n", "")
                    # Do stuff
                    test_file_name = fileDirectory + "s-up.txt"
                    # Open a file in write mode
                    
                    test_file = open(test_file_name, "w")
                    command = command[12:]
                    test_file.write(command)
                    
                    test_file.close()         
                elif request_type == "testupload":
                    print "S> " + str(client_ip) + " - " + username + ": " + command[0:29].replace("\n", "")
                    # Do stuff
                    test_file_name = fileDirectory + "s-testup.txt"
                    # Open a file in write mode
                    test_file = open(test_file_name, "w")
                    command = command[12:]
                    test_file.write(command)
                    
                    test_file.close()                    
                elif request_type == "download":
                    file_name = pieces[1]
                    print "S> " + str(client_ip) + " - " + username + ": " + command
                    
                    transfer_file = open(fileDirectory + str(file_name), "rb")
                    transfer_file = transfer_file.read() 
                    dataRequest = pieces[0] + " " + transfer_file + endMarker
                    
                    connectionArray[client_ip].sendall(encryptString(dataRequest, uniqueKey, ivKey))
                    print "S> " + file_name + " transferred to " + str(client_ip) + " successfully!"
                elif request_type == "ls":
                    print "S> " + str(client_ip) + " - " + username + ": " + command
                    
                    files = os.listdir(fileDirectory)
                    command = pieces[0] + " Files: " + str(files) + endMarker
                    connectionArray[client_ip].sendall(encryptString(command, uniqueKey, ivKey))
                elif request_type == "chat":
                    # Store the chat message in the messageStorage
                    messageStorage.append(command)
                    print "S> " + str(client_ip) + " - " + username + ": " + command
                    # Send message to all active connections if there is a real message
                    if command:
                        for key in connectionArray.keys():
                            if connectionArray[key] != connection:
                                try:
                                    connectionArray[key].sendall(encryptString(pieces[0] + " " + username + ": " +
                                                                               command + endMarker, uniqueKey, ivKey))
                                except:
                                    connectionArray.pop(key, None)
                                    connectionNames.pop(key, None)
                else:
                    # Or: INVALID COMMAND!
                    print "S> INVALID COMMAND " + str(client_ip) + " - " + username + ": " + \
                          command[0:29].replace("\n", "")
            
                # Clear out command after full function executes
                command = ""
                
            else:
                print "this area!"
                # print command[0:19].replace("\n", "")
            

    finally:
        # Clean up the connection
        # connection.recv(numBytesPerRequest)
        
        connection.shutdown()
        connection.close()
        PrintException(debugMode)
        print "S> DISCONNECTED " + str(client_ip) + " - " + username


if __name__ == "__main__":
    
    # Start REST Server...
    tree = ET.parse('user_data.xml')
    root = tree.getroot()
    
    urls = (
        '/users', 'list_users',
        '/users/(.*)', 'get_user'
    )
    
    app = web.application(urls, globals())

    app.run()
    
    argv = sys.argv
    # Finished starting the REST server

    q = Queue.Queue()
    
    try:
        rundir = os.path.dirname(sys.argv[0])
        if rundir == "":
            rundir = os.curdir
    
        # Initialize context
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb) # Demand a certificate
        ctx.use_privatekey_file (os.path.join(rundir, 'keys/server/server.pkey'))
        ctx.use_certificate_file(os.path.join(rundir, 'keys/server/server.cert'))
        ctx.load_verify_locations(os.path.join(rundir, 'keys/server/CA.cert'))

        # Create a TCP/IP socket
        sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        
        # Bind the socket to the port
        # server_address = ("localhost", port)
        # print >>sys.stderr, "S> Starting server on port" + str(server_address)

        sock.bind(('', port))
        # Listen for incoming connections
        sock.listen(3)
        sock.setblocking(0)

        # Client connection counter
        i = 0
        
        clients = {}
        writers = {}
        
        print >>sys.stderr, "S> LISTENING ON: " + str(port)
        print 'S> Waiting for a client to connect...'
        
        # Repeat indefinitely to handle an indefinite number of connection
        while True:
            # Wait for a connection
            r, w, _ = select.select([sock]+clients.keys(), writers.keys(), [])
            
            # Accept the new connection
            connection, client_ip = sock.accept()
            tempUsername = decryptString(connection.recv(numBytesPerRequest), uniqueKey, ivKey)

            threadID = i + 1

            t = threading.Thread(target=clientThread, args=(tempUsername, connection, client_ip, numBytesPerRequest))
            t.daemon = True
            t.start()
            q.put(t)

            i = threadID
            
            # time.sleep(0.1)

    finally:
        for tempConnection in connectionArray:
            tempConnection.shutdown()
            tempConnection.close()
        print "S> Goodbye!"


class ListUsers:
    def __init__(self):
        pass

    @staticmethod
    def get():
        output = 'users:['
        for child in root:
                    print 'child', child.tag, child.attrib
                    output += str(child.attrib) + ','
        output += ']'
        return output


class GetUser:
    def __init__(self):
        pass

    @staticmethod
    def get(self, user):
        for child in root:
            if child.attrib['id'] == user:
                print str(child.attrib)
                return str(child.attrib)
