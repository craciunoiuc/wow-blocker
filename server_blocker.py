
# TCP server to listen for connections on port 3724
# Implementation done for the Warmane server

import socket
import sys
import threading
import datetime

# Challenge sent by the server, will be hardcoded
# This challenge is a one time challenge, so it is fine to expose it.
# For accounts that do not have two factor the last byte is missing.
# Translates to (check wireshark for more info):
'''
Command: Authentication Logon Challenge (0x00)
Protocol version: 0
Error: Success (0x00)
SRP B: e0f2fd58fa216ca8d96a17ce6a09f59040c0c42805869ba9f3e58802f2edfb31
SRP g length: 1
SRP g: 07
SRP N length: 32
SRP N: b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b89
SRP s: cd373815498755f3e0cdb07781d2ac371bf3a12b3946b9a7bf0d3821d6d040e1
CRC salt: baa31e99a00b2157fc373fb369cdd2f1
Two factor enabled: True
'''
response_1 = [
    b'\x00\x00\x00\xf6\xe5\x95\x1e\xb5\x9c?\x88]E\x9d\xe0`\xcb\x1f\xc0\x0fu\xd6M\x1dq\xbeSt\xd9M\xcfN\xb2\xb1\x02\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4\'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x00',
    b'\x00\x00\x00\xb3S\xa0UA\xa3\xd2-\xce\xad9\xd0Z\x0ax\xe5\xbf(\xf4\xc3\xf9\xb8\xaf\xdf\xdeW]r\xa3\xb7\x0d-\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4\'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01',
    b"\x00\x00\x00q\x14\xeb\x13\xb4\xdd_\x1e\xb6m\x07\x0f/z\x9f:\xc2\xff\xf2f\x1a\xbf*\x94\xea\xe3U\x17\xd6\x19_C\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
    b"\x00\x00\x00\x97r\xfd\x85\x9a\x87\x08v7=\xd1\x84Z\xadMq\xe9\xc8'\xc6s\xb9!^-X\xfd+\x80\xa7\x8bY\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
    b"\x00\x00\x00\xd5\x1a\xdd d\xc1\xde^\xe49\x07\xc79\xbc;\xb7\xba\x91\x0e\x99X\xe5\xc5\xd9\xe8\xc7\xb3\x96\xd5c%[\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
    b"\x00\x00\x00#f\x17\xef\xa8j\xb1\x9cQ}\x16\x86\xc6\xe0\xe4\xe3(\xb0x4\xebG\xc6F\x84\x88j\x99D\x04p\x08\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
    b"\x00\x00\x00\xe5U\xed\xd5\xb8\x1e\x85s\xc6\x00\xa9\x1c\xdf*3\xac\xbdR\x1d\x8b\xceW\xa7\xa4\xd1\xe9OmpE\xf7w\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
    b"\x00\x00\x00\xf3Yte\xa7\xea\x91_\x19\xdeAO\xfawW\xd0\x1f\xa6\xa9\xbf\x97\xab%%6\xc7\xbci\xe2\xed\x0ad\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
    b"\x00\x00\x00E\xd7)\xdc!'\xebi\xee\x85\xf7\xfa\xff\xf5\x1aIb\xee\xdf\x92\xe9\xe6\xca7\xc8\x9a\xea\x0dO\xdc\xc3\x83\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
    b"\x00\x00\x00]Q\xb9{\xfb\xa1Y\"w=\xab\x9a]\xc0\x84\x04Y\xe5\xf3\xe0i\x91>'\xac-\x02\xa6]b\x13U\x01\x07 \xb7\x9b>*\x87\x82<\xab\x8f^\xbf\xbf\x8e\xb1\x01\x08SP\x06)\x8b[\xad\xbd[S\xe1\x89^dK\x89\x89V\xc6X_\xc4'\xd8\x01\xd0U\x8d\xdcC\xffr\xee\x9e\xbcJG^/\xc0Q\xf4\x06\x9eZ+k\xb6\xba\xa3\x1e\x99\xa0\x0b!W\xfc7?\xb3i\xcd\xd2\xf1\x04\x01",
]

response_iter = 0

# Response sent by the server. Second byte is the code of the response:
# 0 - Success (sends additional bytes)
# 1 - Unable to connect try again later
# 2 - Unknown error - unused (blocks 3.3.5 client)
# 3 - Account banned (needs additional bytes)
# 4 - Unknown Account
# 5 - Incorrect password - unused (blocks 3.3.5 client)
# 6 - Already logged in
# 7 - Used up all prepaid time
# 8 - Could not log in at this time
# 9 - Could not validate game version - files corrupted
# 10 - Failed version update
# 11 - Unable to connect try again later
# 12 - Account temporarly suspended
# 13 - Unable to connect try again later
# 14 - Success (sends additional bytes)
# 15 - Account restricted by parental controls
response_unknown = b'\x01\x04\x00\x00'
response_banned = b'\x01\x03\x00\x00'

extra_response_3 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # b">\x199e\xfb\xfawz\xd7z\xecq\x8c\xd2\x88h\x07\x19\x99\x1f\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00"

# Account to block, leave empty for all accounts
# if it doesn't match then it will connect to the real server
account_to_block = b'TESTINGACCOUNT'

realm_list = 'logon.warmane.com'

def forward(src: socket, dst: socket):
    # Recv with timeout
    src.settimeout(5)
    while True:
        try:
            data = src.recv(256)
        except socket.timeout:
            print('timeout')
            break
        if data:
            dst.sendall(data)
        else:
            break

def handle_connection(client_socket: socket, server_socket: socket):
    # Create two threads to forward the data in both directions
    t1 = threading.Thread(target=forward, args=(client_socket, server_socket))
    t2 = threading.Thread(target=forward, args=(server_socket, client_socket))

    # Start both threads
    t1.start()
    t2.start()

    # Wait for both threads to finish
    t1.join()
    t2.join()

def conditions_should_block() -> bool:
    # only allow when time between 12PM-12AM
    # if datetime.datetime.now().time().hour > 8:
    #     return False

    return True

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address
server_address = ('0.0.0.0', 3724)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)
try:
    while True:
        should_exit = False
        response_to_use = bytearray(response_1[response_iter % 10])
        response_iter += 1

        # Wait for a connection
        print('waiting for a connection')
        connection, client_address = sock.accept()
        connection.settimeout(2)

        try:
            print('connection from\n', client_address)

            # Receive the data and save it
            saved_data = bytearray()
            while True:
                data = connection.recv(256)
                print('received {!r}'.format(data))
                if data:
                    saved_data.extend(data)
                else:
                    print('no data from\n', client_address)
                    should_exit = True
                    break

                # Add 4 bytes as it does not count the ones before that
                if saved_data[2]+4 == len(saved_data):
                    break

            if should_exit:
                continue

            to_block = False
            if account_to_block in saved_data:
                if conditions_should_block():
                    print('Blocked connection from\n', client_address)
                    to_block = True

            else:
                print('Accepted connection from\n', client_address)
                to_block = False

            if to_block:
                # Set last byte to 1 to enable to factor prompt
                # response_to_use[len(response_to_use) - 1] = 1

                # Send response_to_use
                print('sending response_to_use')
                connection.sendall(response_to_use)

                # Receive all the data from the client and drop it
                connection.settimeout(20)
                while True:
                    data = connection.recv(256)
                    print('received {!r}'.format(data))
                    print('len(data):', len(data))

                    if data:
                        # byte 74 is two factor enabled
                        if data[74] == 4 and data[73] == 0:
                            print('no more data from\n', client_address)
                            break
                        else:
                            print('malformed response\n')
                            should_exit = True

                    else:
                        print('no data from', client_address)
                        break
                connection.settimeout(2)

                if should_exit:
                    continue

                # Send response_2
                print('sending response_2')
                if response_iter % 5 == 0:
                    connection.sendall(response_banned)
                else:
                    connection.sendall(response_unknown)

            else:
                ip_address = socket.gethostbyname(realm_list)

                # In case the IP address is empty or localhost (/etc/hosts use case)
                if ip_address == '' or ip_address == '127.0.0.1':
                    ip_address = '62.138.7.219' # Warmane realm list IP

                # establish connection and send requests to 'logon.warmane.com'

                # Create a new socket to connect to the real server
                # Create a TCP/IP socket
                real = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # Bind the socket to the address
                server_address2 = (ip_address, 3724)

                print('connecting to {} port {}'.format(*server_address2))

                real.connect(server_address2)

                print('connected')

                real.sendall(saved_data)

                handle_connection(connection, real)
        except socket.timeout:
            print('timeout')

        finally:
            # Clean up the connection
            connection.close()
except KeyboardInterrupt:
    print("Caught KeyboardInterrupt, exiting")
    sock.close()
    sys.exit(0)

except Exception as e:
    print("Caught exception", e)
    sock.close()
    sys.exit(1)
