# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  serverPort = 8080
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  serverSocket.bind(('', serverPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  serverSocket.listen(1)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    cacheData = ''.join(cacheData)
    clientSocket.sendall(cacheData.encode())
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      print("TEST")
      originServerSocket.connect((address, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = f"GET {resource} HTTP/1.1"
      originServerRequestHeader = f"Host: {hostname}"
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      data_from_response = b''
      originServerSocket.settimeout(1.0)

      # Boolean to check if response should be cached
      NO_CACHE = False

      # Loop to get data
      while True:
        try:
          # Get Data in segments of length BUFFER_SIZE
          segment = originServerSocket.recv(BUFFER_SIZE)

          # Break out of loop if no more data
          if not segment:
            break
          data_from_response += segment

          # Check if blank line is in response header, indicating end of header
          if b'\r\n\r\n' in data_from_response:
            header_contents = data_from_response.split(b'\r\n')
            
            # RFC Standards Check Booleans
            expires_check = False
            max_age_check = False
            cache_control_check = False
            no_store_check = False

            for header in header_contents:
              # RFC 7234-3
              if header.endswith(b'no-store'):
                no_store_check = True
              if header.startswith(b'Expires: '):
                expires_check = True
              if b"max-age" in header or b"s-maxage" in header:
                max_age_check = True
              if header.startswith(b"Cache-Control: "):
                cache_control_check = True
              
            # MUST NOT UNLESS in RFC 7234-3
            if (expires_check or max_age_check or cache_control_check):
              NO_CACHE = False
            if no_store_check:
              NO_CACHE = True

            # Check status code
            status = header_contents[0].decode()
            
            print("STATUS OF RESPONSE: ", status)
            # If status is 404 or 301/302
            if "404" in status:
              print(f"404 Page Not Found: {status}")
              NO_CACHE = True
              break
            # If 301/302
            elif "301" in status or "302" in status:
              for header in header_contents:
                # Find redirect location
                if header.startswith(b'Location'):
                  redirect_uri = header.split(b': ')[1].decode()
                  print(f"Redirecting to: {redirect_uri}")

                  # Close and reopen socket to origin server to new location
                  originServerSocket.close()
                  originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                  # Uses template code provided above to get URI, hostname and resource
                  if redirect_uri.startswith("/"):
                    resource = redirect_uri
                  else:
                    URI = redirect_uri
                    URI = re.sub('^(/?)http(s?)://', '', URI, count=1)
                    URI = URI.replace('/..', '')
                    resourceParts = URI.split('/', 1)
                    hostname = resourceParts[0]
                    resource = '/'

                    if len(resourceParts) == 2:
                      resource = resource + resourceParts[1]

                  # Connect to new address
                  print("NEW LOCATION: ", hostname, resource)
                  address = socket.gethostbyname(hostname)
                  originServerSocket.connect((address, 80))

                  # Create new request
                  originServerRequest = f"GET {resource} HTTP/1.1"
                  originServerRequestHeader = f"Host: {hostname}"
                  request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'
                  print("NEW REQUEST: ", request)

                  # Send redirect request
                  originServerSocket.sendall(request.encode())

                  # Update cache location to redirect location
                  cacheLocation = './' + hostname + resource
                  if cacheLocation.endswith('/'):
                    cacheLocation = cacheLocation + 'default'

                  # Reset data from response
                  data_from_response = b''
                  break
              continue
            # default case (e.g. 200)
            else:
              break
        except socket.timeout:
          break
      print("Data Received From Origin")
      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(data_from_response)
      print("Sent Response to Client")
      # ~~~~ END CODE INSERT ~~~~

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~
      # If caching is allowed (boolean set above)
      if not NO_CACHE:
        cacheFile.write(data_from_response)
      else:
        # Remove cache file generated as not needed
        # TODO: Also remove parent directories
        # This is being heavily limited by the fact that I can't edit code outside here
        # and not perform a filepath creation if NO_CACHE is True
        os.remove(cacheLocation)
      # ~~~~ END CODE INSERT ~~~~
      cacheFile.close()
      print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
