#!/usr/bin/env python3



import argparse
import socket
import ssl
from spider import MyHTMLParser


# Constants
HOST = "project2.5700.network"
PORT = 443
FORMAT = "utf-8"
BUFFER = 4096

CSRF_TOKEN = None
SESSION_ID = None

HOME_URL =  "/fakebook/"
LOGIN_URL = '/accounts/login/'
NEXT_URL = '/?next=/fakebook/'
HTTP_VERSION = 'HTTP/1.1'
HOST_NAME_HEADER = f'Host: {HOST}'
CSRF_HEADER = 'Cookie: csrftoken='
SESSION_ID_HEADER = 'sessionid='
CONTENT_TYPE_HEADER = 'Content-Type: application/x-www-form-urlencoded'
CONTENT_LENGTH_HEADER = 'Content-Length: '
CONN_ALIVE_HEADER = 'Connection: keep-alive'

#
# Input Function:
# Using argparse library to get command line arguments from user
# 
# input should contain username and password
#
def get_input():
    parser = argparse.ArgumentParser()
    parser.add_argument('username', type=str, help='Server hostname')
    parser.add_argument('password', type=str, help='Northeastern email')
    args = parser.parse_args()
    return args.username, args.password


# 
#
# Function to create sock instance and connect tot the HOST and PORT
#
#
#
def connect_to_host():
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the server
        sock.connect((HOST, PORT))

        # Wrap socket in SSL/TLS format
        context = ssl.create_default_context()

        ssock = context.wrap_socket(sock, server_hostname=HOST)

        return ssock
    
    except Exception as error:
        print("Error:", error)
        return None
#
#
#
# Send GET request for retrieving CSRF token and session ID
#
#
#
def send_get_request_generic(SOCK, PATH, CSRF_TOKEN=None, SESSION_ID=None):
    get_request = (
        f"GET {PATH} HTTP/1.1\r\n",
        f"Host: {HOST}\r\n",
        f'{CSRF_HEADER}{CSRF_TOKEN}; {SESSION_ID_HEADER}{SESSION_ID}',
        "\r\n",
        "Connection: keep-alive\r\n"
        "\r\n"
    )

    get_request = "".join(get_request)

    try:
        # Send GET request to server
        SOCK.send(get_request.encode(FORMAT))

    except Exception as error:
        print("ERROR: ", error)
        return  

# 
# 
# function to send a post request to login to Fakebook
# 
# 
#         
def login_post(SOCKET, USERNAME, PASSWORD, CSRF_TOKEN, SESSION_ID):
    
    # build the HTTP POST message
    content = f'username={USERNAME}&password={PASSWORD}&csrfmiddlewaretoken={CSRF_TOKEN}&next=%2Ffakebook%2F'
    message_lines = [
        f'POST {LOGIN_URL} {HTTP_VERSION}',
        HOST_NAME_HEADER,
        f'{CSRF_HEADER}{CSRF_TOKEN}; {SESSION_ID_HEADER}{SESSION_ID}',
        CONTENT_TYPE_HEADER,
        f'{CONTENT_LENGTH_HEADER}{len(content)}',
        CONN_ALIVE_HEADER,
        '',
        content
    ]
    
    login_message = '\r\n'.join(message_lines)
    
    try:
        # send the login request message to the server
        SOCKET.sendall(login_message.encode(FORMAT))

    except Exception as e:
        print('ERROR: ', e)
        return


#
#
# Function to get the location of the headers
#
#
#
def get_location(headers):
    """Extracts the Location URL from the headers of an HTTP response."""
    #split header line and find location
    for header in headers.split('\r\n'):
        if header.startswith('Location:'):
            return header.split(': ')[1]
    return None


#
#
#
# gets length of the content header 
#
#
def get_length(msg):
    """Return the value of the Content-Length header, or 0 if the header is not found or malformed"""
    # Read incoming message and get content length
    lines = msg.split('\r\n')
    for line in lines:
        if line.startswith(CONTENT_LENGTH_HEADER):
            parts = line.split(':')
            if len(parts) == 2:
                length = parts[1].strip()
                if length.isdigit():
                    return length
    return '0'


#
#
#Function to recieve back the response and parse the message into headers and body section
#
#
#
def receive_response(SOCK):
    response = ''
    # recieve the response in a loop for continous response
    while True:
        chunk = SOCK.recv(BUFFER).decode()
        if not chunk:
            break
        response += chunk

        if '\r\n\r\n' in response:
            headers, body = response.split('\r\n\r\n', 1)
            content_length = get_length(headers)
            while len(body) < int(content_length):
                chunk = SOCK.recv(BUFFER).decode()
                if not chunk:
                    break
                body += chunk
            return headers, body
    # returns none if either header, body or both are not in response
    return None, None


#
#
#Function to parse the header and retreive the status code, csrf token and session id
#
#
#
def parse_http_header(header):
    lines = header.split("\r\n")
    status_code = int(lines[0].split()[1])
    csrf_token = None
    session_id = None
    for line in lines:
        if "csrftoken" in line:
            key, value = line.split("=", 1)
            csrf_token = value.split(";")[0]
        elif "sessionid" in line:
            key, value = line.split("=", 1)
            session_id = value.split(";")[0]

    return {"status_code": status_code, "csrf_token": csrf_token, "session_id": session_id}

#
#
#  Main Crawl function that utilizes MyHTMLParser to detect tags 
#  as well as check and handle differeing status codes
# 
# 
#     
def web_crawl(BODY, SOCK, CSRF_TOKEN, SESSION_ID):
    parser = MyHTMLParser()
    # get html body of the response and feed it to the parse links
    parser.feed(BODY)    

    # keep crawling until all flags are found or queue is empty
    while len(parser.secretFlags) != 5:
        # get the first site to be visited
        LINK = (parser.pagesToVisit.popleft())
        
        # if the current link is not in the visited link list we can visit it now
        if LINK not in parser.pagesVisited: 
            
            # send a get request to the link
            send_get_request_generic(SOCK, LINK, CSRF_TOKEN, SESSION_ID)

            # recieve the response and seperate into HEADER and BODY
            HEADER, BODY = receive_response(SOCK)

            # get session details that includes cookies
            session_details = parse_http_header(HEADER)
            status_code = session_details.get('status_code')

            if status_code == 200:
                if session_details.get('csrf_token') is not None:
                    CSRF_TOKEN = session_details.get('csrf_token')
                if session_details.get('session_id') is not None:
                    SESSION_ID = session_details.get('session_id')
                # add page to visited pages    
                parser.pagesVisited.add(LINK)
                # get next page contents
                parser.feed(BODY)
                
            elif status_code == 301:
                # Try the request again using the new URL given by the server
                new_url = HEADER.split("\r\n")[-1].split(" ")[1]
                send_get_request_generic(SOCK, new_url, CSRF_TOKEN, SESSION_ID)
                HEADER, BODY = receive_response(SOCK)
                session_details = parse_http_header(HEADER)
                if session_details.get('csrf_token') is not None:
                    CSRF_TOKEN = session_details.get('csrf_token')
                if session_details.get('session_id') is not None:
                    SESSION_ID = session_details.get('session_id')
                # add page to visited pages    
                parser.pagesVisited.add(LINK)
                # get next page contents
                parser.feed(BODY)

            elif status_code in [403, 404]:
                # Abandon the URL that generated the error code
                continue

            elif status_code == 500:
                # Re-try the request for the URL until the request is successful
                while status_code == 500:
                    send_get_request_generic(SOCK, LINK, CSRF_TOKEN, SESSION_ID)
                    HEADER, BODY = receive_response(SOCK)
                    session_details = parse_http_header(HEADER)
                    status_code = session_details.get("status_code")
                if session_details.get('csrf_token') is not None:
                    CSRF_TOKEN = session_details.get('csrf_token')
                if session_details.get('session_id') is not None:
                    SESSION_ID = session_details.get('session_id')
                
                # add page to visited pages    
                parser.pagesVisited.add(LINK)
                # get next page contents
                parser.feed(BODY)



#
# Main function connects to the 
# 
# @param = username
# @param = password
# @param = url 
# returns N/A
#
#
def main(USERNAME, PASSWORD, HOST):



    # Connect to host and attempt a login
    Ssock = connect_to_host()
    if Ssock is None:
        return
    
    # send generic get request to the login page to get the first set of cookies
    send_get_request_generic(Ssock, LOGIN_URL)

    # recieve the response and break up into headers and html body
    header, body = receive_response(Ssock)

    # get session details from the headers
    session_details = parse_http_header(header)

    # get status code from get request
    status_code = session_details.get('status_code')

    # check if we got a 200 for status code
    if status_code != 200:
        print("Get request failed")
        return
    
    # assign cookies
    CSRF_TOKEN = session_details.get('csrf_token')
    SESSION_ID = session_details.get('session_id')

    # send a login post to the login page to login
    login_post(Ssock, USERNAME, PASSWORD, CSRF_TOKEN, SESSION_ID)

    # recieve and extract new response headers/body
    header, body = receive_response(Ssock)
    session_details = parse_http_header(header)
    status_code = session_details.get('status_code')

    # check if we got a 302 for status code
    if status_code != 302:
        print("Login failed")
        return

    # check to see that new cookies are actually present if they are assign them to 
    # as the new CSRF token and the new session ID
    if session_details.get('csrf_token') is not None:
        CSRF_TOKEN = session_details.get('csrf_token')
    if session_details.get('session_id') is not None:
        SESSION_ID = session_details.get('session_id')

    # Got successful login code so we can now query the home page and begin to crawl
    send_get_request_generic(Ssock, HOME_URL, CSRF_TOKEN, SESSION_ID)
    header, body = receive_response(Ssock)

    web_crawl(body, Ssock, CSRF_TOKEN, SESSION_ID)

    Ssock.close()


if __name__ == "__main__":
    
    USERNAME, PASSWORD = get_input()
    main(USERNAME, PASSWORD, HOST)