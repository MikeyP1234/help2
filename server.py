import socket
import json
import random
import datetime
import hashlib
import sys
keyDict={}
def parseMessage(m):
    lines = m.split("\r\n")
    start_line = lines[0]
    method,target,version = start_line.split(" ")
    headers = {}
    sum=0
    for header in lines[1:]:
        if header=="":
            break 
        sum=sum+1
        hkey,hval = header.split(": ",1)
        headers[hkey] = hval
    return method,target,version,headers
def postRequest(headers,jsonFile,version):
    cdt2=datetime.datetime.now().timestamp()
    cdt=datetime.datetime.now()
    cdtb=cdt.strftime("%Y-%m-%d-%H-%M-%S")
    if 'username' not in headers or 'password' not in headers:
        print("SERVER LOG: "+cdtb+" LOGIN FAILED")
        return version+" 501 Not Implemented\r\n\r\n"
    access=authenticatePassword(headers['username'],headers['password'],jsonFile)
    if access==1:
        num=hex(random.getrandbits(64))
        sessionID="sessionID="+num
        keyDict[num]=headers['username'],cdt2
        print("SERVER LOG: "+cdtb+" LOGIN SUCCESSFUL: "+headers['username']+" : "+headers['password'])
        return version+" 200 OK\r\nSet-Cookie: "+sessionID+"\r\n\r\nLogged In!"
    else:
        print("SERVER LOG: "+cdtb+" LOGIN FAILED: "+headers['username']+" : "+headers['password'])
        return version+" 200 OK\r\n\r\nLogin Failed!"
def authenticatePassword(username,password,jsonFile):
    sha256=hashlib.sha256()
    with open(jsonFile) as json_file:
        dict=json.load(json_file)
        hexdata=dict[username]
        hexednum=hexdata[0]
        salt=hexdata[1]
        sha256.update(password.encode())
        sha256.update(salt.encode())
        if hexednum==sha256.hexdigest():
            return 1
        else:
            return 0  
def getRequest(headers,target,seshTimeout,rootDirectory,version):
    if 'Cookie' not in headers:
        return version+" 401 Unauthorized\r\n\r\n"
    cdt2=datetime.datetime.now().timestamp()
    cdt=datetime.datetime.now()
    cdtb=cdt.strftime("%Y-%m-%d-%H-%M-%S")
    cookie=str(headers['Cookie'])
    id, cookie=cookie.split("=")
    cookie=cookie.replace('/r','')
    cookie=cookie.strip()
    if cookie not in keyDict:
        print("SERVER LOG: "+cdtb+" COOKIE INVALID: "+target)
        return version+" 401 Unauthorized\r\n\r\n"
    else:
        cookiedata=keyDict[cookie]
        user=str(cookiedata[0])
        cookietime=cookiedata[1]
        t1=cookietime
        t2=cdt2 
        tdelta=t2-t1
        seshion=int(seshTimeout)
        if tdelta<=seshion:
            keyDict[cookie]=user,cdt2
            search=rootDirectory+user+target
            search=search.strip()
            try:
                f=open(search,"r")
                message=f.read()
                print("SERVER LOG: "+cdtb+" GET SUCCEEDED: "+user+" : "+target)
                return version+" 200 OK\r\n\r\n"+message
            except IOError:
                print("SERVER LOG: "+cdtb+" GET FAILED: "+user+" : "+target)
                return version+" 404 NOT FOUND\r\n\r\n"
                    
        else:
            print("SERVER LOG: "+cdtb+" SESSION EXPIRED "+user+" : "+target)
            del keyDict[cookie]
            return version+" 401 Unauthorized\r\n\r\n"
        
    
    
def startServer(IPaddress,portNum,jsonFile,seshTimeout,rootDirectory):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip=IPaddress
    pN=int(portNum)
    server_socket.bind((ip, pN))
    server_socket.listen()
    while True:
        client_socket, client_address = server_socket.accept()
        hello_msg = client_socket.recv(1024).decode()
        method,target,version,headers=parseMessage(hello_msg)
        version="HTTP/1.0"
        if method=="POST" and target=="/":
            msg=postRequest(headers,jsonFile,version)
            client_socket.sendall(msg.encode())
        elif method=="GET":
            msg=getRequest(headers,target,seshTimeout,rootDirectory,version)
            client_socket.sendall(msg.encode())
        else:
            client_socket.sendall((version+" 501 Not Implemented"+"\r\n\r\n").encode())
        client_socket.close()
        
if __name__ == '__main__':
    startServer(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5])
