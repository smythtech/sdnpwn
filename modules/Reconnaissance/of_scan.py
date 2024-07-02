
import signal
import socket
from ipaddress import ip_network

from pyof.v0x01.symmetric.hello import Hello as OFv1Hello
from pyof.v0x01.common.header import Header as OFv1Header, Type as OFv1Type
from pyof.v0x01.asynchronous.error_msg import HelloFailedCode, ErrorMsg as OFv1ErrorMsg, ErrorType as OFv1ErrorType

import modules.sdnpwn.sdnpwn_common as sdnpwn
import modules.sdnpwn.sdnpwn_of_helper as of

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Scan a host for ports running OpenFlow and get a list of supported OpenFlow versions"
  
def usage():
  sdnpwn.addUsage(["--target", "-t"], "Set target IP or network (192.168.0.0/24)", True)
  sdnpwn.addUsage(["--port", "-p"], "Set ports to scan(e.g. 6633,6653 || 6000-7000)", True)
  sdnpwn.addUsage(["--socket-timeout", "-s"], "Set timeout for socket connections", False)
  
  return sdnpwn.getUsage()

def getPorts(port):
  ports = [6633,6634,6653]
  if(port == None):
    sdnpwn.message("No ports given, using 6633,6634, and 6653.", sdnpwn.NORMAL)
  elif("," in port):
    ports = port.split(",")
  elif("-" in port):
    ports = []
    for p in range(int(port.split("-")[0]), int(port.split("-")[1])+1):
      ports.append(p)
  else:
    ports.append(port)
  return ports

def getSocket(ip, port, timeout=2):
  try:
    comm_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    comm_sock.settimeout(timeout)
    comm_sock.connect((ip, int(port)))
    return comm_sock
  except Exception as e:
    #print(e)
    return None

def getOFVersion(version):
  return {
      '1': "1.0 (OF_10)",
      '2': "1.1 (OF_11)",
      '3': "1.2 (OF_12)",
      '4': "1.3 (OF_13)",
      '5': "1.4 (OF_14)",
      '6': "1.5 (OF_15)"
    }[version]


def enumerateVersions(target, port, timeout):
  supportedVersions = []
  testVersions = [b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06'] #b'\x01\x00\x00\x08\x00\x00\x00\x05'
  try:
    for v in testVersions:
      sock = getSocket(target, port, float(timeout))
      if(sock == None):
        return
      sock.send(v + b'\x00\x00\x08\x00\x00\x00\x05') 
      resp = of.getResponse(sock)
      if(resp[0].message_type == OFv1Type.OFPT_HELLO):
        resp = of.getResponse(sock)
        if(resp[0].message_type == OFv1Type.OFPT_FEATURES_REQUEST):
          version = getOFVersion(str(resp[0].version))
          supportedVersions.append(version)
      sock.close()
  except:
    pass
  return supportedVersions

def prettyPrint(target, targetResults):
  print("\'" + "-"*100 + "\'")
  print("  IP Address: " + str(target))
  for r in targetResults:
    if(len(r[1]) > 0):
      print("  Port: " + str(r[0]))
      print("  Openflow Versions: " + ", ".join(r[1]))
  print("\'" + "-"*100 + "\'")
  print("\n\n")

def run(params):
  
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
    
  target = sdnpwn.getArg(["--target", "-t"], params)
  port = sdnpwn.getArg(["--port", "-p"], params)
  sockTimeout = sdnpwn.getArg(["--socket-timeout", "-s"], params, 2)
  of.verbose=False
    
  if(target == None):
    print(info())
    print(usage())
    return
  else:
    startIndex = 0
    endIndex = 1
    if("/" in target):
      targets = ip_network(target)
      startIndex = 1
      endIndex = targets.num_addresses-1
    else:
      targets = ip_network(str(target) + "/32")
  
  ports = getPorts(port)
    
  sdnpwn.printNormal("Starting scan")
  for host in range(startIndex, endIndex):
    targetHost = targets[host].exploded
    targetRes = []
    for port in ports:
      try:
        versions = enumerateVersions(targetHost, port, sockTimeout)
      except:
        pass
      
      if(versions is not None):
          targetRes.append((port, versions))
    if(len(targetRes) > 0):
      prettyPrint(targetHost, targetRes)
    
  sdnpwn.printSuccess("Finished")
 
