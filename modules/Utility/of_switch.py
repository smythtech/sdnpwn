
import signal

import modules.sdnpwn.sdnpwn_common as sdnpwn
import modules.sdnpwn.sdnpwn_of_helper as of
import socket
import json
import threading


from pyof.v0x01.controller2switch.features_reply import FeaturesReply
from pyof.v0x01.common.header import Header

from time import sleep

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit()
  return

def info():
  #Description of the what the module is and what it does. This function should return a string.
  return "OpenFlow Switch"
  
def usage():
  '''
  How to use the module. This function should return a string.
  sdnpwn_common contains functions to print the module usage in a table. 
  These functions are "addUsage", "getUsage", and "printUsage". "addUsage" and "getUsage" are shown below.
  The parameters for addUsage are option, option description, and required (True or False)
  '''
  sdnpwn.addUsage("-c | --controller", "IP address of controller (Default 127.0.0.1)", False)
  sdnpwn.addUsage("-p | --port", "Openflow port on controller (Default 6633)", False)
  sdnpwn.addUsage("-r | --config", "Switch configuration file to use", True)
  sdnpwn.addUsage("-l | --listen", "Port for switch relay proxy", False)
  sdnpwn.addUsage("-o | --output-to", "Interface to forward packet out message payloads", False)
  sdnpwn.addUsage("-f | --output-filter", "Filter packets by output port. Use with -o", False)
  sdnpwn.addUsage("-v | --verbose", "Enable verbose output", False)
  
  return sdnpwn.getUsage()

def activateRelaySocket(port):
  global ofSwitch
  
  hostname = socket.gethostbyname(socket.gethostname())
  listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  listenSock.bind(("0.0.0.0", port))
  listenSock.listen(1)
  data = b''
  sdnpwn.message("[Relay Socket] Relay port open on port " + str(port) + "", sdnpwn.NORMAL)
  while 1:
    try:
      conn, addr = listenSock.accept()
      msgHeader = conn.recv(8)
      header = Header()
      header.unpack(msgHeader)
      sdnpwn.message("[Relay Socket] Got " + str(header.message_type) + " from " + str(addr), sdnpwn.NORMAL)
      msgBody = conn.recv(header.length-8)
      msgFull = header.pack() + msgBody
      print(msgFull)
      ofSwitch.comm_sock.send(msgFull)
    except Exception as e:
      sdnpwn.message("[Relay socket] Error handling message", sdnpwn.WARNING)
      print(e)
  listenSock.close()

def run(params):
  global ofSwitch
  
  verbose = False
  
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
  controllerIP = sdnpwn.getArg(["--controller", "-c"], params, "127.0.0.1")
  controllerPort = sdnpwn.getArg(["--port", "-p"], params, 6633)
  configFile = sdnpwn.getArg(["--config", "-r"], params)
  
  packetOutForwardingIFace = sdnpwn.getArg(["--output-to", "-o"], params)
  
  packetOutForwardingFilter = sdnpwn.getArg(["--output-filter", "-f"], params)
  
  if(sdnpwn.checkArg(["--listen", "-l"], params)):
    rsPort = sdnpwn.getArg(["--listen", "-l"], params)
    rsThread = threading.Thread(target=activateRelaySocket, args=(int(rsPort),))
    rsThread.setDaemon(True)
    rsThread.start()
    
  verbose = sdnpwn.checkArg(["--verbose" "-v"], params)
  
  if(configFile == ""):
    sdnpwn.message("Please provide a switch configuration file using the --config option", sdnpwn.ERROR)
    return
  
  configRaw = open(configFile, 'r')
  config = ""
  try:
    config = json.load(configRaw)
  except Exception as e:
    sdnpwn.message("Could not read config as JSON file. Please check syntax.", sdnpwn.ERROR)
    sdnpwn.message(e, sdnpwn.VERBOSE)
  
  config = config["of-switch"]

  ofSwitch = of.OpenFlowSwitch()
  ofSwitch.loadConfiguration(config)
  ofSwitch.auto_handle_Messages = True
  ofSwitch.enable_output = verbose
  
  if(packetOutForwardingIFace is not None):
    ofSwitch.forward_packet_out_payload = True
    ofSwitch.forward_packet_out_iface = packetOutForwardingIFace
    if(packetOutForwardingFilter is not None):
      ofSwitch.forward_packet_out_port_filter = packetOutForwardingFilter
  
  ofSwitch.connect(controllerIP, int(controllerPort))
  
