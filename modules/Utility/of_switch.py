
import signal

import modules.sdnpwn.sdnpwn_common as sdnpwn
#import modules.sdnpwn.sdnpwn_of_helper as of
import modules.sdnpwn.ofv10.sdnpwn_ofv10_switch as ofv10
import modules.sdnpwn.ofv13.sdnpwn_ofv13_switch as ofv13
import socket
import json
import threading

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
  sdnpwn.addUsage("-V | --of-version", "Openflow version (1.0 or 1.3) (Default Openflow 1.0)", False)
  sdnpwn.addUsage("-c | --controller", "IP address of controller (Default 127.0.0.1)", False)
  sdnpwn.addUsage("-p | --port", "Openflow port on controller (Default 6633)", False)
  sdnpwn.addUsage("-r | --config", "Switch configuration file to use", True)
  sdnpwn.addUsage("-l | --listen", "Port for switch relay proxy", False)
  sdnpwn.addUsage("-o | --output-to", "Interface to forward packet out message payloads", False)
  sdnpwn.addUsage("-f | --output-filter", "Filter packets by output port. Use with -o", False)
  sdnpwn.addUsage("-s | --save-connection-data", "Save basic connection data and flows received from the controller to files", False)
  sdnpwn.addUsage("-v | --verbose", "Enable verbose output", False)

  return sdnpwn.getUsage()

def run(params):

  verbose = False
  saveData = False

  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler

  ofVersion = sdnpwn.getArg(["--of-version", "-V"], params, "1.0")
  controllerIP = sdnpwn.getArg(["--controller", "-c"], params, "127.0.0.1")
  controllerPort = sdnpwn.getArg(["--port", "-p"], params, 6633)
  configFile = sdnpwn.getArg(["--config", "-r"], params)

  packetOutForwardingIFace = sdnpwn.getArg(["--output-to", "-o"], params)

  packetOutForwardingFilter = sdnpwn.getArg(["--output-filter", "-f"], params)

  saveData = sdnpwn.checkArg(["--save-connection-data", "-s"], params)

  verbose = sdnpwn.checkArg(["--verbose", "-v"], params)

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

  if(ofVersion == "1.3"):
    sdnpwn.message("Creating new Openflow 1.3 switch instance", sdnpwn.NORMAL)
    ofSwitch = ofv13.OpenFlowV13Switch()
  else:
    sdnpwn.message("Creating new Openflow 1.0 switch instance", sdnpwn.NORMAL)
    ofSwitch = ofv10.OpenFlowV10Switch()

  ofSwitch.loadConfiguration(config)
  ofSwitch.auto_handle_Messages = True
  ofSwitch.save_connection_data = saveData
  ofSwitch.enable_output = verbose

  if(sdnpwn.checkArg(["--listen", "-l"], params)):
    rsPort = sdnpwn.getArg(["--listen", "-l"], params)
    rsThread = threading.Thread(target=ofSwitch.activateRelaySocket, args=(int(rsPort),))
    rsThread.setDaemon(True)
    rsThread.start()

  if(packetOutForwardingIFace is not None):
    ofSwitch.forward_packet_out_payload = True
    ofSwitch.forward_packet_out_iface = packetOutForwardingIFace
    if(packetOutForwardingFilter is not None):
      ofSwitch.forward_packet_out_port_filter = packetOutForwardingFilter

  ofSwitch.connect(controllerIP, int(controllerPort))

