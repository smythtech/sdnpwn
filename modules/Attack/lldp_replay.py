
import signal
from scapy.all import *

import modules.sdnpwn.sdnpwn_common as sdnpwn

class FrameHandler:
  iface=None
  outFile=None
  
  def __init__(self, iface, outFile):
    self.iface = iface
    self.outFile = outFile
  
  def handler(self, pkt):
    if(pkt.type == 0x88cc): #frame is LLDP
      sdnpwn.message("Got LLDP frame...", sdnpwn.NORMAL)
      wrpcap(self.outFile, pkt)
    

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  #Description of the what the module is and what it does. This function should return a string.
  return "Replays LLDP traffic observed at a given interface back out the same interface."
  
def usage():
  '''
  How to use the module. This function should return a string.
  sdnpwn_common contains functions to print the module usage in a table. 
  These functions are "addUsage", "getUsage", and "printUsage". "addUsage" and "getUsage" are shown below.
  The parameters for addUsage are option, option description, and required (True or False)
  '''
  sdnpwn.addUsage("-i | --iface", "Interface to use", True)
  sdnpwn.addUsage("-c | --count", "Times to replay (Default 1)", False)
  sdnpwn.addUsage("-w | --capture", "Capture LLDP frame to file", False)
  sdnpwn.addUsage("-r | --replay", "Replay captured LLDP frame from file", False)
  
  return sdnpwn.getUsage()

def run(params):
  
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
  iface = sdnpwn.getArg(["--iface", "-i"], params)
  count = sdnpwn.getArg(["--count", "-c"], params, 1)
  
  if(sdnpwn.checkArg(["--capture", "-w"], params)):
    outFile = sdnpwn.getArg(["--capture", "-w"], params)
    frameHandler = FrameHandler(iface, outFile)
    sdnpwn.message("Starting listener on interface " + iface, sdnpwn.NORMAL)
    sniff(iface=iface, store=0, prn=frameHandler.handler, count=1, filter="ether proto 0x88cc")
    sdnpwn.message("LLDP frame saved to " + outFile, sdnpwn.SUCCESS)
  elif(sdnpwn.checkArg(["--replay", "-r"], params)):
    inFile = sdnpwn.getArg(["--replay", "-r"], params)
    pkt = rdpcap(inFile)
    for c in range(int(count)):
      sendp(pkt, iface=iface)
    sdnpwn.message("Replayed  " + inFile + " " + str(count) + " times", sdnpwn.SUCCESS)
