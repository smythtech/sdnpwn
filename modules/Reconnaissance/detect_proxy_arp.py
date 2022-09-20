
import signal
from scapy.all import *

import modules.sdnpwn.sdnpwn_common as sdnpwn

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  return

def info():
  return "This module will check if an ARP proxy is running on the controller."
  
def usage():
  sdnpwn.addUsage(["-i", "--iface"], "Interface to use (Default eth0)", False)
  sdnpwn.addUsage(["-v", "--verbose"], "Enable verbose output", False)
  
  return sdnpwn.getUsage()

def run(params):
  
  signal.signal(signal.SIGINT, signal_handler) # Assign the signal handler
  
  iface = sdnpwn.getArg(["-i", "--iface"], params, "eth0")
  verbose = sdnpwn.checkArg(["-v", "--verbose"], params)
  
  try:
    if(verbose):
      sdnpwn.printVerbose("Getting MAC and IP address for interface " + iface)
      
    ifaceIP = sdnpwn.getIPAddress(iface)
    ifaceMac = sdnpwn.getMacAddress(iface)
    
    if(ifaceMac == "0" or ifaceIP == "0"):
      sdnpwn.printError("Cannot get details for interface " + iface + " ")
      return

    if(verbose):
      sdnpwn.printVerbose("Making this host known in the network")
    
    sendp(Ether(src=ifaceMac, dst="FF:FF:FF:FF:FF:FF", type=0x0806)/ARP(op=ARP.is_at, psrc=ifaceIP, hwsrc=ifaceMac, pdst=ifaceIP)) # We just want the controller to know about this host
      
    sdnpwn.printNormal("Sending ARP request for this host...")
    
    resp = srp(Ether(src=ifaceMac, dst="FF:FF:FF:FF:FF:FF", type=0x0806)/ARP(op=ARP.who_has, pdst=ifaceIP), timeout=2)
    
    try:
      if(resp[0][ARP][0][1].psrc == ifaceIP):
        sdnpwn.printWarning("Proxy ARP is active")
      else:
        sdnpwn.printError("Got another address: " + resp[0][ARP][0][1].psrc)
    except:
      # This should only fail if there is no response or the response is not ARP.
      sdnpwn.printSuccess("Proxy ARP is not active")
      
  except Exception as e:
    print(e)
    
