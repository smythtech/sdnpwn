
import modules.sdnpwn.sdnpwn_common as sdnpwn

from scapy.all import sniff, ARP
import sys
import subprocess
import errno
import signal

class packetHandler:

   mode = None #Modes = watch, map
   hostMacMap = {}
   hostList = None
   currentPacket="";

   def __init__(self):
      currentPacket="";

   def packetIn(self, pkt):
      currentPacket=pkt;
      
      if ARP in pkt:
         self.arpIn(pkt);

   def arpIn(self, pkt):
      arpTypes=['', 'who-is', 'is-at'];
      try:
         arpType=arpTypes[pkt.op];
      except:
         arpType="Unknown";
         
      srcIp=pkt.psrc
      srcMac=pkt.hwsrc
      dstIp=pkt.pdst
      
      if(self.mode == "watch"):
        #print("\n" );
        if(arpType == "who-is"):
          print(f"From {srcIp} ({srcMac}) {arpType} to {dstIp}");
        elif(arpType == "is-at"):
          print(f"{srcIp} {arpType} {srcMac} to {dstIp}");

      elif(self.mode == "map"):
        if(str(dstIp) not in self.hostMacMap):
          self.hostMacMap[dstIp] = "?"
        if(str(srcIp) not in self.hostMacMap):
          self.hostMacMap[srcIp] = srcMac
          printHostMacMap(self.hostMacMap);
        else:
          if(self.hostMacMap[srcIp] != srcMac):
            self.hostMacMap[srcIp] = srcMac
            printHostMacMap(self.hostMacMap);

def printHostMacMap(hostMacMap):
    subprocess.call("clear")
    print("IP\t\t\t\tMac");
    for h in sorted(hostMacMap):
      print(f"{h}\t\t\t{hostMacMap[h]}");

def signal_handler(signal, frame):
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Monitors ARP requests and responses received at a particular interface. Watch mode simply print details of ARP traffic seen. Map mode will create a table of IPs mapped to MAC addresses based on sniffed ARP traffic."
  
def usage():
  
  sdnpwn.addUsage("-i | --iface", "Interface to use", True)
  sdnpwn.addUsage("-m | --mode", "Set mode ( watch or map ). Default: watch", False)
   
  return sdnpwn.getUsage()

def run(params):	
   
  intf = sdnpwn.getArg(["--iface", "-i"], params)
  if(sdnpwn.checkArg(["--mode", "-m"], params)):
    mode = sdnpwn.getArg(["--mode", "-m"], params)
  else:
    mode = "watch"
       
  if((mode != None) and (intf != None)):
     pktHandler = packetHandler();
     pktHandler.mode = mode
     sdnpwn.message(f"Starting sniffer on interface {intf}\n", sdnpwn.NORMAL);
     signal.signal(signal.SIGINT, signal_handler)
     sniff(iface=intf, prn=pktHandler.packetIn)
  else:
     print(info())
     print(usage())


