
import signal
from scapy.all import *
import modules.sdnpwn.sdnpwn_common as sdnpwn
import modules.sdnpwn.sdnpwn_of_helper as ofHelper

from pyof.v0x01.common.header import Header, Type
from pyof.v0x01.controller2switch.features_reply import FeaturesReply

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Perform passive information gathering on an OpenFlow connection."
  
def usage():
  sdnpwn.addUsage(["-i", "--iface"], "Interface to listen on", True)
  
  return sdnpwn.getUsage()

def handlePkt(pkt):
  if(TCP in pkt and len(pkt[TCP].payload) > 0):
    try:
      ofHeader = Header()
      ofHeader.unpack(bytes(pkt[TCP].payload)[:8])
      
      print("[>] " + str(pkt[IP].src) + " -> ", end='')
      print("OFv" + str(ofHeader.version), end=' ')
      print(ofHeader.message_type, end=' -> ')
      print(str(pkt[IP].dst))
      
      #ofBody = ""
      #try:
        ##TODO: Allow for detailed message information to be printed
        #ofBody = bytes(pkt[TCP].payload)[:(ofHeader.length-8)]
        #if((ofHeader.message_type & 0xFF) == 6):
          #ofFeatureReply = FeaturesReply()
          #ofFeatureReply.unpack(ofBody)
          #ofHelper.printFeatureReplyDetails(ofFeatureReply)
      #except Exception as e:
        #print(e)
        
    except:
      #Not an OF message
      pass
  
def run(params):
  
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
  if(sdnpwn.checkArg(["-i", "--iface"], params)):  
    sniff(iface=sdnpwn.getArg(["-i", "--iface"], params), prn=handlePkt)
  
  
  
