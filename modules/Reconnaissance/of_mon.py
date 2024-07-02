
import signal
from scapy.all import *
import modules.sdnpwn.sdnpwn_common as sdnpwn
import modules.sdnpwn.sdnpwn_of_helper as ofHelper

from pyof.v0x01.common.header import Header, Type
from pyof.v0x01.controller2switch.features_reply import FeaturesReply

from pyof.v0x04.controller2switch.features_reply import FeaturesReply as FeaturesReplyNew
from pyof.v0x04.controller2switch.packet_out import PacketOut
from pyof.v0x04.controller2switch.flow_mod import FlowMod

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Perform passive information gathering on an OpenFlow connection."
  
def usage():
  sdnpwn.addUsage(["-i", "--iface"], "Interface to listen on", False)
  sdnpwn.addUsage(["-r", "--read"], "PCAP file to read", False)
  
  return sdnpwn.getUsage()

def printFeatureReplyDetails(ofFeatureReply):
  sdnpwn.message("Device Datapath ID: " + str(ofFeatureReply.datapath_id), sdnpwn.NORMAL)
  sdnpwn.message("Number of Buffers: " + str(ofFeatureReply.n_buffers), sdnpwn.NORMAL)
  sdnpwn.message("Number of Tables: " + str(ofFeatureReply.n_tables), sdnpwn.NORMAL)
  sdnpwn.message("Capabilities: " + bin(int(str(ofFeatureReply.capabilities))), sdnpwn.NORMAL) 

def handlePkt(pkt):
  if(TCP in pkt and len(pkt[TCP].payload) > 0):
    try:
      ofHeader = Header()
      ofHeader.unpack(bytes(pkt[TCP].payload)[:8])

      print(f"[>] {pkt[IP].src}:{pkt[TCP].sport} -> ", end='')
      print(f"OFv{ofHeader.version}", end=' ')
      print(ofHeader.message_type, end=' -> ')
      print(f"{pkt[IP].dst}:{pkt[TCP].dport}")


      ofBody = ""
      try:

        ##TODO: Allow for detailed message information to be printed
        ofBody = bytes(pkt[TCP].payload)[:(ofHeader.length-8)]
        if((ofHeader.message_type & 0xFF) == 6):
          ofFeatureReply = FeaturesReplyNew()
          ofFeatureReply.unpack(ofBody)
          #sdnpwn.message("Device Datapath ID: " + str(ofFeatureReply.datapath_id), sdnpwn.NORMAL)
          printFeatureReplyDetails(ofFeatureReply)
        elif((ofHeader.message_type & 0xFF) == 13):
          pktOut = PacketOut()

      except Exception as e:
        print("Error: " + str(e))

    except:
      #Not an OF message
      pass

def run(params):

  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler

  if(sdnpwn.checkArg(["-i", "--iface"], params)):  
    sniff(iface=sdnpwn.getArg(["-i", "--iface"], params), prn=handlePkt)
  elif(sdnpwn.checkArg(["-r", "--read"], params)):
    pcap = rdpcap(sdnpwn.getArg(["-r", "--read"], params))
    for p in pcap:
      handlePkt(p)
  else:
    print(info())
    print(sdnpwn.getUsage())
