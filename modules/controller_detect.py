from scapy.all import *
import signal
import time
from scipy import stats
import http.client as httpc

import modules.sdnpwn_common as sdnpwn

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Attempts to fingerprint the network controller."
  
def usage():
  
  sdnpwn.addUsage("-i | --iface", "Interface to use")
  sdnpwn.addUsage("-l | --lldp", "Determine controller based off LLDP traffic")
  sdnpwn.addUsage("-t | --target", "Determine controller based northbound interface")
  sdnpwn.addUsage("-p | --ports", "Set ports to scan when --target is specified.")
  sdnpwn.addUsage("-x | --proxy", "Define a proxy server to use when --target is specified.")
  sdnpwn.addUsage("-v | --verbose", "Show verbose output")
   
  return sdnpwn.getUsage()

def lldpListen(interface, dumpLLDP):
   sniff(iface=interface, prn=lldpListenerCallback(interface, dumpLLDP), store=0, stop_filter=lldpStopFilter)
   
def lldpListenerCallback(interface, dumpLLDP):
  def packetHandler(pkt):
    global lldpTimeTrack
    #LLDP: 0x88cc, BDDP: 0x8942
    if(pkt.type == 0x88cc):
      lldpTimeTrack.append(int(round(time.time())))
      if(dumpLLDP == True):
        print(pkt)
  return packetHandler

def lldpStopFilter(pkt):
  global lldpTimeTrack
  if(len(lldpTimeTrack) >= 6):
    return True
  else:
    return False

def run(params):
  global lldpTimeTrack
  
  lldpTimeTrack = []
  
  defaultGuiPorts = {"Floodlight & OpenDayLight": 8080, "OpenDayLight (DLUX Standalone)": 9000, "OpenDayLight (DLUX w/t Karaf) & ONOS": 8181}
  defaultGuiURLs = {"Floodlight": "/ui/index.html", "OpenDayLight (DLUX)": "/dlux/index.html", "OpenDayLight (Hydrogen)": "/index.html", "ONOS": "/onos/ui/login.html"}
  guiIdentifiers = {}
  ofdpIntervals = {"Floodlight": 15, "OpenDayLight (Lithium & Helium)": 5, "OpenDayLight (Hydrogen)": 300, "Pox?": 5, "Ryu?": 1, "Beacon": 15, "ONOS": 3}
  
  iface = None
  verbose = False
  dumpLLDP = False
  
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
  dumpLLDP = sdnpwn.checkArg(["--dump-lldp", "-d"], params)
  verbose = sdnpwn.checkArg(["--verbose", "-v"], params)
  
  if(sdnpwn.checkArg(["--lldp", "-l"], params)):
    #Test by observing LLDP traffic on an interface
    iface = sdnpwn.getArg(["--iface", "-i"], params)
    if(iface is None):
      sdnpwn.message("Please specify an interface with --iface option", sdnpwn.ERROR)
      return
    sdnpwn.message("Collecting 6 LLDP frames. This may take a few minutes...", sdnpwn.NORMAL)
    lldpListen(iface, dumpLLDP)
    sdnpwn.message("Got all LLDP frames. Getting mean time between frames...", sdnpwn.NORMAL)
    timeBetweenMessages = []
    timeBetweenMessages.append((lldpTimeTrack[1] - lldpTimeTrack[0]))
    timeBetweenMessages.append((lldpTimeTrack[3] - lldpTimeTrack[2]))
    timeBetweenMessages.append((lldpTimeTrack[5] - lldpTimeTrack[4]))
                                            
    meanTimeBetweenMessages = 0
    for i in timeBetweenMessages:
      meanTimeBetweenMessages += i
    meanTimeBetweenMessages = (meanTimeBetweenMessages/len(timeBetweenMessages))
    
    sdnpwn.message("Mean time between frames is: " + str(meanTimeBetweenMessages), sdnpwn.NORMAL)
    
    matches = 0
    for k in ofdpIntervals:      
      if((meanTimeBetweenMessages < (ofdpIntervals[k] + (ofdpIntervals[k]/100*5))) and (meanTimeBetweenMessages > (ofdpIntervals[k] - (ofdpIntervals[k]/100*5)))):
        sdnpwn.message("Mean time matches " + k, sdnpwn.NORMAL)
        matches+=1
    if(matches == 0):
      sdnpwn.message("Could not determine controller from LLDP times.", sdnpwn.NORMAL)
  
  elif(sdnpwn.checkArg(["--target", "-t"], params)):
    #Test using a URL
    target = sdnpwn.getArg(["--target", "-t"], params)
    sdnpwn.message("Testing visibility of northbound interface on host " + str(target), sdnpwn.NORMAL)
    ports = sdnpwn.getArg(["--ports", "-p"], params)
    if(ports is None):
      ports = []
      for p in defaultGuiPorts:
        ports.append(defaultGuiPorts[p])
    else:
      ports = ports.split(",")
    
    sdnpwn.message("Enumerating ports...", sdnpwn.NORMAL)
    for p in ports:
      try:
        conn = httpc.HTTPConnection(target, int(p))
        if(sdnpwn.checkArg(["--proxy", "-x"], params)):
          conn.setTunnel((sdnpwn.getArg(["--proxy", "-x"], params)))
        req = conn.request("GET", "/")
        sdnpwn.message("Made HTTP connection to " + str(target) + " on port " + str(p), sdnpwn.SUCCESS)
        for c in defaultGuiPorts:
          if(defaultGuiPorts[c] == p):
            sdnpwn.message("Port used by " + str(c) + " for GUI interface", sdnpwn.VERBOSE)
        sdnpwn.message("Testing GUI URLs for port " + str(p), sdnpwn.NORMAL)
        for u in defaultGuiURLs:
          try:
            conn = httpc.HTTPConnection(target, int(p))
            conn.request("GET", defaultGuiURLs[u])
            res = conn.getresponse()
            reqStatus = res.status
            if(reqStatus >= 200 and reqStatus < 400):
              sdnpwn.message("Got " + str(reqStatus) + " for " + defaultGuiURLs[u], sdnpwn.SUCCESS)
              sdnpwn.message("URL associated with " + u + " GUI interface", sdnpwn.VERBOSE)
            else:
              if(verbose == True):
                sdnpwn.message("Got " + str(reqStatus) + " for URL " + str(u), sdnpwn.VERBOSE)
          except Exception as e:
            if(verbose == True):
              sdnpwn.message("Error testing URL: " + str(e), sdnpwn.VERBOSE)
        print("")
      except Exception as e:
        if(verbose == True):
          sdnpwn.message("No connection to " + str(target) + " on port " + str(p), sdnpwn.VERBOSE)
          sdnpwn.message(str(e), sdnpwn.VERBOSE)
  else:
    sdnpwn.message("No detection method given. Exiting.", sdnpwn.WARNING)
    print(info())
    print(usage())
    return
