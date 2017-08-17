
import signal

import modules.sdnpwn_common as sdnpwn

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  return

def info():
  #Description of the what the module is and what it does. This function should return a string.
  return "My Description"
  
def usage():
  '''
  How to use the module. This function should return a string.
  sdnpwn_common contains functions to print the module usage in a table. 
  These functions are "addUsage", "getUsage", and "printUsage". "addUsage" and "getUsage" are shown below.
  The parameters for addUsage are option, option description, and required (True or False)
  '''
  sdnpwn.addUsage("-v", "Enable verbose output", False)
  
  return sdnpwn.getUsage()

def run(params):
  sdnpwn.message("Module template created!", sdnpwn.SUCCESS)
  sdnpwn.message("Module template created!", sdnpwn.WARNING)
  sdnpwn.message("Module template created!", sdnpwn.ERROR)
  sdnpwn.message("Module template created!", sdnpwn.NORMAL)
  sdnpwn.message("Module template created!", sdnpwn.VERBOSE)
  print("Params are:")
  print(params)
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  