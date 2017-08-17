#!/usr/bin/python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import netifaces
import errno

import modules.sdnpwn_common as com

import imp


SDNPWN_VERSION = "0"

verbose = 0
conf.verb = 0

def main():
  if(len(sys.argv) == 1):
    try:
      mod = imp.load_source("help", "modules/help.py")
      params = sys.argv.pop(0)
      filter(None, params)
      mod.run(params)
      del mod
    except IOError:
      com.message("Error importing " + modName + " as a module.", com.ERROR)
  elif(len(sys.argv) > 1):
    modName = sys.argv[1]
    modName = modName.replace("-", "_")
    params = sys.argv
    filter(None, params)
    params.pop(0)
    try:
      mod = imp.load_source(modName, "modules/" + modName + ".py")
      mod.run(params)
      del sys.modules[modName]
    except IOError as e:
      if(e == errno.EPERM):
        com.message("Run as root!", com.ERROR)
    except ImportError as e:
        com.message("Error importing " + modName + " as a module.", com.ERROR)
        print(e)
    #except Exception as e:
      #com.message("Something went wrong!", com.ERROR)
      #print(e)
      
if __name__=='__main__':
  main()
