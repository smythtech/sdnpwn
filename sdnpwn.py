#!/usr/bin/python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import errno
import modules.sdnpwn.sdnpwn_common as com
import importlib.machinery
import os

def main():
  if((len(sys.argv) == 1) or ("--help" in sys.argv) or ("-h" in sys.argv)):
    try:
      loader = importlib.machinery.SourceFileLoader("help", "modules/sdnpwn/help.py")
      mod = loader.load_module()
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
      moduleLocation = ""
      for direc, direcs, filenames in os.walk('modules/'):
        for filename in filenames:
          if(filename == (modName + ".py")):
            moduleLocation = direc + "/" + (modName + ".py")
            break
      loader = importlib.machinery.SourceFileLoader(modName, moduleLocation)
      mod = loader.load_module()
      mod.run(params)
      del sys.modules[modName]
    except IOError as e:
      if(e == errno.EPERM):
        com.message("Run as root!", com.ERROR)
      else:
       com.msg("Error: " + modName + " does not appear to be a valid module", com.ERROR)
    except ImportError as e:
        com.message("Error importing " + modName + " as a module.", com.ERROR)
        print(e)
    #except Exception as e:
      #com.message("Something went wrong!", com.ERROR)
      #print(e)

if __name__=='__main__':
  main()
