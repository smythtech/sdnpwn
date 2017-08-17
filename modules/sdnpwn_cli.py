
import modules.sdnpwn_common as com
import imp
import errno
import os
import readline
import sys
import signal

def info():
  return "Command line interface for SDNPWN."

def usage():
  return "sdnpwn# <module name> <options>"

def signal_handler(signal, frame):
  print("")
  com.message("Bye", com.NORMAL)
  sys.exit(0)
  
def run(params):
  cmd = ""
  prompt = "$"
  #Check for root and change prompt if user has root
  if(os.geteuid() == 0):
    prompt = "#"
  else:
    com.message("Root not detected. Some modules may be limited.",com.WARNING)
  while(cmd != "exit"):
    signal.signal(signal.SIGINT, signal_handler)
    cmd = input("\033[1msdnpwn" + prompt + " \033[0m")
    if(cmd == "exit"):
      com.message("Bye", com.NORMAL)
      exit(0)
    elif(cmd != ""):
      params = cmd.split(" ")
      cmd = params[0]
      cmd = cmd.replace("-", "_")
      try:
        mod = imp.load_source(cmd, "modules/" + cmd + ".py")
        filter(None, params)
        mod.run(params)
        del sys.modules[cmd]
        imp.reload(signal)
        imp.reload(com)
      except InterruptedError as e:
        print("Module interupted.")
      except IOError as e:
        if(e == errno.EPERM):
          com.message("Run as root!", com.ERROR)
        else:
          com.message("Error importing " + cmd + " as a module.", com.ERROR)
          print(e)
      except Exception as e:
        com.message("Something went wrong!", com.ERROR)
        print(e)