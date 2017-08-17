
import netifaces
from scapy.all import *
from random import randint
from subprocess import check_output
from tabulate import tabulate

SUCCESS = "\033[32m[*]\033[0m "
WARNING = "\033[93m[!]\033[0m "
ERROR = "\033[91m[!]\033[0m "
NORMAL =  "\033[0m[+]\033[0m "
VERBOSE = "    "

SDNPWN_MODULE_USAGE = []

# sdnpwn general functions
def message(msg, col):
  print(col + msg + "\033[0m")
  
def printNormal(msg):
  message(msg, NORMAL)
  
def printWarning(msg):
  message(msg, WARNING)
  
def printSuccess(msg):
  message(msg, SUCCESS)
  
def printVerbose(msg):
  message(msg, VERBOSE)

def addUsage(option, optionDesc, required=False):
  reqTranslate = {True:"Yes", False: "No"}
  SDNPWN_MODULE_USAGE.append([option, optionDesc, reqTranslate[required]])

def getUsage():
  return tabulate(SDNPWN_MODULE_USAGE, headers=["Option", "Description", "Required"])

def printUsage():
  print(tabulate(SDNPWN_MODULE_USAGE, headers=["Option", "Description", "Required"]))

def checkArg(option, params):
  if(isinstance(option, list)):
     for v in option:
       if(v in params):
         return True
  elif(option in params):
    return True
  return False

def getArg(option, params, default=None):
   if(isinstance(option, list)):
     for v in option:
       if(v in params):
         return params[params.index(v)+1]
   elif(option in params):
     return params[params.index(option)+1]
   return default
   
# Networking related functions
def getIPAddress(iface):
  if(iface in netifaces.interfaces()):
    return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
  else:
    return '0'

def getNetworkMask(iface):
  if(iface in netifaces.interfaces()):
    return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
  else:
    return '0'
  
def getMacAddress(iface):
  if(iface in netifaces.interfaces()):
    return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
  else:
    return '0'
  
def getTargetMacAddress(iface, ip):
  try:
    #Check ARP cache first
    mac = ""
    arpTable = str(check_output(["arp", "-n"]))
    for a in arpTable:
      if(ip in a):
        mac = list(filter(None, (a.split(" "))))[2]
        if(mac != "?"):
          return mac
    #MAC not in cache, send ARP request    
    resp = sr(ARP(op=ARP.who_has, psrc=getIPAddress(iface), pdst=ip), timeout=1)
    if(resp[0][ARP][0][1].hwsrc != None):
      return resp[0][ARP][0][1].hwsrc
    else:
      return ""
  except:
    return ""

def getDefaultGatewayIPAddress():
  return netifaces.gateways()['default'][netifaces.AF_INET][0]

def generateRandomMacAddress(ouid=None):
  mac = ""
  alph = "123456789abcdef"
  t = 0
  l = 12
  if(ouid is not None):
    l = 6
    mac = ouid
    if(mac[len(mac)-1] is not ":"):
      mac+= ":"
  for i in range(0, l):
    if(t == 2):
       t = 0
       mac = mac + ":"
    mac = mac + alph[randint(0,len(alph)-1)]
    t+=1
  return mac