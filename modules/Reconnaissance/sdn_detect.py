
import modules.sdnpwn.sdnpwn_common as sdnpwn
from scapy.all import ARP,IP,ICMP, arping, conf, sr1
import netifaces
import time
from scipy import stats,mean
import signal

conf.verb = 0

def info():
  return "Determines if a network is likely to be an SDN by observing Round-Trip Times (RTT) for traffic."

def usage():
  sdnpwn.addUsage("-m", "Protocol to use (ICMP | ARP) (Default ARP)")
  sdnpwn.addUsage("-t", "IP of local host to send traffic to (Defaults to default gateway)")
  sdnpwn.addUsage("-i", "Interval at which packets are sent (Default 1)")
  sdnpwn.addUsage("-c", "Number of packets to send. More packets means better detection accuracy.(Default 10)")
  sdnpwn.addUsage("-v", "Enable verbose output")

  return sdnpwn.getUsage()

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit()

def testForSDN(testMethod, dstIP, count, interval):
  global verbose
  rtt = []
  sentMS = 0

  if(testMethod == "icmp"):
    sdnpwn.message("Testing with ICMP", sdnpwn.NORMAL)
    icmp = (IP(dst=dstIP)/ICMP())
    for i in range(0,count):
      sentMS = int(round(time.time() * 1000))
      resp = sr1(icmp)
      rtt.append((int(round(time.time() * 1000))) - sentMS)
      time.sleep(interval)

  elif(testMethod == "arp"):
    sdnpwn.message("Testing with ARP", sdnpwn.NORMAL)
    for i in range(0,count):
      sentMS = int(round(time.time() * 1000))
      resp = arping(dstIP)
      rtt.append((int(round(time.time() * 1000))) - sentMS)
      time.sleep(interval)

  initValue = rtt[0]
  rtt.pop(0)
  #Perform T-Test to check if first latency value is significantly different from others in our sample
  res = stats.ttest_1samp(rtt, initValue)
  if(verbose == True):
    sdnpwn.message(f"Initial RTT: {initValue}", sdnpwn.VERBOSE)
    sdnpwn.message(f"RTTs for other traffic: {rtt}", sdnpwn.VERBOSE)
    sdnpwn.message(f"Calculated p-value for inital RTT is {res[1]}", sdnpwn.VERBOSE)
    if(all(i < initValue for i in rtt)):
      sdnpwn.message("Initial value is highest value observed", sdnpwn.VERBOSE)
  if(res[1] < .05 and all(i < initValue for i in rtt)): #If the p-value is less that 5% we can say that initValue is significant
    return True
  else:
    return False


def run(params): 
  global verbose

  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler

  verbose = False
  testMethod = "arp"
  dstIP = ""
  count = 10
  interval = 1

  if("-m" in params):
    testMethod = (params[params.index("-m")+1]).lower()
  if("-t" in params):
    dstIP = params[params.index("-t")+1]
  if("-i" in params):
    interval = float(params[params.index("-i")+1])
  if("-c" in params):
    count = int(params[params.index("-c")+1])
  if("-v" in params):
    verbose = True

  if(dstIP == ""):
    sdnpwn.message("No target given, using default gateway", sdnpwn.NORMAL)
    try:
      dstIP = netifaces.gateways()['default'][netifaces.AF_INET][0]
    except:
      sdnpwn.message("Could not determine gateway address. Please specify a target using the -t option.", sdnpwn.ERROR)
      return
    sdnpwn.message("Default gateway detected as " + dstIP, sdnpwn.NORMAL)

  try:
    if(testForSDN(testMethod, dstIP, count, interval)):
      sdnpwn.message("SDN detected!", sdnpwn.SUCCESS)
    else:
      sdnpwn.message("SDN not detected", sdnpwn.WARNING)
  except PermissionError as e:
    sdnpwn.message("Needs root!", sdnpwn.ERROR)


