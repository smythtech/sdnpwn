from subprocess import call
import signal
import errno
import modules.sdnpwn.sdnpwn_common as com

def info():
  return "Run system commands from within the sdnpwn command line."
  
def usage():
  return "system <command>\nExample: \n\t1) system ifconfig\n\t2) system ifconfig eth0 192.168.1.1 netmask 255.255.255.0\n\t3) system whoami"

def run(params):
  if(len(params) > 1):
    params.pop(0)
    try:
      call(params)
    except:
        com.message("Problem executing command. May require Root.", com.ERROR)
    return
  else:
    print(info())
    print(usage())
