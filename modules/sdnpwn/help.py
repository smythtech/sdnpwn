
import signal

import modules.sdnpwn.sdnpwn_common as sdnpwn

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  return

def info():
  return "Information on getting started with sdnpwn"
  
def usage():
  
  sdnpwn.addUsage("", "", False)
  
  return sdnpwn.getUsage()

def run(params):
   
  print("")
  print("")
  
  print('''
         _                           
        | |                          
 ___  __| |_ __  _ ____      ___ __  
/ __|/ _` | '_ \| '_ \ \ /\ / / '_ \ 
\__ \ (_| | | | | |_) \ V  V /| | | |
|___/\__,_|_| |_| .__/ \_/\_/ |_| |_|
                | |                  
                |_|
  ''')
  
  print("Author: Dylan Smyth")
  print("Site: https://sdnpwn.net")
  print("Version: 1.7.0 ")  
  print("")
  
  sdnpwn.message(" What is sdnpwn? ", sdnpwn.SUCCESS)
  print("sdnpwn is a toolkit and framework for testing the security of Software-Defined Networks (SDNs).")
  print("")
  
  sdnpwn.message("Usage", sdnpwn.SUCCESS)
  print('''Functionality in sdnpwn is divided into different modules. Each attack or attack type is available from a certain module.
  
Modules can be executed like so:
  
./sdnpwn.py <module name> <module options>
    
The mods module can be used to list all available modules:
  
./sdnpwn.py mods
  
More information about a certain module can be accessed using the info module:
  
./sdnpwn.py info mods
  
The above command would retrieve more information about the mods module, such as a description and available options.''')
  print("")
  
  sdnpwn.message("Creating and managing modules", sdnpwn.SUCCESS)
  print('''Many sdnpwn modules use functionality from other modules. Each sdnpwn module is a Python module in itself so modules can be imported and functionality accessed. New modules can be created using the following command:
  
./sdnpwn.py mods -n <new module name>
  
Running the above command will create a new sdnpwn module from a template.
Modules can be removed with the following command:
  
./sdnpwn.py mods -r <module name>''')
  print("")
  
  sdnpwn.message("Further Information", sdnpwn.SUCCESS)
  print("Check out https://sdnpwn.net for articles and tutorials on using various sdnpwn modules and the attacks they use.")
  print("")
    
  

  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
