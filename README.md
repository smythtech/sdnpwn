#What is sdnpwn? 
sdnpwn is a toolkit and framework for testing the security of Software-Defined Networks (SDNs).

#Installation
The setup.sh script takes care installing software required for sdnpwn to function. Just run ./setup.sh and follow the instructions.

#Usage
Functionality in sdnpwn is divided into different modules. Each attack or attack type is available from a certain module.
  
Modules can be executed like so:

'''  
./sdnpwn.py <module name> <module options>
'''
 
The mods module can be used to list all available modules:
  
'''
./sdnpwn.py mods
'''
  
More information about a certain module can be accessed using the info module:

'''  
./sdnpwn.py info mods
'''

The above command would retrieve more information about the mods module, such as a description and available options.

#Further Information
Check out https://sdnpwn.net for articles and tutorials on using various sdnpwn modules and the attacks they use.
