[![Mentioned in Awesome SDN Security](https://awesome.re/mentioned-badge.svg)](https://github.com/lopezalvar/awesome-sdn-security)
# What is sdnpwn? 
sdnpwn is a toolkit and framework for testing the security of Software-Defined Networks (SDNs). For more information check out this article: https://sdnpwn.net/2017/08/22/what-is-sdnpwn/

# Installation

First download sdnpwn using git

```
git clone https://github.com/smythtech/sdnpwn
```

Make the sdnpwn.py and setup.sh scripts executable

```
sudo chmod +x sdnpwn.py
sudo chmod +x setup.sh
```

The setup.sh script takes care installing software required for sdnpwn to function. Just run ./setup.sh and follow the instructions.

```
sudo ./setup.sh
```

# Usage

Cheatsheet: https://sdnpwn.net/tools/sdnpwn/

Functionality in sdnpwn is divided into different modules. Each attack or attack type is available from a certain module.
  
Modules can be executed like so:

```  
./sdnpwn.py <module name> <module options>
```
 
The mods module can be used to list all available modules:
  
```
./sdnpwn.py mods
```
  
More information about a certain module can be accessed using the info module:

```  
./sdnpwn.py info mods
```

The above command would retrieve more information about the mods module, such as a description and available options.

# Todo
Necesary tasks:
- Check that the set-up script is still suitable. 
- Test all modules to check for any issues. Verify they function as expected.
- Fix any bugs that arise based on the above testing.
- Add consistent signal handling throughout all modules.
- Add consistent help menu access throughout all modules.
- Check the OpenFlow library used by of-switch. This needs to be updated or changed.
- Clean up/optimise code where possible.

Other tasks:
- Add more OpenFlow versions to the of-switch module. This may require a swap to a different OpenFlow library and possibly a full re-write.
- Look at creating a p4-switch module that provides similar features to of-switch. 
- Improve accuracy of the sdn-detect module.
- Add more information for fingerprinting controllers. Structure the fingerprinting data in a better way (external file?). 
- Add up-to-date application templates for the onos-app module.
- Add modules for vulnerabilities that have been made public in the past few years. 
- Clean up/optimise code. 

# Further Information
Check out https://sdnpwn.net for articles and tutorials on using various sdnpwn modules and the attacks they use.

# Disclaimer
This tool comes without warranty. The developers of this tool decline all responsability for malicious or illegal use, and impact caused by malicious or illegal use. 
