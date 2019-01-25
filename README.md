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

# Further Information
Check out https://sdnpwn.net for articles and tutorials on using various sdnpwn modules and the attacks they use.

# Disclaimer
This tool comes without warranty. The developers of this tool decline all responsability for malicious or illegal use, and impact caused by malicious or illegal use. 
