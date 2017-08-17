
import modules.sdnpwn_common as sdnpwn
import imp
import subprocess
import os

def info():
  return "Displays available modules."
  
def usage():
  sdnpwn.addUsage("-l", "List all available modules")
  sdnpwn.addUsage("-s", "Search available modules")
  sdnpwn.addUsage("-n", "Create new module from base template")
  sdnpwn.addUsage("-t", "Specify template for new module (Optional with -n)")
  sdnpwn.addUsage("-r", "Delete module by name")
  
  return sdnpwn.getUsage()

def run(params):
  if(len(params) == 1 or "-l" in params):
    printModules(None);
  
  if("-n" in params):
    try:
      templateName = "module_base_template"
      newModName = params[params.index("-n")+1]
      if(newModName in getModuleList()):
        sdnpwn.message("Module already exists!", sdnpwn.WARNING)
        return
      if("-t" in params):
        templateName = params[params.index("-t")+1]

      subprocess.call(["cp", "modules/" + templateName.replace("-", "_") + ".py", "modules/" + newModName.replace("-", "_") + ".py"])
    except:
      sdnpwn.message("Could not create new module", sdnpwn.ERROR)
      
  if("-s" in params):
    try:
      searchString = params[params.index("-s")+1]
      printModules(searchString)
    except:
      sdnpwn.message("Error searching for module", sdnpwn.ERROR)
  
  if("-r" in params):
    try:
      moduleName = params[params.index("-r")+1]
      confirm = input("Are you sure you would like to remove '" + moduleName + "'? [y/n]: ")
      if(confirm == "y"):
        os.remove("modules/" + moduleName.replace("-", "_") + ".py")
        try:
          os.remove("modules/" + moduleName.replace("-", "_") + ".pyc")
        except:
          pass
        sdnpwn.message("Module '" + moduleName + "' removed.", sdnpwn.WARNING)
    except Exception as e:
      sdnpwn.message("Error removing module", sdnpwn.ERROR)
      print(e)
    
def getModuleFileList():
  modules = []
  for direc, direcs, filenames in os.walk('modules/'):
    for filename in filenames:
      modules.append(filename)
  
  return sorted(modules)

def getModuleList():
  modules = []
  for direc, direcs, filenames in os.walk('modules/'):
    for filename in filenames:
      if("__init__" not in filename and "template" not in filename and ".pyc" not in filename and "sdnpwn" not in filename and ".py" in filename):
        modules.append((filename.split(".py")[0].replace("_", "-")))
  
  return sorted(modules)
  
def printModules(searchString):
  if(searchString is None):
    sdnpwn.message("Available modules:", sdnpwn.SUCCESS)
    for m in getModuleList():
      sdnpwn.message("" + (m.split(".py")[0]).replace("_", "-"), sdnpwn.NORMAL)
  else:
    sdnpwn.message("Available modules (Matching '" + searchString + "'):", sdnpwn.SUCCESS)
    for m in getModuleList():
      if(searchString in m):
        sdnpwn.message("" + (m.split(".py")[0]).replace("_", "-"), sdnpwn.NORMAL)