
import modules.sdnpwn.sdnpwn_common as sdnpwn
import imp
import subprocess
import os

def info():
  return "Displays available modules."
  
def usage():
  sdnpwn.addUsage("-l", "List all available modules")
  sdnpwn.addUsage("-s", "Search available modules")
  sdnpwn.addUsage("-n", "Create new module from base template")
  sdnpwn.addUsage("-c", "Module catagory. 'A' = Attack, 'R' = Reconnaissance, 'U' = Utility (i.e. mods -n attack_mod -c A.")
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
      if("-c" in params):
        cat = params[params.index("-c")+1]
        catagory = {
          "A": "Attack",
          "R": "Reconnaissance",
          "U": "Utility"
        }[cat]
      else:
        sdnpwn.message("Please provide a catagory for the module (i.e. Attack (A), Reconnaissance (R), Utility (U))", sdnpwn.ERROR)
        return

      subprocess.call(["cp", "modules/sdnpwn/" + templateName.replace("-", "_") + ".py", "modules/" + catagory + "/" + newModName.replace("-", "_") + ".py"])
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
      if("-c" in params):
        cat = params[params.index("-c")+1]
        catagory = {
          "A": "Attack",
          "R": "Reconnaissance",
          "U": "Utility"
        }[cat]
      else:
        sdnpwn.message("Please provide a catagory for the module (i.e. Attack (A), Reconnaissance (R), Utility (U))", sdnpwn.ERROR)
        return

      confirm = input("Are you sure you would like to remove '" + moduleName + "'? [y/n]: ")
      if(confirm == "y"):
        os.remove("modules/" + catagory + "/" + moduleName.replace("-", "_") + ".py")
        try:
          os.remove("modules/" + catagory + "/" + moduleName.replace("-", "_") + ".pyc")
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
  ignoreFileList = ["__init__", "template", ".pyc", "sdnpwn"]
  ignoreDirList = ["", "__pycache__", "ofv10", "ofv13"] # Empty dir name omits contents of modules directory
  modules = {}
  for direc, direcs, filenames in os.walk('modules/'):
    dir = direc.split("/")[-1]
    if(not any(dir == ignore for ignore in ignoreDirList)):
      modules[dir] = []
      for filename in filenames:
        if(not any(ignore in filename for ignore in ignoreFileList)):
          modules[dir].append((filename.split(".py")[0].replace("_", "-")))

  for m in modules:
    modules[m] = sorted(modules[m])

  return modules
  
def printModules(searchString):
  if(searchString is None):
    sdnpwn.message("Available modules:", sdnpwn.SUCCESS)
    modules = getModuleList()
    for m in modules:
      sdnpwn.message(m, sdnpwn.NORMAL)
      for i in modules[m]:
        print("\t- " + (i.split(".py")[0]).replace("_", "-"))
  else:
    sdnpwn.message("Available modules (Matching '" + searchString + "'):", sdnpwn.SUCCESS)
    modules = getModuleList()
    for m in modules:
      for i in modules[m]:
        if(searchString in i):
          sdnpwn.message(m + ": " + (i.split(".py")[0]).replace("_", "-"), sdnpwn.NORMAL)
