
import modules.sdnpwn.sdnpwn_common as com
import importlib.machinery
import os

def info():
  return "Prints module information."
  
def usage():
  return "info <module name> ..."

def run(params):
  if(len(params) == 1):
    com.message("No module name given!", com.ERROR)
  else:
    #try:
      params.pop(0)
      
      for modName in params:
        try:
          modName = modName.replace("-", "_")
          moduleLocation = ""
          for direc, direcs, filenames in os.walk('modules/'):
            for filename in filenames:
              if(filename == (modName + ".py")):
                moduleLocation = direc + "/" + (modName + ".py")
                break
          loader = importlib.machinery.SourceFileLoader(modName, moduleLocation)
          mod = loader.load_module()
          com.message("Module Name: " + modName, com.NORMAL)
          com.message("Description: " + mod.info(), com.NORMAL)
          com.message("Usage:", com.NORMAL)
          print(mod.usage())
        except IOError:
          com.message("Module " + m + " does not exist!", com.ERROR)
    #except:
      #com.message("Error", com.ERROR)
    
  
