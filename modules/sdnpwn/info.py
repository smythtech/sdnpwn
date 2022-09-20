
import modules.sdnpwn.sdnpwn_common as com
import importlib.machinery

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
      
      for m in params:
        try:
          m = m.replace("-", "_")
          loader = importlib.machinery.SourceFileLoader(m, "modules/" + m + ".py")
          mod = loader.load_module()
          com.message("Module Name: " + m, com.NORMAL)
          com.message("Description: " + mod.info(), com.NORMAL)
          com.message("Usage:", com.NORMAL)
          print(mod.usage())
        except IOError:
          com.message("Module " + m + " does not exist!", com.ERROR)
    #except:
      #com.message("Error", com.ERROR)
    
  
