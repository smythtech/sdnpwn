
import modules.sdnpwn_common as com
import imp

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
          mod = imp.load_source(m, "modules/" + m + ".py")
          com.message("Module Name: " + m, com.NORMAL)
          com.message("Description: " + mod.info(), com.NORMAL)
          com.message("Usage:", com.NORMAL)
          print(mod.usage())
        except IOError:
          com.message("Module " + m + " does not exist!", com.ERROR)
    #except:
      #com.message("Error", com.ERROR)
    
  