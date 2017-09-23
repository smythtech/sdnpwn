
import signal
import shutil
from os import listdir
from os.path import isfile,join
import datetime
from subprocess import call

import modules.sdnpwn_common as sdnpwn

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  sdnpwn.message("Stopping...", sdnpwn.NORMAL)
  exit(0)

def info():
  return "Build ONOS applications from templates in apps directory."
  
def usage():
  
  sdnpwn.addUsage(["-c", "--configure"], "Configure app before building", False)
  sdnpwn.addUsage(["-b", "--build"], "Root directory of app to build", True)
  sdnpwn.addUsage(["-k", "--keep-source"], "Keep source of generated application", False)
  
  return sdnpwn.getUsage()

def run(params):
  
  signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
  
  appDir = sdnpwn.getArg(["-b", "--build"], params, None)
  doConfig = sdnpwn.checkArg(["-c", "--configure"], params)
  
  if(appDir == None):
    sdnpwn.message("No app directory specified", sdnpwn.ERROR)
    return
  
  if(doConfig):
    try:
      with open(appDir + "/sdnpwn_options", 'r+') as confFile:
        #confFile = open(appDir + "/sdnpwn_options", 'r+')
        confOut = ""
        for l in confFile.readlines():
          conf = l.split("=")
          confVal = input(conf[0] + " [" + conf[1].replace("\n","") + "]: ") or conf[1].replace("\n","")
          confOut += conf[0] + "=" + confVal + "\n"
        
        confFile.seek(0)
        confFile.write(confOut)
        
    except Exception as e:
      sdnpwn.printWarning("Error while setting configuration!")
      print(e)
      return
    
  sdnpwn.printNormal("Building " + appDir)
    
  buildDir = appDir + "-building-temp"
  try:
    shutil.copytree(appDir, buildDir)
      
    config= {}
    with open(buildDir + "/sdnpwn_options", 'r') as confFile:
      for l in confFile.readlines():
        conf = l.split("=")
        config[conf[0]] = conf[1].replace("\n","")
      
    sdnpwn.printNormal("Got configuration")
      
    with open(buildDir + "/pom.xml", 'r+') as pomFile:
      pomFileData = pomFile.read()
      pomFile.seek(0)
      for k in config.keys():
        pomFileData = pomFileData.replace(k, config[k])
        
      pomFile.write(pomFileData)
        
    javaFilesLocation = buildDir + "/src/main/java/org/onosproject/app/"
    javaFiles = [f for f in listdir(javaFilesLocation) if isfile(join(javaFilesLocation, f))]
    
    for j in javaFiles:
        
      #with open(javaFilesLocation + j, 'r+') as javaFile:
      #javaFileData = javaFile.read()
      #javaFile.seek(0)
      #Above method won't overwrite the whole file for some reason. Should check out why.
      javaFile = open(javaFilesLocation + j, 'r')
      javaFileData = javaFile.read()
      javaFile.close()
      for k in config.keys():
        javaFileData = javaFileData.replace(k, config[k])
      
      javaFile = open(javaFilesLocation + j, 'w')
      javaFile.write(javaFileData)
      javaFile.close()
        
    sdnpwn.printSuccess("Files updated with configuration")
    
    sdnpwn.printNormal("Compiling app with maven")
      
    call(['mvn', '-f', buildDir, 'clean', 'install'])
    
    shutil.copy(buildDir + "/target/" + config["$APP_NAME"] + "-1.0-SNAPSHOT.oar", "apps/compiled_apps/")
    shutil.copy(buildDir + "/target/" + config["$APP_NAME"] + "-1.0-SNAPSHOT.jar", "apps/compiled_apps/")
    
    sdnpwn.printSuccess("OAR and JAR file moved to apps/compiled_apps")
    
    if(sdnpwn.checkArg(["-k", "--keep-source"], params)):
      shutil.copytree(buildDir, appDir + "-" + str(datetime.datetime.now()).split(" ")[0])
      sdnpwn.printNormal("App source saved in " + appDir + "-" + str(datetime.datetime.now()).split(" ")[0])
      
      
  except Exception as e:
    sdnpwn.printError("Error building " + appDir)
    print(e)
  finally:
    shutil.rmtree(buildDir)
    
    
    
    
    
    
    
    
    
    