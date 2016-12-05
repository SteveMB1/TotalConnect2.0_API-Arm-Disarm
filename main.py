#Time spent: 51 Hours - 3 days - 21 hours of sleep 
#FREEBSD 2 Minutes ARP Expires - /bin/echo "net.link.ether.inet.max_age 300" >> /etc/sysctl.conf
#Crontab -e "* * * * * python2.7 /root/Security.py >/dev/null 2>&1"
#Interface re0_vlan4
import subprocess
import ConfigParser
import string, os, sys, httplib
import xml.etree.ElementTree as ET
from datetime import datetime, time
now = datetime.now()
now_time = now.time()

#---- BOL FOR CONFIGURTION INI ----#
# Documentation: https://wiki.python.org/moin/ConfigParserExamples #
Config = ConfigParser.ConfigParser()
Config.read("/root/Security.ini")
cfgfile = open("/root/Security.ini")

def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.getboolean(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1
state = ConfigSectionMap("Status")['armed']

#---- EOL FOR CONFIGURTION INI ----#

device1 = '00:00:00:00:00:00'
device2 = '00:00:00:00:00:00'
device3 = '00:00:00:00:00:00'

#---- BOL for LOG Output ---- #
Log = open('/root/SecurityAuditlog.txt', 'w')
print >> Log, "---------",now_time,"---------"

#---- BOL API Section ----#
    
def TC2_SOAPSessionID():
    global sessionHash
    server_addr = "rs.alarmnet.com"
    service_action = "/TC21API/TC2.asmx"

    body = """
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Header/><soapenv:Body><tns:AuthenticateUserLoginEx xmlns:tns="https://services.alarmnet.com/TC2/"><tns:userName>USERNAME IN THIS ELEMENT</tns:userName><tns:password>PASSWORD IN THIS ELEMENT</tns:password><tns:ApplicationID>14588</tns:ApplicationID><tns:ApplicationVersion>3.14.2</tns:ApplicationVersion><tns:LocaleCode></tns:LocaleCode></tns:AuthenticateUserLoginEx></soapenv:Body></soapenv:Envelope>"""

    request = httplib.HTTPSConnection(server_addr)
    request.putrequest("POST", service_action)
    request.putheader("Accept", "application/soap+xml, application/dime, multipart/related, text/*")
    request.putheader("Content-Type", "text/xml; charset=utf-8")
    request.putheader("Cache-Control", "no-cache")
    request.putheader("Pragma", "no-cache")
    request.putheader("SOAPAction","https://services.alarmnet.com/TC2/AuthenticateUserLoginEx")
    request.putheader("Content-Length", str(len(body)))
    request.endheaders()
    request.send(body)
    response = request.getresponse().read()

    tree = ET.fromstring(response)    
    sessionHash = tree.find('.//{https://services.alarmnet.com/TC2/}SessionID').text
    return
    
def TC2_DisarmSecuritySystem():
    TC2_SOAPSessionID()
    server_addr = "rs.alarmnet.com"
    service_action = "/TC21API/TC2.asmx"
    body = ("""<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:s="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <SOAP-ENV:Body>
    <tns:DisarmSecuritySystem xmlns:tns="https://services.alarmnet.com/TC2/">
      <tns:SessionID>%s</tns:SessionID>
      <tns:LocationID>00000</tns:LocationID>
      <tns:DeviceID>83738</tns:DeviceID>
      <tns:UserCode>-1</tns:UserCode>
    </tns:DisarmSecuritySystem>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>""") 
    
    request = httplib.HTTPSConnection(server_addr)
    request.putrequest("POST", service_action)
    request.putheader("Accept", "application/soap+xml, application/dime, multipart/related, text/*")
    request.putheader("Content-Type", "text/xml; charset=utf-8")
    request.putheader("Cache-Control", "no-cache")
    request.putheader("Pragma", "no-cache")
    request.putheader("SOAPAction","https://services.alarmnet.com/TC2/DisarmSecuritySystem")
    request.putheader("Content-Length", str(len(body % sessionHash)))
    request.endheaders()
    request.send(body % sessionHash)
    response = request.getresponse().read() 
    
    tree = ET.fromstring(response)    
    print >> Log, "API:", tree.find('.//{https://services.alarmnet.com/TC2/}ResultData').text
    return

def TC2_ArmSecuritySystem_Away():
    TC2_SOAPSessionID()
    server_addr = "rs.alarmnet.com"
    service_action = "/TC21API/TC2.asmx"
    body = ("""<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:s="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <SOAP-ENV:Body>
    <tns:ArmSecuritySystem xmlns:tns="https://services.alarmnet.com/TC2/">
      <tns:SessionID>%s</tns:SessionID>
      <tns:LocationID>00000</tns:LocationID>
      <tns:DeviceID>83738</tns:DeviceID>
      <tns:ArmType>0</tns:ArmType>
      <tns:UserCode>-1</tns:UserCode>
    </tns:ArmSecuritySystem>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>""") 
    
    request = httplib.HTTPSConnection(server_addr)
    request.putrequest("POST", service_action)
    request.putheader("Accept", "application/soap+xml, application/dime, multipart/related, text/*")
    request.putheader("Content-Type", "text/xml; charset=utf-8")
    request.putheader("Cache-Control", "no-cache")
    request.putheader("Pragma", "no-cache")
    request.putheader("SOAPAction","https://services.alarmnet.com/TC2/ArmSecuritySystem")
    request.putheader("Content-Length", str(len(body % sessionHash)))
    request.endheaders()
    request.send(body % sessionHash)
    response = request.getresponse().read() 
    
    tree = ET.fromstring(response)    
    print >> Log, "API:", tree.find('.//{https://services.alarmnet.com/TC2/}ResultData').text
    return

def TC2_ArmSecuritySystem_Stay():
    TC2_SOAPSessionID()
    server_addr = "rs.alarmnet.com"
    service_action = "/TC21API/TC2.asmx"
    body = ("""<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:s="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <SOAP-ENV:Body>
    <tns:ArmSecuritySystem xmlns:tns="https://services.alarmnet.com/TC2/">
      <tns:SessionID>%s</tns:SessionID>
      <tns:LocationID>00000</tns:LocationID>
      <tns:DeviceID>83738</tns:DeviceID>
      <tns:ArmType>1</tns:ArmType>
      <tns:UserCode>-1</tns:UserCode>
    </tns:ArmSecuritySystem>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>""") 
    
    request = httplib.HTTPSConnection(server_addr)
    request.putrequest("POST", service_action)
    request.putheader("Accept", "application/soap+xml, application/dime, multipart/related, text/*")
    request.putheader("Content-Type", "text/xml; charset=utf-8")
    request.putheader("Cache-Control", "no-cache")
    request.putheader("Pragma", "no-cache")
    request.putheader("SOAPAction","https://services.alarmnet.com/TC2/ArmSecuritySystem")
    request.putheader("Content-Length", str(len(body % sessionHash)))
    request.endheaders()
    request.send(body % sessionHash)
    response = request.getresponse().read() 
    
    tree = ET.fromstring(response)    
    print >> Log, "API:", tree.find('.//{https://services.alarmnet.com/TC2/}ResultData').text
    return

#---- EOL API Section ----#

def arm_away():
    print >> Log, 'Setting system to ARMED-Away.'
    TC2_ArmSecuritySystem_Away()
    return
    
def disarm():
    print >> Log, 'Setting system to DISARMED...'
    TC2_DisarmSecuritySystem()
    return
    
def countPeople():
    global peopleTotal
    peopleTotal=0
    cmd = subprocess.Popen('arp -a -i re0_vlan4', shell=True, stdout=subprocess.PIPE)
    for line in cmd.stdout:
        if device1 in line:
            peopleTotal += 1
            print >> Log, "Steven is present",peopleTotal
        if device2 in line:
            peopleTotal += 1
            print >> Log, "Rob is present",peopleTotal
        if device3 in line:
            peopleTotal += 1
            print >> Log, "Ashley is present",peopleTotal
#        cfgfile = open("/root/Security.ini",'w')
#        Config.set('Status','armed', True)
#        Config.write(cfgfile)
#        cfgfile.close()
    return

# ---- BOL Program Initiation and function mapping ----#
def runcheck():
    countPeople()
    print state, peopleTotal
    #Check ENV with if Statement to see if the "Armed" boolean is true or false 
            
    if now_time >= time(23,59) or now_time <= time(5,30):
        if state == False and peopleTotal >0:
            cfgfile = open("/root/Security.ini",'w')
            Config.set('Status','armed', True)
            Config.write(cfgfile)
            cfgfile.close()
            TC2_ArmSecuritySystem_Stay()
            print >> Log, "arming - It's now between 11:59AM and 5:30AM"
    else:
        if state is True and peopleTotal >0:
            print >> Log, "disarming - more then 0"
            disarm()
            cfgfile = open("/root/Security.ini",'w')
            Config.set('Status','armed', False)
            Config.write(cfgfile)
            cfgfile.close()  
            print "Disarming", state
        else:
            if state is False and peopleTotal <=0:
                print >> Log, "arming away - less then 1"
                arm_away()
                cfgfile = open("/root/Security.ini",'w')
                Config.set('Status','armed', True)
                Config.write(cfgfile)
                cfgfile.close()
                print "Arming Away", state
                return
runcheck()
# ---- EOL Program Initiation and function mapping ----#

#---- Logging ---- #
print >> Log, "- Armed",state,"-",peopleTotal,"DEVICES PRESENT","-"
Log.close() 
#---- EOL for LOG Output ---- #
