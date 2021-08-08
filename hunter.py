import requests
import re
import sys

if len(sys.argv) > 1:
    file = open (sys.argv[1], 'r')
    fileContent = file.readlines()
    file.close()
else:
    print("Usage: python3 hunter.py [input file]")
    sys.exit()


blacklist_talos=[]
blacklist_cins=[]
blacklist_bambenek=[]
list_comp_bambenek=[]
list_inputIPs=[]
malicious_IPs=[]


def get_blacklist_talos():
    a = []
    r = requests.get('https://www.talosintelligence.com/documents/ip-blacklist')
    #print(r.text)
    s = r.text
    a = s.splitlines()
    return a

def get_blacklist_cins():
    a = []
    r = requests.get('http://cinsscore.com/list/ci-badguys.txt')
    #print(r.text)
    s = r.text
    a = s.splitlines()
    return a

def getInputIPs():
    ips =[]
    for i in fileContent:
        #print(""+i)
        ips.append(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',i))

    a = []
    #print(ips)
    for i in ips:
        for j in i:
            a.append(j)
    #print(a)
    return list(set(a))

def searchListIntoList(listA,listB):
    booleanFlag = any(elem in listA for elem in listB)
    #print(booleanFlag)
    if booleanFlag:
        for i in listB:
            if i in listA:
                malicious_IPs.append(i)
                print(i)
    else:
        print("---------- 0 matches ----------")



list_inputIPs = getInputIPs()

blacklist_talos = get_blacklist_talos()
print("-----------------------------------------------------------------------------")
print(">>>MATCH FROM TALOS INTEL:")
print(" ")
searchListIntoList(blacklist_talos, list_inputIPs)
print(" ")
print("-----------------------------------------------------------------------------")
list(blacklist_talos).clear()
blacklist_cins = get_blacklist_cins()
print(">>>MATCH FROM COLLECTIVE INTELLIGENCE NETWORK SECURITY (CINS) ARMY LIST:")
print(" ")
searchListIntoList(blacklist_cins, list_inputIPs)
print(" ")
print("-----------------------------------------------------------------------------")
list(blacklist_cins).clear()
