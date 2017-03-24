#!/usr/bin/python3

import os
import sys
import re

off = str(sys.argv[1])
filen = str(sys.argv[2])

cmd1 = "dd if="+filen+" bs=512 count=1 status=none | xxd -g1 | sed -n '28,32p' > /root/Desktop/hexd.txt"
os.system(cmd1)
hexdfile = open("/root/Desktop/hexd.txt", 'r').readlines()
regex = re.compile("000001f0:.*55 aa")
if re.search(regex, str(hexdfile)) :
   LittleE = True
else :
   LittleE = False



#cheating and using fsstat
fss = "fsstat " + filen + " > /root/Desktop/fsstat.txt"
fssout = str(os.system(fss))
fssfile = open('/root/Desktop/fsstat.txt','r').readlines()

c1 = re.compile(r"First Cluster of MFT:.(.*)\n")
c2 = re.compile(r"Cluster Size:.(.*)\n")
s1 = re.compile(r"Sector Size:.(.*)\n")

newfss = str()
for line in fssfile :
   newfss += line
   newfss += '\n'
MFTclus = re.findall(c1, newfss)[0]
#clustSec = int((eval(re.findall(c2, newfss)[0])) / (eval(re.findall(s1, newfss)[0])))
SecClust = re.findall(c2, newfss)[0]

cmd1 = "dd if=" + filen + " bs=" + SecClust + " skip=" + MFTclus + " count=20 status=none | xxd -p > /root/Desktop/hexd.txt"
os.system(cmd1)
line = open("/root/Desktop/hexd.txt", 'r').readlines()


hexlist = list()

for data in line :
   hextemp = list(([data[i:i+2] for i in range(0,len(data), 2)]))
   hexlist += hextemp
   hexlist.remove('\n')

#list of mft entries and appends byte number to list in order. 
MFTentries = list()
#46 49 4c 45
for i in range(0,len(hexlist), 1) :
   if hexlist[i] == '46' :
      if hexlist[i+1] == '49' :
         if hexlist[i+2] == '4c' :
            if hexlist[i+3] == '45' :
               MFTentries.append(i)

MFTentryList = list()
for i in MFTentries :
   MFTentryList.append(hexlist[i:i+1024])

#Byte range is 16-17 for example but in python you do 16:18 but it only read 16 and 18.
def MFT_Parser(entry) :
   def Attribute_head_Parse(byte) :
      #attribute 1 value
      Av = MFTentryList[entry][byte:byte+4]
      if (LittleE):
         aID = int(Av[3]+Av[2]+Av[1]+Av[0],16)
      else:
         aID = int(Av[0]+Av[1]+Av[2]+Av[3],16)
      Av = MFTentryList[entry][byte+4:byte+8]
      if (LittleE):
         aLen = int(Av[3]+Av[2]+Av[1]+Av[0],16)
      else:
         aLen = int(Av[0]+Av[1]+Av[2]+Av[3],16)
      nextA = byte + aLen
      res = MFTentryList[entry][byte+8]
      print(res)
      
   print("Sequence Value = ",MFTentryList[entry][16:18])
   print("offset of first attrib = ",MFTentryList[entry][20:22])
   print("MFT allocated size = ",MFTentryList[entry][28:32])
   if (LittleE):
      B1a = int(MFTentryList[entry][21] + MFTentryList[entry][20],16)
   else:   
      B1a = int(MFTentryList[entry][20] + MFTentryList[entry][21],16)
   Attribute_head_Parse(B1a) 


FoundEntries = len(MFTentryList)
for entry in range(0,FoundEntries) :
   MFT_Parser(entry)


