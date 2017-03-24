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

#lists mft entries and appends byte number to list in order.
MFTentryList = list()
for i in MFTentries :
   MFTentryList.append(hexlist[i:i+1024])

#defining value dictionaries
AttribType = {'16':'$STANDARD_INFORMATION','32':'$ATTRIBUTE_LIST','48':'$FILE_NAME','64':'$OBJECT_ID','80':'$SECURITY_ DESCRIPTOR','96':'$VOLUME_NAME','112':'$VOLUME_ INFORMATION','128':'$DATA','144':'$INDEX_ROOT','160':'$INDEX_ALLOCATION','176':'$BITMAP','192':'$REPARSE_POINT','208':'$EA_INFORMATION','224':'$EA','256':'$LOGGED_UTILITY_STREAM'}

Flags = {'00000001':'Read Only','00000002':'Hidden','00000004':'System','00000020':'Archive','00000040':'Device','00000080':'#Normal', '00000100':'Temporary','00000200':'Sparse file','00000400':'Reparse point','00000800':'Compressed','00001000':'Offline','00002000': 'Content is not being indexed for faster searches','00004000':'Encrypted'}

def Standard_Info_Parse(entry,byte,res,next) :
   if res == '00' :
      off = MFTentryList[entry][byte+20:byte+22]
      if (LittleE):
         offset = int(off[1]+off[0],16)
      else:
         offset = int(off[0]+off[1],16)
   else:
      print("Non-Resident")

   byte += offset
   Av = MFTentryList[entry][byte+32:byte+36]
   if (LittleE):
      flag = Av[3]+Av[2]+Av[1]+Av[0]
   else:
      flag = Av[0]+Av[1]+Av[2]+Av[3]
   if flag not in Flags :
      print(flag)
   else:
      print(Flags[flag])
   Attribute_head_Parse(next)

def File_Name_Parse(entry,byte,res,next) :
   if res == '00' :
      off = MFTentryList[entry][byte+20:byte+22]
      if (LittleE):
         offset = int(off[1]+off[0],16)
      else:
         offset = int(off[0]+off[1],16)
   else:
      print("Non-Resident")
   #adds offset and 64 bytes to find length of name.
   byte += offset + 64
   nameLen = int(MFTentryList[entry][byte],16)
   print(MFTentryList[entry][byte+2:byte+nameLen])
   
   Attribute_head_Parse(next)

#Byte range is 16-17 for example but in python you do 16:18 but it only read 16 and 18.
#Parses the attribute head and passes to Attribute parser.
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
      nextAttr = byte + aLen
      res = MFTentryList[entry][byte+8]
      Atype = AttribType[str(aID)]
      print("Attribute Type: " + Atype)
      
      if aID == 16 :
         Standard_Info_Parse(entry,byte,res,nextAttr)
      elif aID == 32:
         print("bless1")
      elif aID == 48:
         File_Name_Parse(entry,byte,res,nextAttr)
      elif aID == 64:
         print("bless3")
      elif aID == 80:
         print("bless4")
      elif aID == 96:
         print("bless5")
      elif aID == 112:
         print("bless6")
      elif aID == 128:
         print("bless7")
      elif aID == 144:
         print("bless8")
      elif aID == 160:
         print("bless9")
      elif aID == 176:
         print("bless10")
      elif aID == 192:
         print("bless11")
      elif aID == 208:
         print("bless12")
      elif aID == 224:
         print("bless13")
      elif aID == 256:
         print("bless14")
      else:
         print("Value Invalid")

def MFT_Parser(entry) :  
   #print("Sequence Value = ",MFTentryList[entry][16:18])
   #print("offset of first attrib = ",MFTentryList[entry][20:22])
   #print("MFT allocated size = ",MFTentryList[entry][28:32])
   if (LittleE):
      B1a = int(MFTentryList[entry][21] + MFTentryList[entry][20],16)
   else:   
      B1a = int(MFTentryList[entry][20] + MFTentryList[entry][21],16)
   Attribute_head_Parse(B1a) 


FoundEntries = len(MFTentryList)
for entry in range(0,FoundEntries) :
   MFT_Parser(entry)



