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

class Attributes:
   def __init__(self,name):
      self.name = name

def Endian(bytes):
   if (LittleE):
      LE_val = str()
      bytes = bytes[::-1]
      bytes = ''.join(bytes)
      return bytes
   else :
      bytes = ''.join(bytes)
      return bytes

def Standard_Info_Parse(entry,byte,res,next) :
   if res == '00' :
      off = MFTentryList[entry][byte+20:byte+22]
      offset = Endian(off)
      byte += int(offset,16)
      Av = MFTentryList[entry][byte+32:byte+36]
      flag = Endian(Av)
      if flag not in Flags :
         print("Invalid Flag")
      else:
         print("     Flag Value:", Flags[flag])
      Attribute_head_Parse(next)
   else:
      print("Non-Resident")


def File_Name_Parse(entry,byte,res,next) :
   if res == '00' :
      off = MFTentryList[entry][byte+20:byte+22]
      offset = Endian(off)
   else:
      print("Non-Resident")
   #adds offset and 64 bytes(lower) to find length of name.
   byte += int(offset,16)
   Size = int(MFTentryList[entry][byte],16)
   global name
   byte += 64
   nameLen = int(MFTentryList[entry][byte],16)
   nameLen *= 2
   name = MFTentryList[entry][byte+2:byte+nameLen+2]
   #will join all hex values and convert to ascii
   #***WE MUST STILL CHECK WHAT THE CHARACTER ENCODING IS***
   print("     File Name:",bytearray.fromhex(''.join(name)).decode('utf-16')) 
   Attribute_head_Parse(next)

def Data_Parser(entry,byte,res,nextAttr,aLen):
   #PAGE 258!!#
   if bytearray.fromhex(''.join(name)).decode('utf-16') == "$BadClus":
      pass
   else:
      if res == '00' :
         ContentSize = MFTentryList[entry][byte+16:byte+20]
         off = MFTentryList[entry][byte+20:byte+22]
         offset = Endian(off)
         byte += int(offset,16)
         print(ContentSize)
         #off = MFTentryList[entry][byte:byte+8]
         #print(Endian(off))
         #print(off)
      else:
         print("  Non-Resident")
         #StartVCN = MFTentryList[entry][byte+16:byte+24]
         EndVCN = MFTentryList[entry][byte+24:byte+32]
         RunOffSet = MFTentryList[entry][byte+32:byte+34] 
         AllocSize = MFTentryList[entry][byte+40:byte+48]
         #ActualSize = MFTentryList[entry][byte+48:byte+56]
         byte += int(Endian(RunOffSet),16)
         
         scale = 16
         num_of_bits = 8
         Binary = bin(int(MFTentryList[entry][byte], scale))[2:].zfill(num_of_bits)
         BinList = list()
         for i in Binary :
            BinList.append(i)
         CountOff= int(''.join(BinList[0:4]),2)
         CountLen = int(''.join(BinList[4:8]),2)

         print("   Byte offset to file",int(Endian(RunOffSet),16),"\n   Count Length bytes: "+str(CountLen)+"\n   Count Offset bytes: "+str(CountOff))

         #byte += 1
         #CountOff += byte
         #RunLen = int(Endian(MFTentryList[entry][byte:byte+CountLen]),16)
         #RunOff = int(Endian(MFTentryList[entry][byte+CountLen:CountOff+1]),16)
         #print(Endian(MFTentryList[entry][byte+CountLen:CountOff+1]))
         
         #print("  File starts at Cluster: "+str(RunOff))
         #print("  Cluster Length: "+str(RunLen))
      #print(int(Endian(EndVCN),16))

      #off = MFTentryList[entry][byte:byte+8]
      #print(Endian(off))
   Attribute_head_Parse(nextAttr)

#Byte range is 16-17 for example but in python you do 16:18 but it only read 16 and 18.
#Parses the attribute head and passes to Attribute parser.
def Attribute_head_Parse(byte) :
   #attribute 1 value
   res = MFTentryList[entry][byte+8]
   #if res == '00' :
      #Aid = MFTentryList[entry][byte:byte+4]
   aID = int(Endian(MFTentryList[entry][byte:byte+4]),16)
      #Av = MFTentryList[entry][byte+4:byte+8]
   aLen = int(Endian(MFTentryList[entry][byte+4:byte+8]),16)
   nextAttr = byte + aLen
   #else :
   #   Aid = MFTentryList[entry][byte:byte+4]
   #   aID = int(Endian(Aid),16)
   #   Av = MFTentryList[entry][byte+4:byte+8]
   #   aLen = int(Endian(Av),16)
   #   nextAttr = byte + aLen
   #   StartVCN = MFTentryList[entry][byte+16:byte+24]
    
   #   num = Endian(StartVCN)
   #   print(int(num,16))
      #Atype = AttribType[str(aID)]
   if str(aID) in AttribType:
      Atype = AttribType[str(aID)]
      print(Atype)
   else:
      None

   if aID == 16 :
      Standard_Info_Parse(entry,byte,res,nextAttr)
   elif aID == 32:
      print("Attriblist")
   elif aID == 48:
      File_Name_Parse(entry,byte,res,nextAttr)
   elif aID == 64:
      print("    Not Configured")
   elif aID == 80:
      print("    Not Configured")
   elif aID == 96:
      print("    Not Configured")
   elif aID == 112:
      print("    Not Configured")
   elif aID == 128:
      #print("    Not Configured")
      Data_Parser(entry,byte,res,nextAttr,aLen)
   elif aID == 144:
      print("    Not Configured")
   elif aID == 160:
      print("    Not Configured")
   elif aID == 176:
      print("    Not Configured")
   elif aID == 192:
      print("    Not Configured")
   elif aID == 208:
      print("    Not Configured")
   elif aID == 224:
      print("    Not Configured")
   elif aID == 256:
      print("    Not Configured")
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

def printer() :
   print(str(getattr(Attributes, "Entry"))+".")
   print("File Name:",getattr(Attributes, "F_Name"),'\n')

FoundEntries = len(MFTentryList)
for entry in range(0,FoundEntries) :
   MFT_Parser(entry)
   print('\n\n')