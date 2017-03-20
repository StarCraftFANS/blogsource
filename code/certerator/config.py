#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Author - laosanlaoyao
#
#  This tool will parse all certificates from a Windows 'exe' file,
#  and change the certerator.py with the first two certificates.
#
#  It reads from in.exe, For example:
#      python config.py -from in.exe
#

import os
import sys
import re

os.system("osslsigncode extract-signature -in "+sys.argv[2] + " -out sig.bin")

fp = open("sig.bin","rb")
data = fp.read()
fp.close()
fp = open("sig.bin","wb")
fp.write(data[8:])
fp.close()

os.system("openssl asn1parse -in sig.bin -inform der -i > sig.asc")

fp = open("sig.asc","rb")
data = fp.read()
fp.close()

items = re.findall("d=([0-9]*)[^\n]*OBJECT\s*:([^\n]*)[^:]*:[^:]*:\s*[A-Z0-9]*\s*:([^\n]*)", data)  
base = ['commonName', 'stateOrProvinceName', 'localityName', 'organizationName', 'countryName']
dic = {}
count = 0
d0 = -1

num = 0
id1 = 1
id2 = 2
if len(items) >= 4:
    id1 = 3
    id2 = 4

fp = open("configure","wb")
for item in items:
    if d0 == -1:
        d0 = int(item[0])
    dic["d"] = item[0]
    dic[item[1]] = item[2]
    if item[1] in base:
        count = count + 1
    
    if count == 5:
        num = num + 1
        if num == id1:
            data = open("certerator.py","r").read()
            if dic.has_key("commonName"):
                data = re.sub("ca\['commonName'\] = [^\n]*", 
                              "ca['commonName'] = \""+dic["commonName"]+"\"", data)
            if dic.has_key("stateOrProvinceName"):
                data = re.sub("ca\['stateOrProvinceName'\] = [^\n]*", 
                              "ca['stateOrProvinceName'] = \""+dic["stateOrProvinceName"]+"\"", data)
            if dic.has_key("localityName"):
                data = re.sub("ca\['localityName'\] = [^\n]*", 
                              "ca['localityName'] = \""+dic["localityName"]+"\"", data)
            if dic.has_key("organizationName"):
                data = re.sub("ca\['organizationName'\] = [^\n]*", 
                              "ca['organizationName'] = \""+dic["organizationName"]+"\"", data)
            if dic.has_key("organizationalUnitName"):
                data = re.sub("ca\['organizationalUnitName'\] = [^\n]*", 
                              "ca['organizationalUnitName'] = \""+dic["organizationalUnitName"]+"\"", data)
            if dic.has_key("countryName"):
                data = re.sub("ca\['countryName'\] = [^\n]*", 
                              "ca['countryName'] = \""+dic["countryName"]+"\"", data)
            open("certerator.py","w").write(data)
        
        if num == id2:
            if dic.has_key("commonName"):
                data = re.sub("cert\['commonName'\] = [^\n]*", 
                              "cert['commonName'] = \""+dic["commonName"]+"\"", data)
            if dic.has_key("stateOrProvinceName"):
                data = re.sub("cert\['stateOrProvinceName'\] = [^\n]*", 
                              "cert['stateOrProvinceName'] = \""+dic["stateOrProvinceName"]+"\"", data)
            if dic.has_key("localityName"):
                data = re.sub("cert\['localityName'\] = [^\n]*", 
                              "cert['localityName'] = \""+dic["localityName"]+"\"", data)
            if dic.has_key("organizationName"):
                data = re.sub("cert\['organizationName'\] = [^\n]*", 
                              "cert['organizationName'] = \""+dic["organizationName"]+"\"", data)
            if dic.has_key("countryName"):
                data = re.sub("cert\['countryName'\] = [^\n]*", 
                              "cert['countryName'] = \""+dic["countryName"]+"\"", data)
            open("certerator.py","w").write(data)
        
        for key in dic.keys():
            if key == "d": continue
            for n in range(0, int(dic["d"])-d0):
                fp.write(" ")
            fp.write(key + ": " + dic[key] + "\n")
        fp.write("\n")
        
        count = 0
        dic = {}
fp.close()
