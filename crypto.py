#!/usr/bin/env python3
import struct, binascii
from .wifi import *
#from binascii import a2b_hex
#from struct import unpack,pack

from Crypto.Cipher import AES
from scapy.layers.dot11 import Dot11, Dot11CCMP, Dot11QoS

def pn2bytes(pn):
	pn_bytes = [0] * 6
	for i in range(6):
		pn_bytes[i] = pn & 0xFF
		pn >>= 8
	return pn_bytes

def pn2bin(pn):
	return struct.pack(">Q", pn)[2:]

def dot11_get_fc(p):
	result = (p.proto << 2) + p.type
	result = (result << 2) + p.subtype
	return struct.pack("<BB", result, int(p.FCfield))

def ccmp_get_nonce(priority, addr, pn):
	return struct.pack("B", priority) + addr2bin(addr) + pn2bin(pn)

def ccmp_get_aad(p):
	fc = dot11_get_fc(p)
	addr1 = addr2bin(p.addr1)
	addr2 = addr2bin(p.addr2)
	addr3 = addr2bin(p.addr3)

	# Sequence number is masked, but fragment number is included
	sc = struct.pack("<H" , p.SC % 16)
	return fc + addr1 + addr2 + addr3 + sc

def Raw(x):
	return x

def encrypt_ccmp(p, tk, pn):
	"""Takes a plaintext Dot11 frame, encrypts it, and adds all the necessairy headers"""

	# We currently don't support Dot11QoS frames
	assert not Dot11QoS in p
	p = p.copy()

	# Update the FC field
	p.FCfield |= Dot11(FCfield="protected").FCfield

	# TODO: Mask flags that are not part of the AAD
	fc = p.FCfield
	payload = raw(p.payload)
	p.remove_payload()
	keyid = 0
	priority = 0

	# Add the CCMP header. res0 and res1 are by default set to zero.
	newp = p/Dot11CCMP()
	pn_bytes = pn2bytes(pn)
	newp.PN0, newp.PN1, newp.PN2, newp.PN3, newp.PN4, newp.PN5 = pn_bytes
	newp.key_id = keyid
	newp.ext_iv = 1

	# Generate the CCMP Header and AAD for encryption.
	ccm_nonce = ccmp_get_nonce(priority, newp.addr2, pn)
	ccm_aad = ccmp_get_aad(newp)
	print("CCM Nonce:", ccm_nonce.hex())
	print("CCM aad  :", ccm_aad.hex())

	# Encrypt the plaintext using AES in CCM Mode.
	print("Payload:", payload.hex())
	cipher = AES.new(tk, AES.MODE_CCM, ccm_nonce, mac_len=8)
	cipher.update(ccm_aad)
	ciphertext = cipher.encrypt(payload)
	digest = cipher.digest()
	newp = newp/Raw(ciphertext)
	newp = newp/Raw(digest)

	print("Ciphertext:", ciphertext.hex())
	print(repr(newp))
	print(raw(newp).hex())

	return newp

