# Copyright (c) 2019, Mathy Vanhoef <mathy.vanhoef@nyu.edu>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
from scapy.all import *
from Crypto.Cipher import AES
from datetime import datetime
import binascii

#### Constants ####

IEEE_TLV_TYPE_BEACON = 0

WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4
WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6
WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7

#### Basic output and logging functionality ####

ALL, DEBUG, INFO, STATUS, WARNING, ERROR = range(6)
COLORCODES = { "gray"  : "\033[0;37m",
               "green" : "\033[0;32m",
               "orange": "\033[0;33m",
               "red"   : "\033[0;31m" }

global_log_level = INFO
def log(level, msg, color=None, showtime=True):
	if level < global_log_level: return
	if level == DEBUG   and color is None: color="gray"
	if level == WARNING and color is None: color="orange"
	if level == ERROR   and color is None: color="red"
	msg = (datetime.now().strftime('[%H:%M:%S] ') if showtime else " "*11) + COLORCODES.get(color, "") + msg + "\033[1;0m"
	print(msg)

#### Back-wards compatibility with older scapy

if not "Dot11FCS" in locals():
	class Dot11FCS():
		pass
if not "Dot11Encrypted" in locals():
	class Dot11Encrypted():
		pass
	class Dot11CCMP():
		pass
	class Dot11TKIP():
		pass

#### Linux ####

def get_device_driver(iface):
	path = "/sys/class/net/%s/device/driver" % iface
	try:
		output = subprocess.check_output(["readlink", "-f", path])
		return output.decode('utf-8').strip().split("/")[-1]
	except:
		return None

#### Utility ####

def get_mac_address(interface):
	return open("/sys/class/net/%s/address" % interface).read().strip()

def addr2bin(addr):
	return binascii.a2b_hex(addr.replace(':', ''))

#### Packet Processing Functions ####

class DHCP_sock(DHCP_am):
	def __init__(self, **kwargs):
		self.sock = kwargs.pop("sock")
		self.server_ip = kwargs["gw"]
		super(DHCP_sock, self).__init__(**kwargs)

	def prealloc_ip(self, clientmac, ip=None):
		"""Allocate an IP for the client before it send DHCP requests"""
		if clientmac not in self.leases:
			if ip == None:
				ip = self.pool.pop()
			self.leases[clientmac] = ip
		return self.leases[clientmac]

	def make_reply(self, req):
		rep = super(DHCP_sock, self).make_reply(req)

		# Fix scapy bug: set broadcast IP if required
		if rep is not None and BOOTP in req and IP in rep:
			if req[BOOTP].flags & 0x8000 != 0 and req[BOOTP].giaddr == '0.0.0.0' and req[BOOTP].ciaddr == '0.0.0.0':
				rep[IP].dst = "255.255.255.255"

		# Explicitly set source IP if requested
		if not self.server_ip is None:
			rep[IP].src = self.server_ip

		return rep

	def send_reply(self, reply):
		self.sock.send(reply, **self.optsend)

	def print_reply(self, req, reply):
		log(STATUS, "%s: DHCP reply %s to %s" % (reply.getlayer(Ether).dst, reply.getlayer(BOOTP).yiaddr, reply.dst), color="green")

	def remove_client(self, clientmac):
		clientip = self.leases[clientmac]
		self.pool.append(clientip)
		del self.leases[clientmac]

class ARP_sock(ARP_am):
	def __init__(self, **kwargs):
		self.sock = kwargs.pop("sock")
		super(ARP_am, self).__init__(**kwargs)

	def send_reply(self, reply):
		self.sock.send(reply, **self.optsend)

	def print_reply(self, req, reply):
		log(STATUS, "%s: ARP: %s ==> %s on %s" % (reply.getlayer(Ether).dst, req.summary(), reply.summary(), self.iff))


#### Packet Processing Functions ####

class MonitorSocket(L2Socket):
	def __init__(self, **kwargs):
		super(MonitorSocket, self).__init__(**kwargs)

	def send(self, p):
		# Hack: set the More Data flag so we can detect injected frames (and so clients stay awake longer)
		p.FCfield |= 0x20
		L2Socket.send(self, RadioTap()/p)

	def _strip_fcs(self, p):
		# Older scapy can't handle the optional Frame Check Sequence (FCS) field automatically
		if p[RadioTap].present & 2 != 0 and not Dot11FCS in p:
			rawframe = str(p[RadioTap])
			pos = 8
			while ord(rawframe[pos - 1]) & 0x80 != 0: pos += 4

			# If the TSFT field is present, it must be 8-bytes aligned
			if p[RadioTap].present & 1 != 0:
				pos += (8 - (pos % 8))
				pos += 8

			# Remove FCS if present
			if ord(rawframe[pos]) & 0x10 != 0:
				return Dot11(str(p[Dot11])[:-4])

		return p[Dot11]

	def recv(self, x=MTU, reflected=False):
		p = L2Socket.recv(self, x)
		if p == None or not (Dot11 in p or Dot11FCS in p):
			return None

		# Hack: ignore frames that we just injected and are echoed back by the kernel
		if p.FCfield & 0x20 != 0:
			return None

		# Ignore reflection of injected frames. These have a small RadioTap header.
		if not reflected and p[RadioTap].len <= 13:
			return None

		# Strip the FCS if present, and drop the RadioTap header
		if Dot11FCS in p:
			return Dot11(raw(p[Dot11FCS])[:-4])
		else:
			return self._strip_fcs(p)

	def close(self):
		super(MonitorSocket, self).close()

# For backwards compatibility
class MitmSocket(MonitorSocket):
	pass

def dot11_get_seqnum(p):
	return p.SC >> 4

def dot11_is_encrypted_data(p):
	# All these different cases are explicitly tested to handle older scapy versions
	return (p.FCfield & 0x40) or Dot11CCMP in p or Dot11TKIP in p or Dot11WEP in p or Dot11Encrypted in p

def payload_to_iv(payload):
	iv0 = payload[0]
	iv1 = payload[1]
	wepdata = payload[4:8]

	# FIXME: Only CCMP is supported (TKIP uses a different IV structure)
	return ord(iv0) + (ord(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)

def dot11_get_iv(p):
	"""
	Assume it's a CCMP frame. Old scapy can't handle Extended IVs.
	This code only works for CCMP frames.
	"""
	if Dot11CCMP in p or Dot11TKIP in p or Dot11Encrypted in p:
		# Scapy uses a heuristic to differentiate CCMP/TKIP and this may be wrong.
		# So even when we get a Dot11TKIP frame, we should treat it like a Dot11CCMP frame.
		payload = str(p[Dot11Encrypted])
		return payload_to_iv(payload)

	elif Dot11WEP in p:
		wep = p[Dot11WEP]
		if wep.keyid & 32:
			# FIXME: Only CCMP is supported (TKIP uses a different IV structure)
			return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)
		else:
			return ord(wep.iv[0]) + (ord(wep.iv[1]) << 8) + (ord(wep.iv[2]) << 16)

	elif p.FCfield & 0x40:
		return payload_to_iv(p[Raw].load)

	else:
		log(ERROR, "INTERNAL ERROR: Requested IV of plaintext frame")
		return 0

def get_tlv_value(p, type):
	if not Dot11Elt in p: return None
	el = p[Dot11Elt]
	while isinstance(el, Dot11Elt):
		if el.ID == type:
			return el.info
		el = el.payload
	return None

def dot11_get_priority(p):
	if not Dot11QoS in p: return 0
	return p[Dot11QoS].TID


#### Crypto functions and util ####

def get_ccmp_payload(p):
	if Dot11WEP in p:
		# Extract encrypted payload:
		# - Skip extended IV (4 bytes in total)
		# - Exclude first 4 bytes of the CCMP MIC (note that last 4 are saved in the WEP ICV field)
		return str(p.wepdata[4:-4])
	elif Dot11CCMP in p or Dot11TKIP in p or Dot11Encrypted in p:
		return p[Dot11Encrypted].data
	else:
		return p[Raw].load

class IvInfo():
	def __init__(self, p):
		self.iv = dot11_get_iv(p)
		self.seq = dot11_get_seqnum(p)
		self.time = p.time

	def is_reused(self, p):
		"""Return true if frame p reuses an IV and if p is not a retransmitted frame"""
		iv = dot11_get_iv(p)
		seq = dot11_get_seqnum(p)
		return self.iv == iv and self.seq != seq and p.time >= self.time + 1

class IvCollection():
	def __init__(self):
		self.ivs = dict() # maps IV values to IvInfo objects

	def reset(self):
		self.ivs = dict()

	def track_used_iv(self, p):
		iv = dot11_get_iv(p)
		self.ivs[iv] = IvInfo(p)

	def is_iv_reused(self, p):
		"""Returns True if this is an *observed* IV reuse and not just a retransmission"""
		iv = dot11_get_iv(p)
		return iv in self.ivs and self.ivs[iv].is_reused(p)

	def is_new_iv(self, p):
		"""Returns True if the IV in this frame is higher than all previously observed ones"""
		iv = dot11_get_iv(p)
		if len(self.ivs) == 0: return True
		return iv > max(self.ivs.keys())

def create_fragments(header, data, num_frags):
	data = raw(data)
	fragments = []
	fragsize = (len(data) + num_frags - 1) // num_frags
	for i in range(num_frags):
		frag = header.copy()
		frag.SC |= i
		if i < num_frags - 1:
			frag.FCfield |= Dot11(FCfield="MF").FCfield

		payload = data[fragsize * i : fragsize * (i + 1)]
		frag = frag/Raw(payload)
		fragments.append(frag)

	return fragments

