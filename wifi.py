# Copyright (c) 2019-2023, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.
from scapy.all import *
from scapy.arch.linux import L2Socket, attach_filter
from datetime import datetime
import binascii

#### Constants ####

FRAME_TYPE_MANAGEMENT = 0
FRAME_TYPE_CONTROL    = 1
FRAME_TYPE_DATA       = 2

FRAME_CONTROL_ACK     = 13

FRAME_DATA_NULLFUNC   = 4
FRAME_DATA_QOSNULL    = 12

IEEE_TLV_TYPE_SSID    = 0
IEEE_TLV_TYPE_CHANNEL = 3
IEEE_TLV_TYPE_TIM     = 5
IEEE_TLV_TYPE_RSN     = 48
IEEE_TLV_TYPE_CSA     = 37
IEEE_TLV_TYPE_FT      = 55
IEEE_TLV_TYPE_VENDOR  = 221

WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4
WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6
WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7

#TODO: Not sure if really needed...
IEEE80211_RADIOTAP_RATE = (1 << 2)
IEEE80211_RADIOTAP_CHANNEL = (1 << 3)
IEEE80211_RADIOTAP_TX_FLAGS = (1 << 15)
IEEE80211_RADIOTAP_DATA_RETRIES = (1 << 17)

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

def change_log_level(delta):
	global global_log_level
	global_log_level += delta

def croprepr(p, length=175):
	string = repr(p)
	if len(string) > length:
		return string[:length - 3] + "..."
	return string

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

def get_macaddress(iface):
	try:
		# This method has been widely tested.
		s = get_if_raw_hwaddr(iface)[1]
		return ("%02x:" * 6)[:-1] % tuple(orb(x) for x in s)
	except:
		# Keep the old method as a backup though.
		return open("/sys/class/net/%s/address" % iface).read().strip()

def addr2bin(addr):
	return binascii.a2b_hex(addr.replace(':', ''))

def get_channel(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("channel (\d+)")
	m = p.search(output)
	if m == None: return None
	return int(m.group(1))

def set_channel(iface, channel):
	if isinstance(channel, int):
		# Compatibility with old channels encoded as simple integers
		subprocess.check_output(["iw", iface, "set", "channel", str(channel)])
	else:
		# Channels represented as strings with extra info (e.g "11 HT40-")
		subprocess.check_output(["iw", iface, "set", "channel"] + channel.split())

def chan2freq(channel):
	if 1 <= channel <= 13:
		return 2412 + (channel - 1) * 5
	elif channel == 14:
		return 2484
	else:
		raise Exception("Unsupported channel in chan2freq")

def set_macaddress(iface, macaddr):
	# macchanger throws an error if the interface already has the given MAC address
	if get_macaddress(iface) != macaddr:
		subprocess.check_output(["ifconfig", iface, "down"])
		subprocess.check_output(["macchanger", "-m", macaddr, iface])

def get_iface_type(iface):
	output = str(subprocess.check_output(["iw", iface, "info"]))
	p = re.compile("type (\w+)")
	return str(p.search(output).group(1))

def set_monitor_mode(iface, up=True, mtu=1500):
	# Note: we let the user put the device in monitor mode, such that they can control optional
	#       parameters such as "iw wlan0 set monitor active" for devices that support it.
	if get_iface_type(iface) != "monitor":
		# Some kernels (Debian jessie - 3.16.0-4-amd64) don't properly add the monitor interface. The following ugly
		# sequence of commands assures the virtual interface is properly registered as a 802.11 monitor interface.
		subprocess.check_output(["ifconfig", iface, "down"])
		subprocess.check_output(["iw", iface, "set", "type", "monitor"])
		time.sleep(0.5)
		subprocess.check_output(["iw", iface, "set", "type", "monitor"])

	if up:
		subprocess.check_output(["ifconfig", iface, "up"])
	subprocess.check_output(["ifconfig", iface, "mtu", str(mtu)])

def set_monitor_active(iface):
	# Interface must be down in order to set active flag
	subprocess.check_output(["ifconfig", iface, "down"])
	try:
		subprocess.check_output(["iw", iface, "set", "monitor", "active"])
		return True
	except subprocess.CalledProcessError:
		log(WARNING, f"Interface {iface} doesn't support active monitor mode")
		return False

def set_managed_mode(iface, up=True):
	# Always put it down. This needs to be done to change the type
	subprocess.check_output(["ifconfig", iface, "down"])
	subprocess.check_output(["iw", iface, "set", "type", "managed"])
	if up:
		subprocess.check_output(["ifconfig", iface, "up"])

def set_ap_mode(iface, up=True):
	# Always put it down. This also assure it will stop broadcasting beacons.
	subprocess.check_output(["ifconfig", iface, "down"])
	if get_iface_type(iface) != "AP":
		try:
			# When using "iw iface set type ap" it claims that a daemon like hostapd is
			# required. But by using "iw iface set type __ap" we can set it in AP mode.
			subprocess.check_output(["iw", iface, "set", "type", "__ap"])
		except subprocess.CalledProcessError:
			return False

	if up:
		subprocess.check_output(["ifconfig", iface, "up"])

	return True

def start_ap(iface, channel, beacon=None, ssid=None, interval=100, dtim_period=1):
	"""
	Put the interface in AP mode (if not yet done) and start broadcasting beacons.
	All other AP functionality would require a deamon or manual nl80211 calls.

	@param iface	Interface to put in AP mode
	@param channel	Channel to use (an integer)
	@param beacon	Optional: beacon to broadcast. Should contain a full beacon including all MAC addresses.
	@param ssid		Optional: override the SSID that is given to the kernel. I'm not sure why this parameter
	                is important and can be given to the kernel. The advertised SSID is taken from the beacon
	                and is not influenced by this parameter.
	@param interval	How often to broadcast the beacon (in TU). Maximum allowed value by Linux is 10000.
	"""

	# Use minimal beacon if not given. Otherwise copy beacon so the given beacon isn't modified.
	if beacon == None:
		ownmac = get_macaddress(iface)
		beacon = Dot11(addr2=ownmac, addr3=ownmac)/Dot11Beacon()
	else:
		beacon = beacon.copy()

	# In order of priority use the provided ssid, the ssid in the beacon, or a default one.
	if ssid == None:
		ssid = get_ssid(beacon)
	if ssid == None:
		ssid = "libwifi-ap-" + get_macaddress(iface)

	# Find the TIM element so we can construct the beacon "head" and "tail" that is
	# before and after the TIM element.
	prev_tim = get_prev_element(beacon, IEEE_TLV_TYPE_TIM)
	if prev_tim != None:
		after_tim = prev_tim.payload.payload
		prev_tim.remove_payload()
	else:
		after_tim = None

	# iw dev <devname> ap start  <SSID> <control freq> [5|10|20|40|80|80+80|160] [<center1_freq> [<center2_freq>]]
	#		<beacon interval in TU> <DTIM period> [hidden-ssid|zeroed-ssid] head <beacon head in hexadecimal>
	#		[tail <beacon tail in hexadecimal>] [inactivity-time <inactivity time in seconds>] [key0:abcde d:1:6162636465]
	cmd = ["iw", "dev", iface, "ap", "start", ssid, str(chan2freq(channel)), str(interval), str(dtim_period), "head", raw(beacon).hex()]
	if after_tim != None:
		cmd += ["tail", raw(after_tim).hex()]

	# Do the real magic: interface in AP mode and start broadcasting beacons
	set_ap_mode(iface)
	log(STATUS, f"Starting AP using: {' '.join(cmd)}")
	subprocess.check_output(cmd)

	# With rt2800usb we need to execute "ifconfig wlan0 up" after "ap start" to make the
	# interface acknowledge recieved frames. Otherwise it wouldn't send ACKs. So to be sure,
	# do this for all interfaces.
	subprocess.check_output(["ifconfig", iface, "up"])

def stop_ap(iface):
	cmd = ["iw", "dev", iface, "ap", "stop"]
	log(STATUS, f"Stopping AP using: {' '.join(cmd)}")
	subprocess.check_output(cmd)

def rawmac(addr):
	return bytes.fromhex(addr.replace(':', ''))

def set_amsdu(p):
	if "A_MSDU_Present" in [field.name for field in Dot11QoS.fields_desc]:
		p.A_MSDU_Present = 1
	else:
		p.Reserved = 1

def is_amsdu(p):
	if "A_MSDU_Present" in [field.name for field in Dot11QoS.fields_desc]:
		return p.A_MSDU_Present == 1
	else:
		return p.Reserved == 1

def remove_dot11qos(p):
	if not Dot11QoS in p: return
	p = p.copy()
	payload = p[Dot11QoS].payload
	p.remove_payload()
	p /= payload
	p.subtype = 0
	return p

def is_valid_sae_pk_password(pw):
	if pw is None:
		return False

	pw = pw.strip('"')
	if len(pw) < 14 or len(pw) % 5 != 4:
		return False

	should_be_dashes = pw[4::5]
	if not all(c == "-" for c in should_be_dashes):
		return False
	if len(should_be_dashes) != pw.count("-"):
		return False

	#TODO: Verify that the checksum and Sec_1b matches
	return True

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

# Compatibility with older Scapy versions
if not "ORDER" in scapy.layers.dot11._rt_txflags:
	scapy.layers.dot11._rt_txflags.append("ORDER")

class MonitorSocket(L2Socket):
	def __init__(self, iface, dumpfile=None, detect_injected=False, **kwargs):
		self.pcap = None
		self.detect_injected = detect_injected
		self.default_rate = None
		super(MonitorSocket, self).__init__(iface, **kwargs)
		if dumpfile:
			self.pcap = PcapWriter("%s.%s.pcap" % (dumpfile, self.iface), append=False, sync=True)

	def set_channel(self, channel):
		subprocess.check_output(["iw", self.iface, "set", "channel", str(channel)])

	def attach_filter(self, bpf):
		log(DEBUG, "Attaching filter to %s: %s" % (self.iface, bpf))
		attach_filter(self.ins, bpf, self.iface)

	def set_default_rate(self, rate):
		self.default_rate = rate

	def send(self, p, rate=None):
		# Hack: set the More Data flag so we can detect injected frames (and so clients stay awake longer)
		if self.detect_injected:
			p.FCfield |= 0x20

		# Control data rate of injected frames
		if RadioTap in p:
			log(WARNING, f"MonitorSocket: Injected frame already contains RadioTap header: {repr(p)}")
		else:
			if rate is None and self.default_rate is None:
				rtap = RadioTap(present="TXFlags", TXFlags="NOSEQ+ORDER")
			else:
				use_rate = rate if rate != None else self.default_rate
				rtap = RadioTap(present="TXFlags+Rate", Rate=use_rate, TXFlags="NOSEQ+ORDER")
			p = rtap/p

		L2Socket.send(self, p)
		if self.pcap: self.pcap.write(p)

	def _strip_fcs(self, p):
		"""
		Scapy may throw exceptions when handling malformed short frames,
		so we need to catch these exceptions and just ignore these frames.
		This in particular happened with short malformed beacons.
		"""
		try:
			return Dot11(raw(p[Dot11FCS])[:-4])
		except:
			return None

	def _detect_and_strip_fcs(self, p):
		# Older scapy can't handle the optional Frame Check Sequence (FCS) field automatically.
		# FIXME: simplify this code by using newer scapy functionality (we use a virtualenv anyway).
		if p[RadioTap].present & 2 != 0 and not Dot11FCS in p:
			rawframe = raw(p[RadioTap])
			pos = 8
			while orb(rawframe[pos - 1]) & 0x80 != 0: pos += 4

			# If the TSFT field is present, it must be 8-bytes aligned
			if p[RadioTap].present & 1 != 0:
				pos += (8 - (pos % 8))
				pos += 8

			# Remove FCS if present
			if orb(rawframe[pos]) & 0x10 != 0:
				return self._strip_fcs(p)

		return p[Dot11]

	def recv(self, x=MTU, injected=False):
		"""
		@param injected	When set to True, injected frames will be recieved by this function.
		                This is because the kernel "echoes" them back with a RadioTap header
		                that includes information about the transmission of the injected frame.
		                We strip the RadioTap header this, so recieving these frames is
		                usually useless in scripts, hence this value is by default False.
		"""
		p = L2Socket.recv(self, x)
		if p == None or not (Dot11 in p or Dot11FCS in p):
			return None
		if self.pcap:
			self.pcap.write(p)

		# Hack: ignore frames that we just injected and are echoed back. This may be useful
		#       when an injected frame is received by another dongle.
		if self.detect_injected and p.FCfield & 0x20 != 0:
			return None

		# Ignore reflection of injected frames. These contain TXFlags in the RadioTap header.
		# FIXME: This also ignores Beacons generated on the same interface (at least with mac80211_hwsim).
		if p[RadioTap].present & "TXFlags":
			return None

		# Strip the FCS if present, and drop the RadioTap header
		if Dot11FCS in p:
			return self._strip_fcs(p)
		else:
			return self._detect_and_strip_fcs(p)

	def flush(self):
		while len(select.select([self], [], [], 0)[0]) > 0:
			L2Socket.recv(self, MTU)

	def close(self):
		if self.pcap: self.pcap.close()
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
	return orb(iv0) + (orb(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)

def dot11_get_iv(p):
	"""
	This function assumes the frame is encrypted using either CCMP or WEP.
	It does not work for other encrypion protocol (e.g. TKIP).
	"""

	# The simple and default case
	if Dot11CCMP in p:
		payload = raw(p[Dot11CCMP])
		return payload_to_iv(payload)

	# Scapy uses a heuristic to differentiate CCMP/TKIP and this may be wrong.
	# So even when we get a Dot11TKIP frame, we'll still treat it like a Dot11CCMP frame.
	elif Dot11TKIP in p:
		payload = raw(p[Dot11TKIP])
		return payload_to_iv(payload)

	elif Dot11WEP in p:
		wep = p[Dot11WEP]
		# Older Scapy versions parse CCMP-encrypted frames as Dot11WEP. So we check if the
		# extended IV flag is set, and if so, treat it like a CCMP frame.
		if wep.keyid & 32:
			# This only works for CCMP (TKIP uses a different IV structure).
			return orb(wep.iv[0]) + (orb(wep.iv[1]) << 8) + (struct.unpack(">I", wep.wepdata[:4])[0] << 16)

		# If the extended IV flag is not set meaning it's indeed WEP.
		else:
			return orb(wep.iv[0]) + (orb(wep.iv[1]) << 8) + (orb(wep.iv[2]) << 16)

	# Scapy uses Dot11Encrypted if it couldn't determine how the frame was encrypted. Assume CCMP.
	elif Dot11Encrypted in p:
		payload = raw(p[Dot11Encrypted])
		return payload_to_iv(payload)

	# Manually detect encrypted frames in case (older versions of) Scapy failed to do this. Assume CCMP.
	elif p.FCfield & 0x40:
		return payload_to_iv(p[Raw].load)

	# Couldn't determine the IV
	return None

def dot11_get_priority(p):
	if not Dot11QoS in p: return 0
	return p[Dot11QoS].TID


#### Crypto functions and util ####

def get_ccmp_keyid(p):
	if Dot11WEP in p:
		return p.keyid
	return p.key_id

def get_ccmp_payload(p):
	if Dot11WEP in p:
		# Extract encrypted payload:
		# - Skip extended IV (4 bytes in total)
		# - Exclude first 4 bytes of the CCMP MIC (note that last 4 are saved in the WEP ICV field)
		return raw(p.wepdata[4:-4])
	elif Dot11CCMP in p:
		return p[Dot11CCMP].data
	elif Dot11TKIP in p:
		return p[Dot11TKIP].data
	elif Dot11Encrypted in p:
		return p[Dot11Encrypted].data
	elif Raw in p:
		return p[Raw].load
	else:
		return None

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
	# This special case is useful so scapy keeps the full "interpretation" of the frame
	# instead of afterwards treating/displaying the payload as just raw data.
	if num_frags == 1: return [header/data]

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

def get_element(el, id):
	if not Dot11Elt in el: return None
	el = el[Dot11Elt]
	while not el is None:
		if el.ID == id:
			return el
		el = el.payload
	return None

def get_prev_element(p, id):
	if not Dot11Elt in p: return None
	curr = p[Dot11Elt]
	prev = None
	while not curr is None:
		if curr.ID == id:
			return prev
		prev = curr
		curr = curr.payload
	return None

def get_ssid(beacon):
	if not (Dot11 in beacon or Dot11FCS in beacon): return
	if Dot11Elt not in beacon: return
	if beacon[Dot11].type != 0 and beacon[Dot11].subtype != 8: return
	el = get_element(beacon, IEEE_TLV_TYPE_SSID)
	return el.info.decode()

def is_from_sta(p, macaddr):
	if not (Dot11 in p or Dot11FCS in p):
		return False
	if p.addr1 != macaddr and p.addr2 != macaddr:
		return False
	return True

def get_bss(iface, clientmac, timeout=20):
	ps = sniff(count=1, timeout=timeout, lfilter=lambda p: is_from_sta(p, clientmac) and p.addr2 != None, iface=iface)
	if len(ps) == 0:
		return None
	return ps[0].addr1 if ps[0].addr1 != clientmac else ps[0].addr2

def create_msdu_subframe(src, dst, payload, last=False):
	length = len(payload)
	p = Ether(dst=dst, src=src, type=length)

	payload = raw(payload)

	total_length = len(p) + len(payload)
	padding = ""
	if not last and total_length % 4 != 0:
		padding = b"\x00" * (4 - (total_length % 4))

	return p / payload / Raw(padding)

def find_network(iface, ssid, opened_socket):
	log(STATUS, "Searching for target network...")
	for chan in [None, 1, 6, 11, 3, 8, 2, 7, 4, 10, 5, 9, 12, 13]:
		# We first search on the current channel that the network card is on
		if chan != None:
			set_channel(iface, chan)
			log(DEBUG, f"Listening on channel {chan}")
		if opened_socket == None:
			ps = sniff(count=1, timeout=0.3, lfilter=lambda p: get_ssid(p) == ssid, iface=iface)
		else:
			ps = sniff(count=1, timeout=0.3, lfilter=lambda p: get_ssid(p) == ssid, opened_socket=opened_socket)
		if ps and len(ps) >= 1: break

	if ps and len(ps) >= 1:
		# Even though we capture the beacon we might still be on another channel,
		# so it's important to explicitly switch to the correct channel.
		actual_chan = orb(get_element(ps[0], IEEE_TLV_TYPE_CHANNEL).info)
		set_channel(iface, actual_chan)

		# Return the beacon that we captured
		return ps[0]

	return None


def construct_csa(channel, count=1):
	switch_mode = 1			# STA should not Tx untill switch is completed
	new_chan_num = channel	# Channel it should switch to
	switch_count = count	# Immediately make the station switch

	# Contruct the IE
	payload = struct.pack("<BBB", switch_mode, new_chan_num, switch_count)
	return Dot11Elt(ID=IEEE_TLV_TYPE_CSA, info=payload)


def append_csa(p, channel, count=1):
	p = p.copy()

	el = p[Dot11Elt]
	prevel = None
	while isinstance(el, Dot11Elt):
		prevel = el
		el = el.payload

	prevel.payload = construct_csa(channel, count)

	return p

