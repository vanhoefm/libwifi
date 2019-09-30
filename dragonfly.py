# TODO: For now only include the code we actually used for EAP-pwd
# TODO: Program unit tests so we can easily keep our EAP-pwd code correct
#!/usr/bin/env python3
from scapy.all import *
from libwifi import *
import sys, struct, math, random, select, time, binascii

from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import ECC
from Crypto.Math.Numbers import Integer

# Alternative is https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python
from sympy.ntheory.residue_ntheory import sqrt_mod_iter

# ----------------------- Utility ---------------------------------

def int_to_data(num):
	return binascii.unhexlify("%064x" % num)

def zeropoint_to_data():
	return int_to_data(0) + int_to_data(0)

#TODO: Not sure if this actually works under python2...
def str2bytes(password):
	if not isinstance(password, str): return password
	if sys.version_info < (3, 0):
		return bytes(password)
	else:
		return bytes(password, 'utf8')

def getord(value):
	if isinstance(value, int):
		return value
	else:
		return ord(value)

def HMAC256(pw, data):
	h = HMAC.new(pw, digestmod=SHA256)
	h.update(data)
	return h.digest()


# ----------------------- Elliptic Curve Operations ---------------------------------

# This is group 19. Support of it is required by WPA3.
secp256r1_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
secp256r1_a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
secp256r1_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
secp256r1_r = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def legendre_symbol(a, p):
	"""Compute the Legendre symbol."""
	if a % p == 0: return 0

	ls = pow(a, (p - 1)//2, p)
	return -1 if ls == p - 1 else ls

def point_on_curve(point):
	rhs = (point.x ** 3 + Integer(secp256r1_a) * point.x + Integer(secp256r1_b)) % Integer(secp256r1_p)
	lhs = (point.y ** 2) % Integer(secp256r1_p)
	return lhs == rhs

def point_to_data(p):
	if p is None:
		return zeropoint_to_data()
	return int_to_data(p.x) + int_to_data(p.y)


# ----------------------- WPA3 ---------------------------------

def is_sae(p):
	if not Dot11Auth in p:
		return False
	return p[Dot11Auth].algo == 3

def is_sae_commit(p):
	return is_sae(p) and p[Dot11Auth].seqnum == 1

def is_sae_confirm(p):
	return is_sae(p) and p[Dot11Auth].seqnum == 2

def KDF_Length(data, label, context, length):
	iterations = int(math.ceil(length / 256.0))
	result = b""
	for i in range(1, iterations + 1):
		hash_data = struct.pack("<H", i) + str2bytes(label) + context + struct.pack("<H", length)
		result += HMAC256(data, hash_data)
		print("KDF hash data:", hash_data)
	return result


def derive_pwe_ecc(password, addr1, addr2):
	print("Derive PWE: %s, %s, %s" % (password, addr1, addr2))
	addr1 = binascii.unhexlify(addr1.replace(':', ''))
	addr2 = binascii.unhexlify(addr2.replace(':', ''))
	hash_pw = addr1 + addr2 if addr1 > addr2 else addr2 + addr1

	secp256r1_p_data = binascii.unhexlify("%x" % secp256r1_p)
	bits = int(math.ceil(math.log(secp256r1_p, 2)))
	assert bits % 8 == 0

	for counter in range(1, 100):
		hash_data = str2bytes(password) + struct.pack("<B", counter)
		pwd_seed = HMAC256(hash_pw, hash_data)
		log(DEBUG, "PWD-seed: %s" % pwd_seed)
		pwd_value = KDF_Length(pwd_seed, "SAE Hunting and Pecking", secp256r1_p_data, bits)
		log(DEBUG, "PWD-value: %s" % pwd_value)
		pwd_value = int(binascii.hexlify(pwd_value), 16)

		if pwd_value >= secp256r1_p:
			continue
		x = pwd_value

		log(DEBUG, "X-candidate: %x" % x)
		y_sqr = (x**3 + secp256r1_a * x + secp256r1_b) % secp256r1_p
		if legendre_symbol(y_sqr, secp256r1_p) != 1:
			continue

		solutions = list(sqrt_mod_iter(y_sqr, secp256r1_p))
		y_bit = getord(pwd_seed[-1]) & 1
		if solutions[0] & 1 == y_bit:
			return ECC.EccPoint(x, solutions[0])
		else:
			return ECC.EccPoint(x, solutions[1])


# TODO: Use this somewhere???
def calc_k_kck_pmk(pwe, peer_element, peer_scalar, my_rand, my_scalar):
	k = ((pwe * peer_scalar + peer_element) * my_rand).x

	keyseed = HMAC256(b"\x00" * 32, int_to_data(k))
	kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK",
	                         int_to_data((my_scalar + peer_scalar) % secp256r1_r), 512)
	kck = kck_and_pmk[0:32]
	pmk = kck_and_pmk[32:]

	return k, kck, pmk


def calculate_confirm_hash(kck, send_confirm, scalar, element, peer_scalar, peer_element):
	return HMAC256(kck, struct.pack("<H", send_confirm) + int_to_data(scalar) + point_to_data(element)
	                    + int_to_data(peer_scalar) + point_to_data(peer_element))

def build_sae_commit(srcaddr, dstaddr, scalar, element, token=""):
	p = Dot11(addr1=dstaddr, addr2=srcaddr, addr3=dstaddr)
	p = p/Dot11Auth(algo=3, seqnum=1, status=0)

	group_id = 19
	scalar_blob = ("%064x" % scalar).decode("hex")
	element_blob = ("%064x" % element.x).decode("hex") + ("%064x" % element.y).decode("hex")

	return p/Raw(struct.pack("<H", group_id) + token + scalar_blob + element_blob)
	

def build_sae_confirm(srcaddr, dstaddr, send_confirm, confirm):
	p = Dot11(addr1=dstaddr, addr2=srcaddr, addr3=dstaddr)
	p = p/Dot11Auth(algo=3, seqnum=2, status=0)

	return p/Raw(struct.pack("<H", send_confirm) + confirm)	


class SAEHandshake():
	def __init__(self, password, srcaddr, dstaddr):
		self.password = password
		self.srcaddr = srcaddr
		self.dstaddr = dstaddr

		self.pwe = None
		self.rand = None
		self.scalar = None
		self.element = None
		self.kck = None
		self.pmk = None

	def send_commit(self, password):
		self.pwe = derive_pwe_ecc(password, self.dstaddr, self.srcaddr)
		assert point_on_curve(self.pwe)

		# After generation of the PWE, each STA shall generate a secret value, rand, and a temporary secret value,
		# mask, each of which shall be chosen randomly such that 1 < rand < r and 1 < mask < r and (rand + mask)
		# mod r is greater than 1, where r is the (prime) order of the group.
		self.rand = random.randint(0, secp256r1_r - 1)
		mask = random.randint(0, secp256r1_r - 1)

		# commit-scalar = (rand + mask) mod r
		self.scalar = (self.rand + mask) % secp256r1_r
		assert self.scalar > 1

		# COMMIT-ELEMENT = inverse(mask * PWE)
		temp = self.pwe * mask
		self.element = ECC.EccPoint(temp.x, Integer(secp256r1_p) - temp.y)
		assert point_on_curve(self.element)

		auth = build_sae_commit(self.srcaddr, self.dstaddr, self.scalar, self.element)
		sendp(RadioTap()/auth)

	def process_commit(self, p):
		payload = str(p[Dot11Auth].payload)

		group_id = struct.unpack("<H", payload[:2])[0]
		pos = 2

		self.peer_scalar = int(payload[pos:pos+32].encode("hex"), 16)
		pos += 32

		peer_element_x = int(payload[pos:pos+32].encode("hex"), 16)
		peer_element_y = int(payload[pos+32:pos+64].encode("hex"), 16)
		self.peer_element = ECC.EccPoint(peer_element_x, peer_element_y)
		pos += 64

		k = ((self.pwe * self.peer_scalar + self.peer_element) * self.rand).x

		keyseed = HMAC256("\x00"*32, int_to_data(k))
		kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK",
		                         int_to_data((self.scalar + self.peer_scalar) % secp256r1_r), 512)
		self.kck = kck_and_pmk[0:32]
		self.pmk = kck_and_pmk[32:]

		self.send_confirm()

	def send_confirm(self):
		send_confirm = 0
		confirm = calculate_confirm_hash(self.kck, send_confirm, self.scalar, self.element, self.peer_scalar, self.peer_element)

		auth = build_sae_confirm(self.srcaddr, self.dstaddr, send_confirm, confirm)
		sendp(RadioTap()/auth)

	def process_confirm(self, p):
		payload = str(p[Dot11Auth].payload)

		send_confirm = struct.unpack("<H", payload[:2])[0]
		pos = 2

		received_confirm = payload[pos:pos+32]
		pos += 32

		expected_confirm = calculate_confirm_hash(self.kck, send_confirm, self.peer_scalar, self.peer_element, self.scalar, self.element)


# ----------------------- EAP-pwd (TODO Test with Python3) ---------------------------------

def KDF_Length_eappwd(data, label, length):
	# TODO: EAP-pwd uses a different byte ordering for the counter and length?!? WTF!
	iterations = int(math.ceil(length / 256.0))
	result = b""
	for i in range(1, iterations + 1):
		hash_data  = digest if i > 1 else b""
		hash_data += struct.pack(">H", i) + str2bytes(label) + struct.pack(">H", length)
		digest = HMAC256(data, hash_data)
		result += digest
	return result


def derive_pwe_ecc_eappwd(password, peer_id, server_id, token, info=None):
	hash_pw = struct.pack(">I", token) + str2bytes(peer_id + server_id + password)

	secp256r1_p_data = binascii.unhexlify("%x" % secp256r1_p)
	bits = int(math.ceil(math.log(secp256r1_p, 2)))
	assert bits % 8 == 0

	for counter in range(1, 100):
		hash_data = hash_pw + struct.pack("<B", counter)
		pwd_seed = HMAC256(b"\x00", hash_data)
		log(DEBUG, "PWD-Seed: %s" % pwd_seed)
		pwd_value = KDF_Length_eappwd(pwd_seed, "EAP-pwd Hunting And Pecking", bits)
		log(DEBUG, "PWD-Value: %s" % pwd_value)
		pwd_value = int(binascii.hexlify(pwd_value), 16)

		if pwd_value >= secp256r1_p:
			continue
		x = pwd_value

		log(DEBUG, "X-candidate: %x" % x)
		y_sqr = (x**3 + secp256r1_a * x + secp256r1_b) % secp256r1_p
		if legendre_symbol(y_sqr, secp256r1_p) != 1:
			continue

		solutions = list(sqrt_mod_iter(y_sqr, secp256r1_p))
		y_bit = getord(pwd_seed[-1]) & 1
		if solutions[0] & 1 == y_bit:
			if not info is None: info["counter"] = counter
			return ECC.EccPoint(x, solutions[0])
		else:
			if not info is None: info["counter"] = counter
			return ECC.EccPoint(x, solutions[1])


def calculate_confirm_eappwd(k, element1, scalar1, element2, scalar2, group_num=19, rand_func=1, prf=1):
	hash_data  = int_to_data(k)
	hash_data += point_to_data(element1)
	hash_data += int_to_data(scalar1)
	hash_data += point_to_data(element2)
	hash_data += int_to_data(scalar2)
	hash_data += struct.pack(">HBB", group_num, rand_func, prf)
	confirm = HMAC256(b"\x00" * 32, hash_data)
	return confirm


def unit_test_eappwd():
	data = b'yKY2\xdfVP_\x84R\x04d\t\xa9\xac\xc0\xd0\x81\xe7\x01\xaa5\xe0\xd5r\xb6K\xb1g\xe0\xc8\xca'
	label = "EAP-pwd Hunting And Pecking"
	result = KDF_Length_eappwd(data, label, 256)
	assert result == b'\x82\xe7\x92\xd75\xfc\xef\x0e:\xb1\xea\x85E\xe6\rt\x849\xd6\xc3l\xcd\x00\x8e\xde\x94\xe4\xde\xa6q\x91\x1e'

	data = b'\xa8\xd5\x0c\xf47\x9b\xd0\x1d\x89\x1d\x1f\xf4\xa1\xeb\xdd\x9e\x17\x9d\xecm\xd8\xe6A2\x9c\xde$p\x9a\xcb\xd5N'
	result = KDF_Length_eappwd(data, label, 256)
	assert result == b'\xc8r\xfdke\xce\xfa\xbb\x0e\xc3\xb8\x83\xc2\x04\x95\x9fT\xc3P\xa9\x1be\x84\x16\xfba&\xc0!\xfbMs'

	data = b'\x82\x02\x07\xceX\xf5\xbb\x11s\xdc\xe4\xcb\xcc"\xa9\x1f\'\x19\xe0\xee\x84w\xb7\xd6G\xad\xa6w_\xf1\x8eg'
	label = b'4%\xfe\x8e\xd4\x93YD\xb3\xe7\xea\x8coN\xac\xf1 r\x83\x86u\xe1I\xbeS\xa7\x12l\xea\xbdhw\xc7'
	result = KDF_Length_eappwd(data, label, 1024)
	expected  = b's\xdd\xb9\xcf]\x80\x08\xf6\xa08\xf1J L\x8d\xd5\xa9j\x83J\x9d\x04T(\x1a\xbc\x11o\xab\x015\x82V\xd8\xff>J'
	expected += b'\x80P\x1f[PB\xfaF\x13\xae\xef\xfd\xddBkX\xff\xe03\xd3q(\x80\x9f"S\xad\xfeK:\x98\x90\xde\xdfw'
	expected += b'\xd5\xe4\xf0O\xcf\x9c\xa1\r^\xf3\xf6\x1fp_\xd9\x13<\xf7\x0e\xf11\x81\x88\xb9\xfe\x80mn\xed\xf2'
	expected += b'\xdel\x8f8f\\\xd4\x91\x83}|\xd0\x90\xa6I\xac\xca\xdb\x1d4\x00\xf5\xf8\xf5/\xa1'
	assert result == expected

	k = 34571911558658786479991772754682275693090212979118519100150784653967632958583
	e1x = 35056562182093533434520846036041768262744712948121085631797144112066231820275
	e1y = 30178867311470377631935198005507521070028138958470370567962433403317268006022
	e1 = ECC.EccPoint(e1x, e1y)
	s1 = 25673957538626389018921350300691255233489834439459044820849488820063961042178
	e2x = 55846548926525467025361797152934092596912359473099878093027981331310692689958
	e2y = 25540727936496301520339336932631497861346599764823572263118430938562903665071
	e2 = ECC.EccPoint(e2x, e2y)
	s2 = 89671311642711662572527453485728796207545960881415665173397225314404138450610
	confirm = calculate_confirm_eappwd(k, e1, s1, e2, s2)
	assert confirm == b"n\xe1N\xc1\x86\x0f\x94\x85W*Y\xf8\xf2'\x19\xac\x9c\xf6\xe6\xe6\x14\x8c+\xf7\x0e\xd0\xfdF\x87\x03G\xcc"

	pwe = derive_pwe_ecc_eappwd("password", "user", "server", 2903600207)
	assert pwe.x == 65324672961960968584356420288746215288928369435013474055323481826901726558522
	assert pwe.y == 81287605691219879983190651062276165371083848816381214499332721121120114417256

	pwe = derive_pwe_ecc_eappwd("password", "user", "server", 2546484939)
	assert pwe.x == 32774075109236952337158599048510140249162039589740847669274255820096074575478
	assert pwe.y == 65816200486131266053931191249788950977703402544735864608496951271815280382692


# ----------------------- Fuzzing/Testing ---------------------------------

def inject_sae_auth(srcaddr, bssid):
	p = Dot11(addr1=bssid, addr2=srcaddr, addr3=bssid)
	p = p/Dot11Auth(algo=3, seqnum=1, status=0)

	group_id = 19
	scalar = 0
	element_x = 0
	element_y = 0
	p = p/Raw(struct.pack("<H", group_id))

	if False:
		# Convert to octets
		commit_scalar = ("%064x" % scalar).decode("hex")
		commit_element = ("%064x" % element_x).decode("hex") + ("%064x" % element_y).decode("hex")
		p = p / Raw(commit_scalar + commit_element)
	else:
		p = p / Raw(open("/dev/urandom").read(32*3))
	sendp(RadioTap()/p)

def forge_sae_confirm(bssid, stamac):
	kck = "\x00" * 32
	send_confirm = "\x00\x00"
	confirm = HMAC256(kck, send_confirm + int_to_data(0) + zeropoint_to_data()
	                       + int_to_data(0) + zeropoint_to_data())

	auth = Dot11(addr1=bssid, addr2=stamac, addr3=bssid)
	auth = auth/Dot11Auth(algo=3, seqnum=2, status=0)
	auth = auth/Raw(struct.pack("<H", 0) + confirm)

	sendp(RadioTap()/auth)

