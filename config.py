import base64
from lb3_crypto import *

# Researched and created by https://github.com/lldre together with Northwave
# A description of the config structure can be found on the Northwave blog

FLAGS = ["LB3_ENCRYPT_ANY_BIG_FILE", "LB3_RANDOMISE_FILENAME", "LB3_AUTHENTICATE_USING_CREDS", "LB3_SKIP_HIDDEN_FILES", "LB3_LANGUAGE_CHECK", "LB3_ENCRYPT_MICROSOFT_EXCHANGE", "LB3_ENCRYPT_NETWORK_SHARES", "LB3_KILL_PROCESSES", "LB3_KILL_SERVICES", "LB3_CREATE_MUTEX", "LB3_PRINT_SIMPLIFIED_RANSOMNOTE", "LB3_SET_BACKGROUND", "LB3_REGISTER_ICON", "LB3_ENABLE_C2_LOGGING", "LB3_SELF_DESTRUCT", "LB3_ATTEMPT_UAC_BYPASS", "LB3_SELF_DESTRUCT_2", "LB3_RESTART_PROCESS_WITH_PSEX_FLAG", "LB3_RESTART_PROCESS_WITH_GSPD_FLAG", "LB3_UNKNOWN", "LB3_SELF_DESTRUCT_3", "LB3_CLEAR_EVENT_LOGS", "LB3_PROPAGATE_THROUGH_NETWORK", "LB3_RESERVED"]

def pretty_print_config(strings, rsakey, company_id, flags):
	print("#####################################\n#########Lockbit 3.0 config##########\n#####################################\n\n~~~~~~~~~~~* VARIABLES *~~~~~~~~~~~~~\nRSA-1024 KEY:\n%s\n\nCOMPANY ID:\n%s\n\n\n~~~~~~~~~~~~~* FLAGS *~~~~~~~~~~~~~~~\n%s\n\n\n~~~~~~~~~~~~* STRINGS *~~~~~~~~~~~~~~\n%s\n\
		"%(rsakey, company_id, flags, strings))

def format_utf_ascii(s):
	ss = ""

	for i in range(0, len(s), 2):
		c = s[i]
		if c == 0x00:
			ss += " "
		else:
			ss += chr(c)

	return ss


# Check if string is utf8 or ascii then print
def print_wrapper(s):
	ret = ""
	if (s[1] == 0x00) and (s[3] == 0x00):
		ret = format_utf_ascii(s)
	else:
		ret = s

	return ret


# Print raw bytes as hex
def print_bytes(bt, off,  n):
	for i in range(n):
		sys.stdout.write("%02X "%bt[off + i])

	print("")


# Get a little endian dword from a bytearray
def dword_from_bytes(bt, off):
	return (bt[off+3] << 24) | (bt[off+2] << 16) | (bt[off+1] << 8) | (bt[off+0] << 0)


# Decode the b64 block
def base64_decode_all(bt, off):

	ret = ""
	x = dword_from_bytes(bt, off + 0)
	if x != 0:
		ret += "Folder Exclusion Hashes:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)
		for i in range(len(d) // 4):
			ret = ret + hex(dword_from_bytes(d, i * 4)) + " "

		ret += "\n\n"


	x = dword_from_bytes(bt, off + 4)
	if x != 0:
		ret += "File Exclusion Hashes:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)
		for i in range(len(d) // 4):
			ret = ret + hex(dword_from_bytes(d, i * 4)) + " "

		ret += "\n\n"


	x = dword_from_bytes(bt, off + 8)
	if x != 0:
		ret += "File Extension Exclusion Hashes:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)
		for i in range(len(d) // 4):
			ret = ret + hex(dword_from_bytes(d, i * 4)) + " "

		ret += "\n\n"

	x = dword_from_bytes(bt, off + 0xC)
	if x != 0:
		ret += "Computername Exclusion Hashes:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)
		for i in range(len(d) // 4):
			ret = ret + hex(dword_from_bytes(d, i * 4)) + " "

		ret += "\n\n"

	
	x = dword_from_bytes(bt, off + 0x14)
	if x != 0:
		ret += "Software to terminate:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)
		ret += print_wrapper(d)

		ret += "\n\n"


	x = dword_from_bytes(bt, off + 0x18)
	if x != 0:
		ret += "Services to remove:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)
		ret += print_wrapper(d)

		ret += "\n\n"

	x = dword_from_bytes(bt, off + 0x20)
	if x != 0:
		ret += "Credentials:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)

		t = bytearray()
		for i in range(len(d)):
			t.append(d[i] ^ key_stream[i])

		ret += print_wrapper(t)

		ret += "\n\n"

	x = dword_from_bytes(bt, off + 0x24)
	if x != 0:
		ret += "Ransomnote:\n"

		y = 0
		while (bt[off + x + y] != 0x00):
			y += 1

		d = base64_decode(bt, off + x, y)

		t = bytearray()
		for i in range(len(d)):
			t.append(d[i] ^ key_stream[i])

		ret += t.decode()

		ret += "\n\n"

	return ret


def base64_decode(bt, off, n):
	enc = ""
	for i in range(n):
		enc += chr(bt[off + i])

	return base64.b64decode(enc)


CONFIG_START = 0x42800c

# Function for decrypting the config
def pdata_config():
	bb = decrypt_member_aplib(CONFIG_START)

	rsakey = ""
	for i in range(0x80):
		rsakey += "%X"%bb[i]

	company_id = ""
	for i in range(0x10):
		company_id += "%X"%bb[i+0x80]


	f = ""
	for i in range(24):
		if bb[0xA0 + i] == 1:
			f = f + FLAGS[i] + "\n"

	s = base64_decode_all(bb, 0xb8)
	
	pretty_print_config(s, rsakey, company_id, f)
