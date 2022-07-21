import idc
import aplib

# Researched and created by https://github.com/lldre together with Northwave
# Blog describing the config structure can be found on the Northwave blog

# We could generate this using the idapython api
PDATA_ADDR = 0x428000

# The first 2 dwords of the config define the
# initial state for the key generation algorithm
# * STATIC1 and STATIC2 will remain the same
# * STATE1 and STATE2 will get updated each loop
STATIC1 = idc.get_wide_dword(PDATA_ADDR)
STATIC2 = idc.get_wide_dword(PDATA_ADDR+4)
STATE1 	= STATIC1
STATE2 	= STATIC2

# 4 static immediates that might vary
# between samples. These were taken from the function
# sub_4017C8 jumps to. This function isn't visible
# during static analysis, so please use a debugger
VAR1 = 0x5851F42D
VAR2 = 0x4C957f2D
VAR3 = 0xF767814F
VAR4 = 0x14057b7E

# The key stream
key_stream = bytearray()


# Implementation of function 0x408C9C
# this function generates 2 dwords that function as
# a xor key to decrypt the config
def update():
	global STATE1, STATE2

	tmp_eax, tmp_edx = algo(VAR1, VAR2, STATE1, STATE2)

	tmp_eax = (tmp_eax + VAR3)
	tmp_edx = (tmp_edx + VAR4)

	if (tmp_eax&0xFFFFFFFF00000000) > 0:
		tmp_edx += 1

	STATE1 = tmp_eax & 0xFFFFFFFF
	STATE2 = tmp_edx & 0xFFFFFFFF


	return algo(STATE2, STATE1, STATIC1, STATIC2)

def algo(v1, v2, k1, k2):
	
	if (v1 | k2) == 0:
		tmp = k1 * v2
		return (tmp & 0xFFFFFFFF), ((tmp >> 32) & 0xFFFFFFFF)

	else:
		tmp = k2 * v2
		tmp_eax = (tmp & 0xFFFFFFFF)
		tmp_edx = (tmp >> 32) & 0xFFFFFFFF
		tmp = k1 * v1
		tmp_eax += (tmp & 0xFFFFFFFF)
		tmp = k1 * v2
		return (tmp & 0xFFFFFFFF), (((tmp >> 32) + tmp_eax) & 0xFFFFFFFF)


# Because, for a given initial state, the resulting
# dwords are always the same, we can generate a key
# stream once and use it for every entry in the config.
# One thing we have to do when generating the keystream
# is reordering the bytes
# 
# n = length of desired key stream given in bytes
def create_key_stream(n):
	i = (n / 8) + (1 if ((n%8) > 0) else 0)
	while (i > 0):
		x, y = update()
		key_stream.append((x & 0x00FF	) >> 0)
		key_stream.append((y & 0xFF00	) >> 8)
		key_stream.append((x & 0xFF00	) >> 8)
		key_stream.append((y & 0x00FF	) >> 0)
		key_stream.append((x & 0x00FF0000) >> 16)
		key_stream.append((y & 0xFF000000) >> 24)
		key_stream.append((x & 0xFF000000) >> 24)
		key_stream.append((y & 0x00FF0000) >> 16)

		i -= 1


# Call this on any data section or pdata section
# encrypted blob that needs decrypting AND decompression.
def decrypt_member_aplib(start):
	b 		= bytearray()
	sz 		= idc.get_wide_dword(start - 4)

	for i in range(sz):
		b.append(idc.get_bytes(start + i, 1)[0] ^ key_stream[i])

	return aplib.decompress(b)


# Call this on any data section or pdata section
# encrypted blob that ONLY needs decrypting
def decrypt_member(start):
	b 		= bytearray()
	sz 		= idc.get_wide_dword(start - 4)


	for i in range(sz):
		b.append(idc.get_bytes(start + i, 1)[0] ^ key_stream[i])

	return b


# Sneaky little init
create_key_stream(0x10000)
