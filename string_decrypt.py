import idaapi
import idautils
import idc

# Script for decrypting all normal strings in the Lockbit 3.0 binary
# Written by https://github.com/lldre together with Northwave

# This script finds all references to the string decrypt function and
# harvests the encrypted dwords that are pushed before it. It then decrypts
# Them using the dword listed inside of the string decrypt function. You
# might have to change this value for each new binary. The key is the not
# inverted version of the key in the actual binary.

FUNC = 0x401260
KEY  = 0xbaf92035

def harvest_dword_loads(addr):
	ret = []
	state = 0
	insn = ida_ua.insn_t()

	# max lookback of 100
	for i in range(100):
		ida_ua.decode_insn(insn, addr)

		if (insn.itype == idaapi.NN_mov) and (insn.Op2.type == o_imm):
			ret.append(insn.Op2.value & 0xFFFFFFFF)
			state = 1

		elif state == 1:
			break

		addr = prev_head(addr)

	return reversed(ret)

def decrypt(lst):
	string = ""
	for dw in lst:
		dw ^= KEY
		chars = [(dw & 0xFF), ((dw & 0xFF00) >> 8), ((dw & 0xFF0000) >> 16), ((dw & 0xFF000000) >> 24)]

		for c in chars:
			if c:
				string += chr(c)
	return string


for ea in idautils.CodeRefsTo(FUNC, 0):
	l = harvest_dword_loads(ea)
	s = decrypt(l)
	print("%X: %s"%(ea, s))
