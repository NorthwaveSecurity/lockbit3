import sys

START = 0x427408
END   = 0x427888
DEBUG = False


# x64dbg script for resolving APIs in lockbit 3.0
# Created by https://github.com/lldre together with Northwave
# 
# 
# Quick description:
#
# The first function call after the unpacker function appears to be creating a custom import table
# Each of the unk_XXXXXX offsets are actually the starts of arrays of dwords. These dwords 
# are all pointers to dynamically created stub functions that resolve the actual addresses 
# of APIs. As they're all dynamically created, there's no easy way for us to script the 
# resolving of these pointers in ida. Instead, we need to script it using the debugger.
#
# Usage:
#
# Break at the end of the import address table creation function. Run using the
# x64dbg python plugin.
# START gives the start of the IAT in memory
# END gives the end
# For each of dwords between these 2 addresses, it will check if it's a pointer
# to a thunk and if it is it will eventually execute it and get the API name from it.


def log(s):
    if DEBUG:
        print s

def execute_n(n):
	for i in range(n):
		pluginsdk.StepIn()

# For a given offset in the dynamically resolved IAT,
# read out the ptr, determine its size, execute it and
# finally read out and return the api ptr and name
def resolve_api(addr):
	
	end 		= 0
	n 			= 0
	label 		= ""
	x = pluginsdk.ReadDword(addr)

	log(" - - Resolving api for addr: %x"%x)

	ins 	= pluginsdk.x64dbg.DISASM_INSTR()
	pluginsdk.x64dbg.DbgDisasmAt(x, ins)

	cur_addr 	= x

	# Peek up to 6 instructions
	for i in range(6):
		if ins.instruction[:3] == "jmp":
			n 	= i
			end = cur_addr

		cur_addr += ins.instr_size
		pluginsdk.x64dbg.DbgDisasmAt(cur_addr, ins)

	if end == 0:
		return end

	log(" - - Found jmp instruction at %X for function %X"%(end, x))

	log(" - - Executing %d instructions starting from %X"%(n, x))
	pluginsdk.SetEIP(x)
	execute_n(n)

	eax = pluginsdk.GetEAX()
	pluginsdk.x64dbg.DbgGetLabelAt(eax, 0, label)
	log(" - - Found eax: %X"%eax)
	log(label)

	return label


# start gives the start of the array. this is the 1st arg to the api_lookup func
# eg. push    offset unk_427694
# amount gives the amount of dwords to check in this array
def harvest_addrs(start, amount):
	log(" - - Starting the harvest of %d dwords in array %X"%(amount, start))

	addrs 	= []
	count   = 0
	ins 	= pluginsdk.x64dbg.DISASM_INSTR()

	for i in range(amount):
		x = pluginsdk.ReadDword(start + (i * 4))
		pluginsdk.x64dbg.DbgDisasmAt(x, ins)
		if pluginsdk.IsValidPtr(x) and (ins.instruction[:3] == "mov"):
			log(" - - Found valid thunk ptr: %X"%x)
			addrs.append(start + (i * 4))
			count += 1

	return addrs, count



arr, n = harvest_addrs(START, (END-START) / 4)

for i in range(n):
	log("%X"%arr[i])

for i in range(n):
	api = resolve_api(arr[i])

	if api == 0:
		continue

	sys.stdout.write("%X : "%arr[i])
	print(api)

