
# Quick implementation of lockbit 3.0's hashing algorithm
# it uses this to compare string hashes to a list of hashes
# in the config among other things.

# You could load in your own wordlist and compare the hashes
# against the hashes listed in the config to figure out what
# each hash means.

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


def some_hash(str, val):
	x = val
	s = str.lower()
	for i in range(len(s)):
		c = s[i]
		x = ror(x, 13, 32)
		x = (x + ord(c)) & 0xFFFFFFFF

	x = ror(x, 13, 32)
	x = (x + 0) & 0xFFFFFFFF

	return x
