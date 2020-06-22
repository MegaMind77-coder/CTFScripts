#!/usr/bin/python
## OTP - Recovering the private key from a set of messages that were encrypted w/ the same private key (Many time pad attack) - crypto100-many_time_secret @ alexctf 2017
# @author intrd - http://dann.com.br/ 
# Original code by jwomers: https://github.com/Jwomers/many-time-pad-attack/blob/master/attack.py)

import string
import collections
import sets, sys

# 11 unknown ciphertexts (in hex format), all encrpyted with the same key
c1 = "0707491c4e0c53440616490f47470116001111411354150c520e061100000800414c0f01120606454d13"
c2 = "1c0d4900411e53540f0e1d4e1348114f530706520454501c1d41070d454f134e491a001c1411481d1406"
c3 = "00000c1d00011600140e1e4e0f45530b0005005441441148140d1202000008004409061c1e041c495b5c"
c4 = "151b490a4f1c534b09001e42474d150b4e071653414903481e0818000008144156051117495a4641585e"
c5 = "1d481c00450d5354084f1d060e4e1f4f540a0454414d09481e08150000180753000d451a15150f45504b"
c6 = "1911491e4f1d1b45154f080210410d1c0016004c0d5350051741070a001c0b494c09450f091048504146"
c7 = "1d481d1b4f1c1448134f001a4757151c00050a490f47501c1d41110a540703520001004247161d54145b"
c8 = "03000c1d00101c55470d1b070947540245420a55150c500b130f531c4f1a46494e18170103010b45145f"
c9 = "03000807000d1c001e001c4e0045004f570a004e41591f1d5202010a531c4641000100001315044c4d12"
c10 = "00000c5357060153134f190f1554540046420d4117491e0f52005308450112414c4c0c020b1a0d534712"
c11 = "111e0c01590b1c441e4f001d47410309550e45540945030d5205121c5341466954e281b5164e021a0755535a"
c12 = "12071b534d1053570f00050b474c1d09454e45694144190c1ce281b807454b0109570005034e2e540d56515c"
c13 = "1c091f1600101c55471c0c0b090003074116454915e280b903481e0818000000135400180d0b151144007947"

ciphers = [c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11]
# The target ciphertext we want to crack
target_cipher = "2e0d0700452a27661c5f1d1e38101a5e593d554e02130d"

# XORs two string
def strxor(a, b):     # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])

# To store the final key
final_key = [None]*150
# To store the positions we know are broken
known_key_positions = set()

# For each ciphertext
for current_index, ciphertext in enumerate(ciphers):
	counter = collections.Counter()
	# for each other ciphertext
	for index, ciphertext2 in enumerate(ciphers):
		if current_index != index: # don't xor a ciphertext with itself
			for indexOfChar, char in enumerate(strxor(ciphertext.decode('hex'), ciphertext2.decode('hex'))): # Xor the two ciphertexts
				# If a character in the xored result is a alphanumeric character, it means there was probably a space character in one of the plaintexts (we don't know which one)
				if char in string.printable and char.isalpha(): counter[indexOfChar] += 1 # Increment the counter at this index
	knownSpaceIndexes = []

	# Loop through all positions where a space character was possible in the current_index cipher
	for ind, val in counter.items():
		# If a space was found at least 7 times at this index out of the 9 possible XORS, then the space character was likely from the current_index cipher!
		if val >= 7: knownSpaceIndexes.append(ind)
	#print knownSpaceIndexes # Shows all the positions where we now know the key!

	# Now Xor the current_index with spaces, and at the knownSpaceIndexes positions we get the key back!
	xor_with_spaces = strxor(ciphertext.decode('hex'),' '*150)
	for index in knownSpaceIndexes:
		# Store the key's value at the correct position
		final_key[index] = xor_with_spaces[index].encode('hex')
		# Record that we known the key at this position
		known_key_positions.add(index)

# Construct a hex key from the currently known key, adding in '00' hex chars where we do not know (to make a complete hex string)
final_key_hex = ''.join([val if val is not None else '00' for val in final_key])
# Xor the currently known key with the target cipher
output = strxor(target_cipher.decode('hex'),final_key_hex.decode('hex'))

print "Fix this sentence:"
print ''.join([char if index in known_key_positions else '*' for index, char in enumerate(output)])+"\n"

# WAIT.. MANUAL STEP HERE 
# This output are printing a * if that character is not known yet
# fix the missing characters like this: "Let*M**k*ow if *o{*a" = "cure, Let Me know if you a"
# if is too hard, change the target_cipher to another one and try again
# and we have our key to fix the entire text!

#sys.exit(0) #comment and continue if u got a good key

target_plaintext = "zenseCTF{0tp_0n1y_0nc3}"
print "Fixed:"
print target_plaintext+"\n"

key = strxor(target_cipher.decode('hex'),target_plaintext)

print "Decrypted msg:"
for cipher in ciphers:
	print strxor(cipher.decode('hex'),key)

print "\nPrivate key recovered: "+key+"\n"
