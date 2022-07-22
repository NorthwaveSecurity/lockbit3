This repo contains a few scripts that were used in the analysis of Lockbit 3.0.
A full description of the config and what it looks like can be found on our blog here: https://northwave-security.com/lockbit3-0/

**string_decrypt.py**: Setting the `FUNC` variable to the string decryption routine's address will let you decrypt around 95% of the strings.

**api_resolve.py**: This is an x64dbg python script to be used with the x64dbg python extension. After unpacking, lockbit initializes its own custom IAT. But, rather than using direct pointers to APIs, it uses small thunk functions that "decrypt" the pointer to the API. These pointers to thunk functions are all located sequentially in the data segment. After lockbit has initialized all of the thunk functions, you can use this script to execute all the thunks and get the API names belonging to them. Set the START and END variables to the start and end of the custom IAT.

**hash.py**: Lockbit implements a custom hashing algorithm to match the hashes of strings to hardcoded hashes. This script implements the hashing algorithm so you can pass your own strings into it and see what hash comes out. Technically the hashing algorithm also accepts a 2nd parameter to alter the hashing algorithm, but in reality this is always 0.

**config.py**: A script for decrypting the config in a lockbit sample. Set the CONFIG_START variable to the start of the config, after its size. This script depends on the lb3_crypto.py module.

**lb3_crypto.py**: This module implements the decryption algorithm for the config and many other values stored in the data segment. You can call `decrypt_member_aplib()` on any encrypted blob that needs decrypting AND aplib decompression. Call `decrypt_member()` on values that only need decryption. When using this on a new sample, there is a good chance the global variables will be different and have to be extracted from the decryption function. These variables are VAR1-VAR4 and they are immediate values pushed inside of the decryption function.