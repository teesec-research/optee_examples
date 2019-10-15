# OP-TEE Sample Applications
This git contains source code for sample host and Trusted Application that can
be used directly in the OP-TEE project.

All official OP-TEE documentation has moved to http://optee.readthedocs.io. The
information that used to be here in this git can be found under
[optee_examples].

// OP-TEE core maintainers

[optee_examples]: https://optee.readthedocs.io/building/gits/optee_examples/optee_examples.html

## New Examples:
### dumpmem
Allows extraction of RAM contents as seen from the TA.
Call it via readmem <starting address> <length>
### runmem
Demonstrates from where memory can be executed. Call with any number to be incremented by 1337, if it doesn't crash.
### vuln
Demonstrates Type Confusion and Buffer Overflow vulnerabilities.
#### TA
The TA contains some extra code at the end as well as references to libraries to cause GCC to link additional code which could be present and contain additional ROP gadgets.

Symbols:
- SECRET: a secret string, which might have been decrypted at runtime instead.
- remember_id: an id string, which identifies the data object within secure storage.
- call_strdup: Duplicates a session name into the heap.
- call_remember: Saves a passphrase to secure storage
- call_check{,2}: Verifies a passphrase against secure storage, and releases a secret from RAM.
- call_fibufnacci: Vulnerable to type confusion and buffer overflow, can be used to extract the passphrase or the secret.
#### REE
- rop{1,2}.h: Contains ROP chains, is included in an array definition within main.c
- tee_api_defines.h: Headers copied to allow printing human-readable error messages.
- main.c: Uses intended functionality and executes exploits. Symbols:
    - reg_pair_to_64/reg_pair_from_64: helper functions copied from OP-TEE for parameter construction
    - handler: handler for segfaults within the REE application to simplify debugging, installed in main()
    - report_return/check_return: prints error messages from the libteec framework, the TEE, and the TA.
    - invoke: ordinarily uses the fibufnacci functionality as intended, also setting a session name before.
    - remember/check: ordinarily uses the passphrase storage and verification feature.
    - hack_typeconfusion: exploits the type confusion
    - hack_rop: exploits the heap buffer overflow to print log messages with a ROP chain. Will print the SECRET to the serial console.
    - hack_rop2: exploits the heap buffer overflow to gain code execution with a ROP chain. Will print the SECRET and the stored value to the serial console. Contains the necessary Python code to assemble the shellcode -- please don't use pwntools from the Debian packages, importing them will fail due to syntax errors. 
### heap
Demonstates Double-Free vulnerability. Only works with a libutee/libutils compiled with NDEBUG!
