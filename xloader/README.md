# Xloader IDA Decryption Tool for Encrypted Code

**Xloader** (previously Formbook) utilizes numerous encryption layers to [obfuscate critical sections of the stealer's code and data](https://www.zscaler.com/blogs/security-research/technical-analysis-xloaders-code-obfuscation-version-43). 

ThreatLabz has created an IDA Python script to remove Xloader's encryption layers for recent samples including the latest version 4.3. Once executed, the script will search for encrypted functions and will attempt to decrypt them, overwriting encrypted data with the original code in the disassembly.

# Example (Packed) Xloader Samples

|Family  |Version |SHA256                                                          |
|--------|--------|----------------------------------------------------------------|
|Xloader |4.3     |9e1b4f2d408e187ca641c0c16269069d0acabe5ae15514418726fbc720b33731|
|Xloader |4.3     |f55ce0741ed4615bae5646c644b3a971323ac344b12693495d5749c688d5d489|
|Xloader |4.3     |3bd86f3906f59f627bf65664d2bfacf37a29dbaafeae601baf5eeb544396f26c|
