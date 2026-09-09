key = [
 198, 163, 113, 153, 204, 79, 133, 227, 8, 76, 110, 256, 13, 227, 
 150, 39, 33, 128, 7, 85, 144, 64, 212, 84, 113, 154, 217, 162, 190, 
 18, 248, 20, 67, 30, 2, 140, 119, 213, 38, 99, 204, 137, 48, 121, 
 66, 12, 177, 194, 86]

enc_flag = [
 181, 213, 5, 226, 191, 124, 230, 150, 122, 37, 89, 377, 82, 212, 
 254, 85, 17, 245, 96, 61, 207, 112, 182, 50, 4, 233, 186, 215, 204, 
 107, 207, 109, 28, 47, 113, 211, 25, 229, 17, 60, 249, 236, 83, 
 12, 48, 101, 134, 187, 43]

# XOR decryption
flag = "".join([chr(f ^ k) for f, k in zip(enc_flag, key)])
print(f"The Flag is: {flag}")

#1. Identification
#The binary was initially analyzed in GDB, revealing zlib inflation
# and dynamic loading symbols. Combined with the pydata string found 
# via strings, this confirmed the executable was a PyInstaller bundle.

#2. Extraction
#Using pyinstxtractor, the ELF binary was unpacked to retrieve the embedded 
#data archive. This yielded chall.pyc (the compiled Python 3.7 bytecode) 
#and the necessary runtime environment.

#3. Decompilation
#The bytecode was translated back into readable Python source code using 
#uncompyle6. While the main() function was a decoy, the actual flag data 
#was discovered hidden in two global arrays: key and enc_flag.

#4. Decryption
#A simple Python script was used to perform a Bitwise XOR operation 
#between the two arrays. This reversed the obfuscation and revealed the 
#final flag: svt{s3curi7y_7hr0ugh_0bfuscury7y_1s_n07_5ecuri7y}.