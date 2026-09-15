
the following repo contains several PoCs, created during the research, analysis and development. you might find duplication and unused code blocks but the idea is clear enough if you want to use WerEnc technique.

werenc_probe.c -> API signature probing. 

Compilation: 
x86_64-w64-mingw32-gcc -O2 -o werenc_probe.exe werenc_probe.c -ladvapi32 

Usage:
 *   werenc_probe.exe                     (probe with synthetic MDMP test data)
 *   werenc_probe.exe <input_file>        (encrypt a specific file)


werenc_byok.c -> PoC to generate keys, scan, patch the RSA keys in memory, encrypt, decrypt and insert IAT hooks to capture every key, IV and buffer WerEnc passes into BCrypt during encryption revealing 
the structure-block key and content IV. 

Compilation: 
 x86_64-w64-mingw32-gcc -O2 -o werenc_byok.exe werenc_byok.c -ladvapi32 -lbcrypt -lcrypt32 -municode

Usage: 
 *   werenc_byok.exe --generate-keys          Generate RSA-4096 key pair
 *   werenc_byok.exe --encrypt <input.file>    Encrypt with BYOK
 *   werenc_byok.exe --decrypt <input.enc>    Decrypt with private key
 *   werenc_byok.exe --decrypt <in> <out> <iv-hex> ...with captured content IV
 *   werenc_byok.exe --capture <input.file>    Encrypt + log BCrypt keys/IVs
 *   werenc_byok.exe --scan-dll               Scan WerEnc.dll for RSA blobs



