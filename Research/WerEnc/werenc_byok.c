/*
 * werenc_byok.c — WerEnc.dll BYOK (Bring Your Own Key) Encryption
 *
 * Compile (MinGW cross):
 *   x86_64-w64-mingw32-gcc -O2 -o werenc_byok.exe werenc_byok.c \
 *       -ladvapi32 -lbcrypt -lcrypt32 -municode
 *
 * Usage:
 *   werenc_byok.exe --generate-keys          Generate RSA-4096 key pair
 *   werenc_byok.exe --encrypt <input.dmp>    Encrypt with BYOK
 *   werenc_byok.exe --decrypt <input.enc>    Decrypt with private key
 *   werenc_byok.exe --decrypt <in> <out> <iv-hex>
 *                                            ...with captured content IV
 *   werenc_byok.exe --capture <input.dmp>    Encrypt + log BCrypt keys/IVs
 *   werenc_byok.exe --scan-dll               Scan WerEnc.dll for RSA blobs
 *
 * Author: @zux0x3a 0xsp research
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>


typedef struct {
    LPVOID lpBaseOfDll;
    DWORD  SizeOfImage;
    LPVOID EntryPoint;
} MY_MODULEINFO;


typedef struct {
    ULONG Magic;
    ULONG BitLength;
    ULONG cbPublicExp;
    ULONG cbModulus;
    ULONG cbPrime1;
    ULONG cbPrime2;
} MY_BCRYPT_RSAKEY_BLOB;

#define MY_BCRYPT_RSAPUBLIC_MAGIC   0x31415352  /* 'RSA1' */
#define MY_BCRYPT_RSAPRIVATE_MAGIC  0x32415352  /* 'RSA2' */
#define MY_BCRYPT_RSAFULLPRIVATE_MAGIC 0x33415352 /* 'RSA3' */


#define MY_BCRYPT_PAD_NONE   0x00000001
#define MY_BCRYPT_PAD_OAEP   0x00000002
#define MY_BCRYPT_PAD_PKCS1  0x00000004


typedef struct {
    LPCWSTR pszAlgId;
    BYTE   *pbLabel;
    ULONG   cbLabel;
} MY_BCRYPT_OAEP_PADDING_INFO;


typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *pfn_BCryptOpenAlgorithmProvider)(
    void **phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImpl, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptGenerateKeyPair)(
    void *hAlgorithm, void **phKey, ULONG dwLength, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptFinalizeKeyPair)(
    void *hKey, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptExportKey)(
    void *hKey, void *hExportKey, LPCWSTR pszBlobType,
    BYTE *pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptImportKeyPair)(
    void *hAlgorithm, void *hImportKey, LPCWSTR pszBlobType,
    void **phKey, BYTE *pbInput, ULONG cbInput, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptDecrypt)(
    void *hKey, BYTE *pbInput, ULONG cbInput, void *pPaddingInfo,
    BYTE *pbIV, ULONG cbIV, BYTE *pbOutput, ULONG cbOutput,
    ULONG *pcbResult, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptEncrypt)(
    void *hKey, BYTE *pbInput, ULONG cbInput, void *pPaddingInfo,
    BYTE *pbIV, ULONG cbIV, BYTE *pbOutput, ULONG cbOutput,
    ULONG *pcbResult, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptGenerateSymmetricKey)(
    void *hAlgorithm, void **phKey, BYTE *pbKeyObject, ULONG cbKeyObject,
    BYTE *pbSecret, ULONG cbSecret, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptSetProperty)(
    void *hObject, LPCWSTR pszProperty, BYTE *pbInput, ULONG cbInput,
    ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptGenRandom)(
    void *hAlgorithm, BYTE *pbBuffer, ULONG cbBuffer, ULONG dwFlags);
typedef NTSTATUS (WINAPI *pfn_BCryptDestroyKey)(void *hKey);
typedef NTSTATUS (WINAPI *pfn_BCryptCloseAlgorithmProvider)(
    void *hAlgorithm, ULONG dwFlags);


typedef HRESULT (WINAPI *pfn_EncryptDumpFile_PP)(LPCWSTR, LPCWSTR);
typedef HRESULT (WINAPI *pfn_EncryptDumpFile_HH)(HANDLE, HANDLE);


#define PUBKEY_FILE   L"werenc_pub.key"
#define PRIVKEY_FILE  L"werenc_priv.key"
#define AES_KEY_FILE  L"werenc_aes.key"

static void hexdump(const BYTE *buf, size_t len, size_t max)
{
    size_t show = (len < max) ? len : max;
    for (size_t i = 0; i < show; i++) {
        if (i && (i % 16 == 0)) printf("\n  ");
        printf("%02X ", buf[i]);
    }
    if (show < len) printf("... (+%zu bytes)", len - show);
    printf("\n");
}



static int writeKeyFile(const wchar_t *path, const BYTE *data, DWORD len)
{
    HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD w;
    WriteFile(hf, data, len, &w, NULL);
    CloseHandle(hf);
    return (w == len);
}

static BYTE *readKeyFile(const wchar_t *path, DWORD *outLen)
{
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) { *outLen = 0; return NULL; }
    DWORD sz = GetFileSize(hf, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) { CloseHandle(hf); *outLen = 0; return NULL; }
    BYTE *buf = (BYTE *)malloc(sz);
    DWORD rd;
    ReadFile(hf, buf, sz, &rd, NULL);
    CloseHandle(hf);
    *outLen = rd;
    return buf;
}

static int GenerateKeyPair(void)
{
    printf("[*] generating RSA-4096 key pair for BYOK...\n");
 
    HMODULE hBCrypt = LoadLibraryW(L"bcrypt.dll");
    if (!hBCrypt) { printf("[!] cannot load bcrypt.dll\n"); return 1; }

    pfn_BCryptOpenAlgorithmProvider pOpen =
        (pfn_BCryptOpenAlgorithmProvider)GetProcAddress(hBCrypt, "BCryptOpenAlgorithmProvider");
    pfn_BCryptGenerateKeyPair pGen =
        (pfn_BCryptGenerateKeyPair)GetProcAddress(hBCrypt, "BCryptGenerateKeyPair");
    pfn_BCryptFinalizeKeyPair pFinal =
        (pfn_BCryptFinalizeKeyPair)GetProcAddress(hBCrypt, "BCryptFinalizeKeyPair");
    pfn_BCryptExportKey pExport =
        (pfn_BCryptExportKey)GetProcAddress(hBCrypt, "BCryptExportKey");
    pfn_BCryptDestroyKey pDestroy =
        (pfn_BCryptDestroyKey)GetProcAddress(hBCrypt, "BCryptDestroyKey");
    pfn_BCryptCloseAlgorithmProvider pClose =
        (pfn_BCryptCloseAlgorithmProvider)GetProcAddress(hBCrypt, "BCryptCloseAlgorithmProvider");

    if (!pOpen || !pGen || !pFinal || !pExport || !pDestroy || !pClose) {
        printf("[!] Error, missing BCrypt exports\n");
        return 1;
    }

    void *hAlg = NULL;
    NTSTATUS st = pOpen(&hAlg, L"RSA", NULL, 0);
    if (st != 0) { printf("[!] BCryptOpenAlgorithmProvider: 0x%08lX\n", (unsigned long)st); return 1; }

    void *hKey = NULL;
    st = pGen(hAlg, &hKey, 4096, 0);
    if (st != 0) { printf("[!] BCryptGenerateKeyPair: 0x%08lX\n", (unsigned long)st); return 1; }

    st = pFinal(hKey, 0);
    if (st != 0) { printf("[!] BCryptFinalizeKeyPair: 0x%08lX\n", (unsigned long)st); return 1; }

    //  Export public key 
    ULONG pubLen = 0;
    pExport(hKey, NULL, L"RSAPUBLICBLOB", NULL, 0, &pubLen, 0);
    BYTE *pubBlob = (BYTE *)malloc(pubLen);
    st = pExport(hKey, NULL, L"RSAPUBLICBLOB", pubBlob, pubLen, &pubLen, 0);
    if (st != 0) { printf("[!] export public: 0x%08lX\n", (unsigned long)st); return 1; }

    MY_BCRYPT_RSAKEY_BLOB *pubHdr = (MY_BCRYPT_RSAKEY_BLOB *)pubBlob;
    printf("[+] public key exported (%lu bytes)\n", (unsigned long)pubLen);
    printf("    magic: 0x%08lX (RSA1=0x%08X)\n",
           (unsigned long)pubHdr->Magic, MY_BCRYPT_RSAPUBLIC_MAGIC);
    printf("    bits:  %lu\n", (unsigned long)pubHdr->BitLength);
    printf("    exp:   %lu bytes, mod: %lu bytes\n",
           (unsigned long)pubHdr->cbPublicExp, (unsigned long)pubHdr->cbModulus);

    writeKeyFile(PUBKEY_FILE, pubBlob, pubLen);
    wprintf(L"    saved: %s\n\n", PUBKEY_FILE);

   // exporting the private key
    ULONG privLen = 0;
    pExport(hKey, NULL, L"RSAFULLPRIVATEBLOB", NULL, 0, &privLen, 0);
    BYTE *privBlob = (BYTE *)malloc(privLen);
    st = pExport(hKey, NULL, L"RSAFULLPRIVATEBLOB", privBlob, privLen, &privLen, 0);
    if (st != 0) { printf("[!] export private: 0x%08lX\n", (unsigned long)st); return 1; }

    MY_BCRYPT_RSAKEY_BLOB *privHdr = (MY_BCRYPT_RSAKEY_BLOB *)privBlob;
    printf("[+] private key exported (%lu bytes)\n", (unsigned long)privLen);
    printf("    magic: 0x%08lX (RSA3=0x%08X)\n",
           (unsigned long)privHdr->Magic, MY_BCRYPT_RSAFULLPRIVATE_MAGIC);

    writeKeyFile(PRIVKEY_FILE, privBlob, privLen);
    wprintf(L"    saved: %s\n\n", PRIVKEY_FILE);

    // export as RSAPRIVATEBLOB for KernelDumpDecrypt compat, additional shit. 
    ULONG privSimpleLen = 0;
    pExport(hKey, NULL, L"RSAPRIVATEBLOB", NULL, 0, &privSimpleLen, 0);
    BYTE *privSimple = (BYTE *)malloc(privSimpleLen);
    st = pExport(hKey, NULL, L"RSAPRIVATEBLOB", privSimple, privSimpleLen, &privSimpleLen, 0);
    if (st == 0) {
        writeKeyFile(L"werenc_priv_simple.key", privSimple, privSimpleLen);
        wprintf(L"    also saved: werenc_priv_simple.key (KernelDumpDecrypt compat)\n\n");
    }
    free(privSimple);

    printf("[+] key pair generation complete\n");
    printf("    public key:  use for BYOK patching of WerEnc.dll\n");
    printf("    private key: use for decryption (keep secure!)\n\n");
    printf("    decrypt cmd:\n");
    printf("      werenc_byok.exe --decrypt <encrypted.enc>\n");

    pDestroy(hKey);
    pClose(hAlg, 0);
    free(pubBlob);
    free(privBlob);
    FreeLibrary(hBCrypt);
    return 0;
}



typedef struct {
    BYTE *address;
    ULONG blobSize;
    MY_BCRYPT_RSAKEY_BLOB header;
} RSA_BLOB_HIT;

static int ScanDllForRSABlobs(HMODULE hMod, RSA_BLOB_HIT *hits, int maxHits)
{
    MY_MODULEINFO mi;
    typedef BOOL (WINAPI *pfn_GetModuleInformation)(HANDLE, HMODULE, void *, DWORD);
    HMODULE hPsapi = LoadLibraryW(L"psapi.dll"); // you can call the API in different way but yeah this still one of my fav
    pfn_GetModuleInformation pGMI = NULL;
    if (hPsapi)
        pGMI = (pfn_GetModuleInformation)GetProcAddress(hPsapi, "GetModuleInformation");

    BYTE *base;
    DWORD size;

    if (pGMI && pGMI(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
        base = (BYTE *)mi.lpBaseOfDll;
        size = mi.SizeOfImage;
    } else {
   
        base = (BYTE *)hMod;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        size = nt->OptionalHeader.SizeOfImage;
    }

    if (hPsapi) FreeLibrary(hPsapi);

    printf("[*] scanning WerEnc.dll: base=%p, size=%lu bytes\n",
           (void *)base, (unsigned long)size);

    int count = 0;
    for (DWORD off = 0; off < size - sizeof(MY_BCRYPT_RSAKEY_BLOB); off++) {
        ULONG magic = *(ULONG *)(base + off);
        if (magic == MY_BCRYPT_RSAPUBLIC_MAGIC ||
            magic == MY_BCRYPT_RSAPRIVATE_MAGIC ||
            magic == MY_BCRYPT_RSAFULLPRIVATE_MAGIC) {

            MY_BCRYPT_RSAKEY_BLOB *blob = (MY_BCRYPT_RSAKEY_BLOB *)(base + off);

          
            if ((blob->BitLength == 2048 || blob->BitLength == 4096) && // between 2028 - 4096 
                blob->cbPublicExp > 0 && blob->cbPublicExp <= 8 &&
                blob->cbModulus > 0 && blob->cbModulus <= 512) {

                ULONG totalSize = sizeof(MY_BCRYPT_RSAKEY_BLOB) +
                                  blob->cbPublicExp + blob->cbModulus;

                if (count < maxHits) {
                    hits[count].address  = base + off;
                    hits[count].blobSize = totalSize;
                    hits[count].header   = *blob;
                    count++;
                }

                printf("  [+] RSA blob at offset 0x%lX (addr %p)\n",
                       (unsigned long)off, (void *)(base + off));
                printf("      magic: 0x%08lX (%s)\n",
                       (unsigned long)magic,
                       magic == MY_BCRYPT_RSAPUBLIC_MAGIC ? "RSA1/public" :
                       magic == MY_BCRYPT_RSAPRIVATE_MAGIC ? "RSA2/private" : "RSA3/full");
                printf("      bits: %lu, exp: %lu bytes, mod: %lu bytes\n",
                       (unsigned long)blob->BitLength,
                       (unsigned long)blob->cbPublicExp,
                       (unsigned long)blob->cbModulus);
                printf("      total blob: %lu bytes\n", (unsigned long)totalSize);

                /* Show first bytes of modulus */
                BYTE *modulus = (BYTE *)(blob + 1) + blob->cbPublicExp;
                printf("      modulus[0..15]: ");
                hexdump(modulus, blob->cbModulus, 16);
            }
        }
    }

    return count;
}



static int PatchWerEncPublicKey(HMODULE hEnc, const BYTE *pubBlob, DWORD pubLen);

static int EncryptWithBYOK(const wchar_t *inputPath, const wchar_t *outputPath)
{
    printf("\n=== BYOK Encryption via WerEnc.dll ===\n\n");

    // load the pub key
    DWORD pubLen = 0;
    BYTE *pubBlob = readKeyFile(PUBKEY_FILE, &pubLen);
    if (!pubBlob || pubLen < sizeof(MY_BCRYPT_RSAKEY_BLOB)) {
        wprintf(L"[!] cannot read %s — run --generate-keys first\n", PUBKEY_FILE);
        return 1;
    }

    MY_BCRYPT_RSAKEY_BLOB *ourKey = (MY_BCRYPT_RSAKEY_BLOB *)pubBlob;
    printf("[*] our RSA key: %lu bits, exp %lu bytes, mod %lu bytes\n",
           (unsigned long)ourKey->BitLength,
           (unsigned long)ourKey->cbPublicExp,
           (unsigned long)ourKey->cbModulus);


    HMODULE hEnc = LoadLibraryW(L"WerEnc.dll");
    if (!hEnc) hEnc = LoadLibraryW(L"C:\\Windows\\System32\\WerEnc.dll");
    if (!hEnc) {
        printf("[!] cannot load WerEnc.dll\n");
        free(pubBlob);
        return 1;
    }




    int patched = PatchWerEncPublicKey(hEnc, pubBlob, pubLen);

    if (patched == 0) {
        printf("[!] failed to patch any RSA blob\n");
        printf("    fallback: use Strategy 2 (--capture) or Strategy 3 (--setup-crashcontrol)\n");
        free(pubBlob);
        FreeLibrary(hEnc);
        return 1;
    }

    printf("[+] %d RSA blob(s) patched — WerEnc.dll now uses OUR key\n\n", patched);



    FARPROC pRaw = GetProcAddress(hEnc, "EncryptDumpFile");
    if (!pRaw) pRaw = GetProcAddress(hEnc, (LPCSTR)1);
    if (!pRaw) {
        printf("[!] EncryptDumpFile not found\n");
        free(pubBlob);
        FreeLibrary(hEnc);
        return 1;
    }

    printf("[*] calling EncryptDumpFile with BYOK-patched key...\n");
    wprintf(L"    input:  %s\n", inputPath);
    wprintf(L"    output: %s\n", outputPath);


    int success = 0;
    {
        pfn_EncryptDumpFile_PP fn = (pfn_EncryptDumpFile_PP)pRaw;
        HRESULT hr = fn(inputPath, outputPath);
        printf("    EncryptDumpFile(LPCWSTR, LPCWSTR) -> 0x%08lX\n", (unsigned long)hr);
        DWORD sz = 0;
        HANDLE hChk = CreateFileW(outputPath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hChk != INVALID_HANDLE_VALUE) {
            sz = GetFileSize(hChk, NULL);
            CloseHandle(hChk);
        }
        if (SUCCEEDED(hr) && sz > 0) {
            printf("    [+] SUCCESS — %lu bytes encrypted with OUR key\n",
                   (unsigned long)sz);
            success = 1;
        }
    }


    if (!success) {
        HANDLE hIn = CreateFileW(inputPath, GENERIC_READ, FILE_SHARE_READ,
                                 NULL, OPEN_EXISTING, 0, NULL);
        HANDLE hOut = CreateFileW(outputPath, GENERIC_WRITE | GENERIC_READ, 0,
                                  NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hIn != INVALID_HANDLE_VALUE && hOut != INVALID_HANDLE_VALUE) {
            pfn_EncryptDumpFile_HH fn = (pfn_EncryptDumpFile_HH)pRaw;
            HRESULT hr = fn(hIn, hOut);
            printf("    EncryptDumpFile(HANDLE, HANDLE) -> 0x%08lX\n", (unsigned long)hr);
            CloseHandle(hIn);
            CloseHandle(hOut);

            HANDLE hChk = CreateFileW(outputPath, GENERIC_READ, FILE_SHARE_READ,
                                      NULL, OPEN_EXISTING, 0, NULL);
            if (hChk != INVALID_HANDLE_VALUE) {
                DWORD sz = GetFileSize(hChk, NULL);
                if (SUCCEEDED(hr) && sz > 0) {
                    printf("    [+] SUCCESS — %lu bytes encrypted with OUR key\n",
                           (unsigned long)sz);
                    success = 1;
                }
                CloseHandle(hChk);
            }
        } else {
            if (hIn  != INVALID_HANDLE_VALUE) CloseHandle(hIn);
            if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
        }
    }

    if (success) {
        printf("\n[+] file encrypted with generated RSA key (BYOK)\n");
        printf("[+] decrypt with:\n");
        printf("      werenc_byok.exe --decrypt %S\n", outputPath);
        printf("    or:\n");

    } else {
        printf("\n[-] EncryptDumpFile did not produce output\n");
        printf("    WerEnc.dll may require specific parameters or context\n");
        printf("    try --scan-dll to examine the DLL structure\n");
    }

    free(pubBlob);
    FreeLibrary(hEnc);
    return success ? 0 : 1;
}



static int ScanDLL(void)
{
    printf("\n== WerEnc.dll RSA Blob Scanner ===\n\n");

    HMODULE hEnc = LoadLibraryW(L"WerEnc.dll");
    if (!hEnc) hEnc = LoadLibraryW(L"C:\\Windows\\System32\\WerEnc.dll");
    if (!hEnc) {
        printf("[!] cannot load WerEnc.dll\n");
        return 1;
    }

    wchar_t dllPath[MAX_PATH];
    GetModuleFileNameW(hEnc, dllPath, MAX_PATH);
    wprintf(L"[*] loaded: %s\n", dllPath);

    RSA_BLOB_HIT hits[16];
    int nHits = ScanDllForRSABlobs(hEnc, hits, 16);

    if (nHits == 0) {
        printf("\n[*] no embedded RSA blobs found\n");
        printf("    the key may be:\n");
        printf("    - loaded from Windows cert store at runtime\n");
        printf("    - loaded from a resource section\n");
        printf("    - derived via DPAPI or similar\n");
        printf("    use Strategy 2 (BCrypt hook) or Strategy 3 (CrashControl reg)\n");
    } else {
        printf("\n[*] found %d RSA blob(s) — BYOK patching is viable\n", nHits);
        printf("    run --generate-keys then --encrypt <file> to use\n");
    }


    printf("\n[*] checking BCrypt import patterns...\n");
    BYTE *base = (BYTE *)hEnc;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD imgSize = nt->OptionalHeader.SizeOfImage;


    printf("\n[*] import table, crypto-related modules:\n");
    {
        IMAGE_DATA_DIRECTORY *dir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir->VirtualAddress) {
            printf("  (no import directory)\n");
        } else {
            IMAGE_IMPORT_DESCRIPTOR *imp =
                (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress);
            for (; imp->Name; imp++) {
                const char *modName = (const char *)(base + imp->Name);
                char lower[64];
                size_t j;
                for (j = 0; modName[j] && j < sizeof(lower) - 1; j++)
                    lower[j] = (char)tolower((unsigned char)modName[j]);
                lower[j] = '\0';
                if (!strstr(lower, "crypt")) continue;
                printf("  from %s:\n", modName);
                ULONG64 *thunk = (ULONG64 *)(base +
                    (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                             : imp->FirstThunk));
                for (; *thunk; thunk++) {
                    if (IMAGE_SNAP_BY_ORDINAL64(*thunk)) {
                        printf("      ordinal %llu\n",
                               (unsigned long long)IMAGE_ORDINAL64(*thunk));
                    } else {
                        IMAGE_IMPORT_BY_NAME *ibn =
                            (IMAGE_IMPORT_BY_NAME *)(base + (DWORD)*thunk);
                        printf("      %s\n", (const char *)ibn->Name);
                    }
                }
            }
        }
    }

    const char *bcryptFns[] = {
        "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
        "BCryptGenerateSymmetricKey", "BCryptImportKey", "BCryptImportKeyPair",
        "BCryptGenRandom", "BCryptDeriveKey", NULL
    };

    for (int i = 0; bcryptFns[i]; i++) {
        int found = 0;
        size_t fnLen = strlen(bcryptFns[i]);
        for (DWORD off = 0; off < imgSize - (DWORD)fnLen; off++) {
            if (memcmp(base + off, bcryptFns[i], fnLen) == 0) {
                found = 1;
                break;
            }
        }
        printf("  %s: %s\n", bcryptFns[i], found ? "FOUND" : "not found");
    }

    FreeLibrary(hEnc);
    return 0;
}





static int ParseHexBuffer(const wchar_t *hex, BYTE *out, DWORD outCap, DWORD *outLen)
{
    *outLen = 0;
    if (!hex) return 0;
    while (*hex && *outLen < outCap) {
        int hi, lo;
        wchar_t c = *hex++;
        if      (c >= L'0' && c <= L'9') hi = (int)(c - L'0');
        else if (c >= L'a' && c <= L'f') hi = 10 + (int)(c - L'a');
        else if (c >= L'A' && c <= L'F') hi = 10 + (int)(c - L'A');
        else return 0;
        if (!*hex) return 0;
        c = *hex++;
        if      (c >= L'0' && c <= L'9') lo = (int)(c - L'0');
        else if (c >= L'a' && c <= L'f') lo = 10 + (int)(c - L'a');
        else if (c >= L'A' && c <= L'F') lo = 10 + (int)(c - L'A');
        else return 0;
        out[(*outLen)++] = (BYTE)((hi << 4) | lo);
    }
    return (*outLen == 16);
}

static int PrintableCount(const BYTE *buf, DWORD len)
{
    int n = 0;
    for (DWORD i = 0; i < len; i++)
        if ((buf[i] >= 0x20 && buf[i] < 0x7F) || buf[i] == 0x0D || buf[i] == 0x0A)
            n++;
    return n;
}

static int RsaUnwrap(pfn_BCryptDecrypt pDecrypt, void *hKey,
                     const BYTE *block, ULONG blockLen,
                     BYTE *out, ULONG outCap, ULONG minLen, ULONG maxLen,
                     ULONG *outLen, const char *what)
{
    *outLen = 0;

    NTSTATUS st = pDecrypt(hKey, (BYTE *)block, blockLen, NULL, NULL, 0,
                           out, outCap, outLen, MY_BCRYPT_PAD_PKCS1);
    printf("[*] RSA unwrap %s (PKCS1 v1.5):  0x%08lX (%lu bytes)\n",
           what, (unsigned long)st, (unsigned long)*outLen);
    if (st == 0 && *outLen >= minLen && *outLen <= maxLen) return 1;

    wchar_t sha256[] = L"SHA256";
    wchar_t sha1[]   = L"SHA1";
    MY_BCRYPT_OAEP_PADDING_INFO oaep;
    oaep.pbLabel = NULL;
    oaep.cbLabel = 0;

    oaep.pszAlgId = sha256;
    *outLen = 0;
    st = pDecrypt(hKey, (BYTE *)block, blockLen, &oaep, NULL, 0,
                  out, outCap, outLen, MY_BCRYPT_PAD_OAEP);
    printf("[*] RSA unwrap %s (OAEP-SHA256): 0x%08lX (%lu bytes)\n",
           what, (unsigned long)st, (unsigned long)*outLen);
    if (st == 0 && *outLen >= minLen && *outLen <= maxLen) return 1;

    oaep.pszAlgId = sha1;
    *outLen = 0;
    st = pDecrypt(hKey, (BYTE *)block, blockLen, &oaep, NULL, 0,
                  out, outCap, outLen, MY_BCRYPT_PAD_OAEP);
    printf("[*] RSA unwrap %s (OAEP-SHA1):   0x%08lX (%lu bytes)\n",
           what, (unsigned long)st, (unsigned long)*outLen);
    if (st == 0 && *outLen >= minLen && *outLen <= maxLen) return 1;

    return 0;
}

static int DecryptBYOK(const wchar_t *inputPath, const wchar_t *outputPath,
                       const wchar_t *ivHex)
{
    printf("\n=== BYOK Decryption ===\n\n");

  
    DWORD privLen = 0;
    BYTE *privBlob = readKeyFile(PRIVKEY_FILE, &privLen);
    if (!privBlob || privLen < sizeof(MY_BCRYPT_RSAKEY_BLOB)) {
        wprintf(L"[!] cannot read %s — run --generate-keys first\n", PRIVKEY_FILE);
        return 1;
    }

    MY_BCRYPT_RSAKEY_BLOB *privHdr = (MY_BCRYPT_RSAKEY_BLOB *)privBlob;
    printf("[*] private key: %lu bits (magic 0x%08lX)\n",
           (unsigned long)privHdr->BitLength, (unsigned long)privHdr->Magic);

  
    DWORD encLen = 0;
    BYTE *encData = readKeyFile(inputPath, &encLen);
    if (!encData || encLen == 0) {
        wprintf(L"[!] cannot read %s\n", inputPath);
        free(privBlob);
        return 1;
    }
    printf("[*] encrypted file: %lu bytes\n", (unsigned long)encLen);

    if (encLen < 0x40) {
        printf("[!] file too small to be a WerEnc encrypted file\n");
        free(privBlob); free(encData);
        return 1;
    }

  
    DWORD version   = *(DWORD *)(encData + 0x20);
    DWORD blobOff   = *(DWORD *)(encData + 0x24);
    DWORD origSize  = *(DWORD *)(encData + 0x28);
    DWORD blobSize  = *(DWORD *)(encData + 0x30);
    DWORD rsaBlkSz  = *(DWORD *)(encData + 0x34);
    DWORD keySize   = *(DWORD *)(encData + 0x38);

    if (rsaBlkSz == 0) rsaBlkSz = privHdr->BitLength / 8;

    printf("[*] header: version=%lu blobOff=0x%lX origSize=%lu blobSize=%lu rsaBlk=%lu keySize=%lu\n",
           (unsigned long)version, (unsigned long)blobOff,
           (unsigned long)origSize, (unsigned long)blobSize,
           (unsigned long)rsaBlkSz, (unsigned long)keySize);

    if (version != 2)
        printf("[!] unexpected version %lu — continuing anyway\n", (unsigned long)version);

    if (blobOff < 0x40 || blobSize == 0 ||
        (DWORD64)blobOff + blobSize + rsaBlkSz > encLen) {
        printf("[!] header size fields inconsistent with file size\n");
        free(privBlob); free(encData);
        return 1;
    }

    DWORD rsaOff     = blobOff + blobSize;
    DWORD structOff  = rsaOff + rsaBlkSz;
    DWORD contentPadded = (origSize + 15) & ~15;

    if (contentPadded == 0 || contentPadded > encLen ||
        encLen - contentPadded < structOff) {
        printf("[!] original size field (0x%08lX) inconsistent with layout\n",
               (unsigned long)origSize);
        free(privBlob); free(encData);
        return 1;
    }
    DWORD contentOff = encLen - contentPadded;

    printf("[*] layout: RSA-wrapped key @0x%lX, struct block @0x%lX (%lu bytes), content @0x%lX (%lu bytes)\n",
           (unsigned long)rsaOff, (unsigned long)structOff,
           (unsigned long)(contentOff - structOff),
           (unsigned long)contentOff, (unsigned long)contentPadded);

    /* Load BCrypt */
    HMODULE hBCrypt = LoadLibraryW(L"bcrypt.dll");
    if (!hBCrypt) { printf("[!] cannot load bcrypt.dll\n"); free(privBlob); free(encData); return 1; }

    pfn_BCryptOpenAlgorithmProvider pOpen =
        (pfn_BCryptOpenAlgorithmProvider)GetProcAddress(hBCrypt, "BCryptOpenAlgorithmProvider");
    pfn_BCryptImportKeyPair pImport =
        (pfn_BCryptImportKeyPair)GetProcAddress(hBCrypt, "BCryptImportKeyPair");
    pfn_BCryptDecrypt pDecrypt =
        (pfn_BCryptDecrypt)GetProcAddress(hBCrypt, "BCryptDecrypt");
    pfn_BCryptDestroyKey pDestroy =
        (pfn_BCryptDestroyKey)GetProcAddress(hBCrypt, "BCryptDestroyKey");
    pfn_BCryptCloseAlgorithmProvider pClose =
        (pfn_BCryptCloseAlgorithmProvider)GetProcAddress(hBCrypt, "BCryptCloseAlgorithmProvider");

    if (!pOpen || !pImport || !pDecrypt || !pDestroy || !pClose) {
        printf("[!] missing BCrypt exports\n");
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }

  
    void *hAlg = NULL;
    NTSTATUS st = pOpen(&hAlg, L"RSA", NULL, 0);
    if (st != 0) {
        printf("[!] BCryptOpenAlgorithmProvider: 0x%08lX\n", (unsigned long)st);
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }

    void *hKey = NULL;
    st = pImport(hAlg, NULL, L"RSAFULLPRIVATEBLOB", &hKey, privBlob, privLen, 0);
    if (st != 0)
        st = pImport(hAlg, NULL, L"RSAPRIVATEBLOB", &hKey, privBlob, privLen, 0);
    if (st != 0) {
        printf("[!] BCryptImportKeyPair: 0x%08lX\n", (unsigned long)st);
        free(privBlob); free(encData); pClose(hAlg, 0); FreeLibrary(hBCrypt);
        return 1;
    }
    printf("[+] RSA private key imported\n\n");

  
    BYTE aesKey[64];
    ULONG aesKeyLen = 0;
    if (!RsaUnwrap(pDecrypt, hKey, encData + rsaOff, rsaBlkSz,
                   aesKey, sizeof(aesKey), 16, 32, &aesKeyLen, "session key")) {
        printf("\n[-] could not unwrap the session key with this private key\n");
        printf("    - was the file encrypted with a different key pair?\n");
        printf("    - external tool: KernelDumpDecrypt.exe /keyfile werenc_priv_simple.key %S out.bin\n",
               inputPath);
        pDestroy(hKey); pClose(hAlg, 0);
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }

    printf("[+] AES session key recovered (%lu bytes): ", (unsigned long)aesKeyLen);
    hexdump(aesKey, aesKeyLen, 32);
    if (keySize && aesKeyLen != keySize)
        printf("[!] header says key size %lu, unwrapped %lu — continuing\n",
               (unsigned long)keySize, (unsigned long)aesKeyLen);
    writeKeyFile(AES_KEY_FILE, aesKey, aesKeyLen);
    wprintf(L"    saved: %s\n", AES_KEY_FILE);

 
    void *hAesAlg = NULL;
    st = pOpen(&hAesAlg, L"AES", NULL, 0);
    if (st != 0) {
        printf("[!] AES provider: 0x%08lX\n", (unsigned long)st);
        pDestroy(hKey); pClose(hAlg, 0);
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }

    pfn_BCryptSetProperty pSetProp =
        (pfn_BCryptSetProperty)GetProcAddress(hBCrypt, "BCryptSetProperty");
    pfn_BCryptGenerateSymmetricKey pGenSym =
        (pfn_BCryptGenerateSymmetricKey)GetProcAddress(hBCrypt, "BCryptGenerateSymmetricKey");
    if (!pSetProp || !pGenSym) {
        printf("[!] missing BCrypt symmetric exports\n");
        pClose(hAesAlg, 0); pDestroy(hKey); pClose(hAlg, 0);
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }

    wchar_t cbcMode[] = L"ChainingModeCBC";
    pSetProp(hAesAlg, L"ChainingMode", (BYTE *)cbcMode,
             (ULONG)(wcslen(cbcMode) + 1) * 2, 0);

    void *hAesKey = NULL;
    st = pGenSym(hAesAlg, &hAesKey, NULL, 0, aesKey, aesKeyLen, 0);
    if (st != 0) {
        printf("[!] BCryptGenerateSymmetricKey: 0x%08lX\n", (unsigned long)st);
        pClose(hAesAlg, 0); pDestroy(hKey); pClose(hAlg, 0);
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }

  
    BYTE ivBuf[16];
    int haveIv = 0;
    const char *ivName = "zeros (fallback)";

    if (ivHex) {
        DWORD ivLen = 0;
        if (!ParseHexBuffer(ivHex, ivBuf, sizeof(ivBuf), &ivLen)) {
            wprintf(L"[!] invalid IV hex '%s' (need 32 hex chars = 16 bytes)\n", ivHex);
            pDestroy(hAesKey); pClose(hAesAlg, 0); pDestroy(hKey); pClose(hAlg, 0);
            free(privBlob); free(encData); FreeLibrary(hBCrypt);
            return 1;
        }
        haveIv = 1;
        ivName = "user-supplied";
        printf("[*] using user-supplied content IV: ");
        hexdump(ivBuf, 16, 16);
    } else {
   
        BYTE ivPlain[64];
        ULONG ivPlainLen = 0;
        if (contentOff - structOff >= rsaBlkSz &&
            RsaUnwrap(pDecrypt, hKey, encData + structOff, rsaBlkSz,
                      ivPlain, sizeof(ivPlain), 16, 32, &ivPlainLen,
                      "struct block (content IV)")) {
            memcpy(ivBuf, ivPlain, 16);
            haveIv = 1;
            ivName = "RSA-wrapped struct block";
            printf("[+] content IV recovered from struct block: ");
            hexdump(ivBuf, 16, 16);
        } else {
            printf("[!] could not RSA-unwrap the struct block — trying IV candidates\n");
        }
    }

    BYTE cand[3][16];
    memcpy(cand[0], encData, 16);        /* IV1 */
    memcpy(cand[1], encData + 16, 16);   /* IV2 */
    memset(cand[2], 0, 16);              /* zeros */
    const char *candName[3] = { "IV1(header)", "IV2(header)", "zeros" };

    if (!haveIv) {
        printf("[*] probing candidate IVs (scoring first plaintext block):\n");
        int best = 2, bestScore = -1;
        ULONG probeIn = (contentPadded < 16) ? contentPadded : 16;
        for (int i = 0; i < 3; i++) {
            BYTE probe[32];
            ULONG probeLen = 0;
            BYTE ivCopy[16];
            memcpy(ivCopy, cand[i], 16);
            st = pDecrypt(hAesKey, encData + contentOff, probeIn, NULL,
                          ivCopy, 16, probe, sizeof(probe), &probeLen, 0);
            int score = (st == 0) ? PrintableCount(probe, probeLen < 16 ? probeLen : 16) : -1;
            printf("    %-12s: %d/16 printable%s\n", candName[i], score,
                   (st != 0) ? " (decrypt failed)" : "");
            if (score > bestScore) { bestScore = score; best = i; }
        }
        memcpy(ivBuf, cand[best], 16);
        ivName = candName[best];
        printf("[*] selected %s (score %d/16)\n", ivName, bestScore);
        if (bestScore < 12)
            printf("[!] no candidate IV looks right — first 16 bytes will be garbage\n");
    }

  
    BYTE *decrypted = (BYTE *)malloc(contentPadded + 16);
    BYTE ivUse[16];
    ULONG decLen = 0;
    memcpy(ivUse, ivBuf, 16);
    st = pDecrypt(hAesKey, encData + contentOff, contentPadded, NULL,
                  ivUse, 16, decrypted, contentPadded + 16, &decLen, 0);
    if (st != 0 || decLen == 0) {
        printf("[!] AES decrypt failed: 0x%08lX\n", (unsigned long)st);
        free(decrypted);
        pDestroy(hAesKey); pClose(hAesAlg, 0); pDestroy(hKey); pClose(hAlg, 0);
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }

    DWORD writeLen = decLen;
    if (origSize > 0 && origSize <= decLen) writeLen = origSize;

    printf("\n[+] decrypted %lu bytes (IV: %s)\n", (unsigned long)decLen, ivName);

    HANDLE hOut = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] cannot write %s\n", outputPath);
        free(decrypted);
        pDestroy(hAesKey); pClose(hAesAlg, 0); pDestroy(hKey); pClose(hAlg, 0);
        free(privBlob); free(encData); FreeLibrary(hBCrypt);
        return 1;
    }
    DWORD w;
    WriteFile(hOut, decrypted, writeLen, &w, NULL);
    CloseHandle(hOut);

    wprintf(L"[+] DECRYPTED: %s (%lu bytes of %lu original)\n\n",
            outputPath, (unsigned long)writeLen, (unsigned long)origSize);

    printf("    content: ");
    hexdump(decrypted, writeLen, 64);
    printf("    ASCII:   ");
    for (DWORD i = 0; i < writeLen && i < 80; i++)
        printf("%c", (decrypted[i] >= 0x20 && decrypted[i] < 0x7F) ? decrypted[i] : '.');
    printf("\n");

    if (writeLen >= 4 && decrypted[0] == 'M' && decrypted[1] == 'D' &&
        decrypted[2] == 'M' && decrypted[3] == 'P')
        printf("    [+] valid MDMP header\n");

    if (!haveIv && PrintableCount(decrypted, (writeLen < 16) ? writeLen : 16) < 12) {
        printf("\n[!] NOTE: the first 16 bytes are garbled — the content IV is unknown.\n");
        if (writeLen <= 16)
            printf("    This file is a single AES block: ALL bytes depend on the IV.\n");
        else
            printf("    All later bytes are already correct (CBC chaining).\n");
        printf("    To recover the first block fully:\n");
        printf("      1. werenc_byok.exe --capture <original-file>\n");
        printf("         -> werenc_capture.log lists every IV WerEnc used\n");
        printf("      2. werenc_byok.exe --decrypt <file.enc> <out> <iv-hex>\n");
    }

    free(decrypted);
    pDestroy(hAesKey);
    pClose(hAesAlg, 0);
    pDestroy(hKey);
    pClose(hAlg, 0);
    free(privBlob);
    free(encData);
    FreeLibrary(hBCrypt);
    return 0;
}



static FILE *g_cap = NULL;

static pfn_BCryptEncrypt              g_realEncrypt = NULL;
static pfn_BCryptDecrypt              g_realDecrypt = NULL;
static pfn_BCryptGenerateSymmetricKey g_realGenSym  = NULL;
static pfn_BCryptSetProperty          g_realSetProp = NULL;
static pfn_BCryptGenRandom            g_realGenRand = NULL;
static pfn_BCryptImportKeyPair        g_realImportKP = NULL;

static void CapHex(const char *tag, const BYTE *buf, ULONG len);

static NTSTATUS WINAPI Hook_BCryptImportKeyPair(void *hAlgorithm, void *hImportKey,
    LPCWSTR pszBlobType, void **phKey, BYTE *pbInput, ULONG cbInput, ULONG dwFlags)
{
    if (g_cap) {
        fprintf(g_cap, "[BCryptImportKeyPair] hAlg=%p blobType=%ls cbInput=%lu\n",
                hAlgorithm, pszBlobType ? pszBlobType : L"(null)",
                (unsigned long)cbInput);
        if (pbInput && cbInput) CapHex("key blob", pbInput, cbInput);
    }
    NTSTATUS st = g_realImportKP(hAlgorithm, hImportKey, pszBlobType, phKey,
                                 pbInput, cbInput, dwFlags);
    if (g_cap && st == 0 && phKey)
        fprintf(g_cap, "    -> hKey=%p\n", *phKey);
    return st;
}

static void CapHex(const char *tag, const BYTE *buf, ULONG len)
{
    if (!g_cap) return;
    fprintf(g_cap, "    %-14s (%lu bytes): ", tag, (unsigned long)len);
    ULONG show = (len < 64) ? len : 64;
    for (ULONG i = 0; i < show; i++)
        fprintf(g_cap, "%02X", buf ? buf[i] : 0);
    if (show < len) fprintf(g_cap, "...(+%lu)", (unsigned long)(len - show));
    fprintf(g_cap, "\n");
}

static NTSTATUS WINAPI Hook_BCryptEncrypt(void *hKey, BYTE *pbInput, ULONG cbInput,
    void *pPaddingInfo, BYTE *pbIV, ULONG cbIV, BYTE *pbOutput, ULONG cbOutput,
    ULONG *pcbResult, ULONG dwFlags)
{
    if (g_cap) {
        fprintf(g_cap, "[BCryptEncrypt]   hKey=%p cbInput=%lu cbIV=%lu flags=0x%lX padInfo=%p\n",
                hKey, (unsigned long)cbInput, (unsigned long)cbIV,
                (unsigned long)dwFlags, pPaddingInfo);
        if (pbIV && cbIV) CapHex("IV", pbIV, cbIV);
        else              fprintf(g_cap, "    IV             (none)\n");
        if (pbInput && cbInput) CapHex("plaintext", pbInput, cbInput);
    }
    NTSTATUS st = g_realEncrypt(hKey, pbInput, cbInput, pPaddingInfo,
                                pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
    if (g_cap && st == 0 && pbOutput && pcbResult && *pcbResult)
        CapHex("ciphertext", pbOutput, *pcbResult);
    return st;
}

static NTSTATUS WINAPI Hook_BCryptDecrypt(void *hKey, BYTE *pbInput, ULONG cbInput,
    void *pPaddingInfo, BYTE *pbIV, ULONG cbIV, BYTE *pbOutput, ULONG cbOutput,
    ULONG *pcbResult, ULONG dwFlags)
{
    if (g_cap) {
        fprintf(g_cap, "[BCryptDecrypt]   hKey=%p cbInput=%lu cbIV=%lu flags=0x%lX\n",
                hKey, (unsigned long)cbInput, (unsigned long)cbIV,
                (unsigned long)dwFlags);
        if (pbIV && cbIV) CapHex("IV", pbIV, cbIV);
    }
    return g_realDecrypt(hKey, pbInput, cbInput, pPaddingInfo,
                         pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}

static NTSTATUS WINAPI Hook_BCryptGenerateSymmetricKey(
    void *hAlgorithm, void **phKey, BYTE *pbKeyObject, ULONG cbKeyObject,
    BYTE *pbSecret, ULONG cbSecret, ULONG dwFlags)
{
    if (g_cap) {
        fprintf(g_cap, "[BCryptGenSymKey] hAlg=%p cbSecret=%lu flags=0x%lX\n",
                hAlgorithm, (unsigned long)cbSecret, (unsigned long)dwFlags);
        if (pbSecret && cbSecret) CapHex("KEY MATERIAL", pbSecret, cbSecret);
    }
    NTSTATUS st = g_realGenSym(hAlgorithm, phKey, pbKeyObject, cbKeyObject,
                               pbSecret, cbSecret, dwFlags);
    if (g_cap && st == 0 && phKey)
        fprintf(g_cap, "    -> hKey=%p\n", *phKey);
    return st;
}

static NTSTATUS WINAPI Hook_BCryptSetProperty(void *hObject, LPCWSTR pszProperty,
    BYTE *pbInput, ULONG cbInput, ULONG dwFlags)
{
    if (g_cap) {
        fprintf(g_cap, "[BCryptSetProp]   obj=%p prop=%ls cb=%lu\n",
                hObject, pszProperty ? pszProperty : L"(null)", (unsigned long)cbInput);
        if (pbInput && cbInput && cbInput <= 128) CapHex("value", pbInput, cbInput);
    }
    return g_realSetProp(hObject, pszProperty, pbInput, cbInput, dwFlags);
}

static NTSTATUS WINAPI Hook_BCryptGenRandom(void *hAlgorithm, BYTE *pbBuffer,
    ULONG cbBuffer, ULONG dwFlags)
{
    NTSTATUS st = g_realGenRand(hAlgorithm, pbBuffer, cbBuffer, dwFlags);
    if (g_cap && st == 0 && pbBuffer)
        CapHex("[GenRandom]", pbBuffer, cbBuffer);
    return st;
}


static int PatchIatForBcrypt(HMODULE hMod)
{
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir->VirtualAddress) return 0;

    struct { const char *name; void *hook; void **orig; } targets[] = {
        { "BCryptEncrypt",              (void *)Hook_BCryptEncrypt,              (void **)&g_realEncrypt },
        { "BCryptDecrypt",              (void *)Hook_BCryptDecrypt,              (void **)&g_realDecrypt },
        { "BCryptGenerateSymmetricKey", (void *)Hook_BCryptGenerateSymmetricKey, (void **)&g_realGenSym  },
        { "BCryptSetProperty",          (void *)Hook_BCryptSetProperty,          (void **)&g_realSetProp },
        { "BCryptGenRandom",            (void *)Hook_BCryptGenRandom,            (void **)&g_realGenRand },
        { "BCryptImportKeyPair",        (void *)Hook_BCryptImportKeyPair,        (void **)&g_realImportKP },
    };
    int nTargets = (int)(sizeof(targets) / sizeof(targets[0]));
    int hooked = 0;

    IMAGE_IMPORT_DESCRIPTOR *imp =
        (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress);
    for (; imp->Name; imp++) {
        const char *modName = (const char *)(base + imp->Name);

      
        char lower[64];
        size_t j;
        for (j = 0; modName[j] && j < sizeof(lower) - 1; j++)
            lower[j] = (char)tolower((unsigned char)modName[j]);
        lower[j] = '\0';
        if (!strstr(lower, "bcrypt")) continue;

        ULONG64 *thunkRef = (ULONG64 *)(base +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        ULONG64 *funcRef = (ULONG64 *)(base + imp->FirstThunk);

        for (; *thunkRef; thunkRef++, funcRef++) {
            if (IMAGE_SNAP_BY_ORDINAL64(*thunkRef)) continue;
            IMAGE_IMPORT_BY_NAME *ibn =
                (IMAGE_IMPORT_BY_NAME *)(base + (DWORD)*thunkRef);
            const char *funcName = (const char *)ibn->Name;
            for (int i = 0; i < nTargets; i++) {
                if (strcmp(funcName, targets[i].name) != 0) continue;
                DWORD oldProt;
                if (VirtualProtect(funcRef, sizeof(ULONG64), PAGE_READWRITE, &oldProt)) {
                    *targets[i].orig = (void *)*funcRef;
                    *funcRef = (ULONG64)(ULONG_PTR)targets[i].hook;
                    VirtualProtect(funcRef, sizeof(ULONG64), oldProt, &oldProt);
                    printf("  [+] hooked WerEnc!%s\n", targets[i].name);
                    hooked++;
                }
            }
        }
    }
    return hooked;
}


static int PatchWerEncPublicKey(HMODULE hEnc, const BYTE *pubBlob, DWORD pubLen)
{
    if (pubLen < sizeof(MY_BCRYPT_RSAKEY_BLOB)) return 0;
    MY_BCRYPT_RSAKEY_BLOB *ourKey = (MY_BCRYPT_RSAKEY_BLOB *)pubBlob;

    RSA_BLOB_HIT hits[16];
    int nHits = ScanDllForRSABlobs(hEnc, hits, 16);
    if (nHits == 0) {
        printf("[!] no RSA blobs found in WerEnc.dll\n");
        return 0;
    }

    int patched = 0;
    for (int i = 0; i < nHits; i++) {
        if (hits[i].header.Magic != MY_BCRYPT_RSAPUBLIC_MAGIC) continue;
        if (hits[i].header.BitLength != ourKey->BitLength) {
            printf("  [!] blob %d: bit length mismatch (DLL=%lu, key=%lu)\n",
                   i, (unsigned long)hits[i].header.BitLength,
                   (unsigned long)ourKey->BitLength);
            continue;
        }

        ULONG msftBlobSize = sizeof(MY_BCRYPT_RSAKEY_BLOB) +
                             hits[i].header.cbPublicExp + hits[i].header.cbModulus;
        ULONG ourBlobSize  = sizeof(MY_BCRYPT_RSAKEY_BLOB) +
                             ourKey->cbPublicExp + ourKey->cbModulus;
        if (msftBlobSize != ourBlobSize ||
            hits[i].header.cbPublicExp != ourKey->cbPublicExp ||
            hits[i].header.cbModulus   != ourKey->cbModulus) {
            printf("  [!] blob %d: size mismatch (%lu vs %lu)\n",
                   i, (unsigned long)msftBlobSize, (unsigned long)ourBlobSize);
            continue;
        }

        DWORD oldProt;
        if (!VirtualProtect(hits[i].address, msftBlobSize, PAGE_READWRITE, &oldProt)) {
            printf("  [!] VirtualProtect failed: %lu\n", (unsigned long)GetLastError());
            continue;
        }
        memcpy(hits[i].address, pubBlob, ourBlobSize);
        VirtualProtect(hits[i].address, msftBlobSize, oldProt, &oldProt);

        printf("  [+] PATCHED blob %d at %p with our RSA public key\n",
               i, (void *)hits[i].address);
        patched++;
    }
    return patched;
}



static int CaptureEncrypt(const wchar_t *inputPath, const wchar_t *outputPath)
{
    printf("\n=== Strategy 2: BCrypt Capture during EncryptDumpFile ===\n\n");

    g_cap = _wfopen(L"werenc_capture.log", L"w");
    if (!g_cap) {
        printf("[!] cannot create werenc_capture.log\n");
        return 1;
    }

    DWORD pubLen = 0;
    BYTE *pubBlob = readKeyFile(PUBKEY_FILE, &pubLen);
    if (!pubBlob || pubLen < sizeof(MY_BCRYPT_RSAKEY_BLOB)) {
        wprintf(L"[!] cannot read %s — run --generate-keys first\n", PUBKEY_FILE);
        fclose(g_cap); g_cap = NULL;
        return 1;
    }

    HMODULE hEnc = LoadLibraryW(L"WerEnc.dll");
    if (!hEnc) hEnc = LoadLibraryW(L"C:\\Windows\\System32\\WerEnc.dll");
    if (!hEnc) {
        printf("[!] cannot load WerEnc.dll\n");
        free(pubBlob);
        fclose(g_cap); g_cap = NULL;
        return 1;
    }


    int hooked = PatchIatForBcrypt(hEnc);
    printf("[*] %d BCrypt function(s) hooked in WerEnc.dll IAT\n", hooked);
    if (hooked == 0)
        printf("[!] no static bcrypt imports — WerEnc may resolve dynamically\n");

    fprintf(g_cap, "=== WerEnc BCrypt capture ===\n");
    fwprintf(g_cap, L"input:  %s\n", inputPath);
    fwprintf(g_cap, L"output: %s\n", outputPath);
    fprintf(g_cap, "hooks:  %d\n\n", hooked);

    int patched = PatchWerEncPublicKey(hEnc, pubBlob, pubLen);
    if (patched == 0) {
        printf("[!] failed to patch any RSA blob — aborting capture\n");
        free(pubBlob); FreeLibrary(hEnc);
        fclose(g_cap); g_cap = NULL;
        return 1;
    }

    FARPROC pRaw = GetProcAddress(hEnc, "EncryptDumpFile");
    if (!pRaw) pRaw = GetProcAddress(hEnc, (LPCSTR)1);
    if (!pRaw) {
        printf("[!] EncryptDumpFile not found\n");
        free(pubBlob); FreeLibrary(hEnc);
        fclose(g_cap); g_cap = NULL;
        return 1;
    }

    printf("[*] calling EncryptDumpFile with capture active...\n");
    wprintf(L"    input:  %s\n", inputPath);
    wprintf(L"    output: %s\n", outputPath);


    HRESULT hr = E_FAIL;
    int success = 0;

    HANDLE hIn = CreateFileW(inputPath, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hOut = CreateFileW(outputPath, GENERIC_WRITE | GENERIC_READ, 0,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn != INVALID_HANDLE_VALUE && hOut != INVALID_HANDLE_VALUE) {
        pfn_EncryptDumpFile_HH fn = (pfn_EncryptDumpFile_HH)pRaw;
        hr = fn(hIn, hOut);
        printf("    EncryptDumpFile(HANDLE, HANDLE) -> 0x%08lX\n", (unsigned long)hr);
    } else {
        printf("[!] cannot open files (in=%p out=%p)\n",
               (void *)hIn, (void *)hOut);
    }
    if (hIn  != INVALID_HANDLE_VALUE) CloseHandle(hIn);
    if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);

    if (!SUCCEEDED(hr)) {
        /* fallback: path-based signature */
        pfn_EncryptDumpFile_PP fn = (pfn_EncryptDumpFile_PP)pRaw;
        hr = fn(inputPath, outputPath);
        printf("    EncryptDumpFile(LPCWSTR, LPCWSTR) -> 0x%08lX\n", (unsigned long)hr);
    }

    {
        DWORD sz = 0;
        HANDLE hChk = CreateFileW(outputPath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hChk != INVALID_HANDLE_VALUE) {
            sz = GetFileSize(hChk, NULL);
            CloseHandle(hChk);
        }
        if (SUCCEEDED(hr) && sz > 0) {
            printf("    [+] SUCCESS — %lu bytes written\n", (unsigned long)sz);
            success = 1;
        }
    }

    fclose(g_cap);
    g_cap = NULL;

    if (success) {
        printf("\n[+] capture written to werenc_capture.log\n");
        printf("    look for: KEY MATERIAL (session keys), IV lines, plaintext buffers\n");
        printf("    the content IV = the IV on the BCryptEncrypt call whose cbInput\n");
        printf("    matches your original file size; pass it to --decrypt <iv-hex>\n");
    } else {
        printf("\n[-] encryption failed — capture log may be incomplete\n");
    }

    free(pubBlob);
    FreeLibrary(hEnc);
    return SUCCEEDED(hr) ? 0 : 1;
}



static int AnalyzeEncrypted(const wchar_t *inputPath)
{
    printf("\n=== Encrypted File Format Analysis ===\n\n");

    DWORD encLen = 0;
    BYTE *enc = readKeyFile(inputPath, &encLen);
    if (!enc || encLen == 0) {
        wprintf(L"[!] cannot read %s\n", inputPath);
        return 1;
    }

    wprintf(L"[*] file: %s (%lu bytes)\n\n", inputPath, (unsigned long)encLen);

   
    printf("[*] first 256 bytes:\n  ");
    hexdump(enc, encLen, 256);


    printf("\n[*] ASCII view (first 256 bytes):\n  ");
    size_t show = (encLen < 256) ? encLen : 256;
    for (size_t i = 0; i < show; i++) {
        if (i && (i % 64 == 0)) printf("\n  ");
        printf("%c", (enc[i] >= 0x20 && enc[i] < 0x7F) ? enc[i] : '.');
    }
    printf("\n");

   
    printf("\n[*] magic scan:\n");
    struct { DWORD magic; const char *name; } magics[] = {
        { 0x504D444D, "MDMP (minidump)" },
        { 0x31415352, "RSA1 (public key)" },
        { 0x32415352, "RSA2 (private key)" },
        { 0x33415352, "RSA3 (full private)" },
        { 0x00020000, "possible version/type" },
        { 0x00010000, "possible version/type" },
        { 0, NULL }
    };

    for (int m = 0; magics[m].name; m++) {
        for (DWORD off = 0; off + 4 <= encLen; off++) {
            if (*(DWORD *)(enc + off) == magics[m].magic) {
                printf("  [+] %s at offset 0x%lX\n",
                       magics[m].name, (unsigned long)off);
            }
        }
    }


    printf("\n[*] entropy analysis (high = encrypted/compressed):\n");
    DWORD chunkSz = 128;
    for (DWORD off = 0; off < encLen; off += chunkSz) {
        DWORD len = (off + chunkSz > encLen) ? (encLen - off) : chunkSz;
        int freq[256] = {0};
        for (DWORD i = 0; i < len; i++) freq[enc[off + i]]++;
        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / (double)len;
            entropy -= p * (p > 0 ? (log(p) / log(2.0)) : 0);
        }
        printf("  0x%04lX-0x%04lX: %.2f bits/byte %s\n",
               (unsigned long)off, (unsigned long)(off + len - 1),
               entropy,
               entropy > 7.0 ? "(encrypted)" :
               entropy > 5.0 ? "(mixed)" : "(structured)");
    }

 
    printf("\n[*] format hypotheses (file size = %lu):\n", (unsigned long)encLen);
    printf("  - RSA-4096 block = 512 bytes\n");

    if (encLen > 512) {
        printf("  - if RSA at start:    header=0, RSA=0..511, AES=%lu bytes\n",
               (unsigned long)(encLen - 512));
        DWORD rem = encLen - 512;
        if (rem % 16 == 0)
            printf("    AES payload is 16-byte aligned (CBC likely)\n");
    }

    
    DWORD hdrs[] = { 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 64, 128 };
    for (int i = 0; i < (int)(sizeof(hdrs)/sizeof(hdrs[0])); i++) {
        DWORD h = hdrs[i];
        if (h + 512 <= encLen) {
            DWORD payload = encLen - h - 512;
            if (payload > 0 && payload % 16 == 0)
                printf("  - header=%lu, RSA=512, AES=%lu (16-aligned)\n",
                       (unsigned long)h, (unsigned long)payload);
        }
    }

 
    if (encLen > 64) {
        printf("\n[*] last 64 bytes:\n  ");
        hexdump(enc + encLen - 64, 64, 64);
    }

    free(enc);
    return 0;
}



static void PrintUsage(const wchar_t *prog)
{
    printf("\n");
    printf("============================================================\n");
    printf("  WerEnc.dll BYOK — Bring Your Own Key Encryption\n");
    printf("  0xsp Research — @zux0x3a Mr.Z \n");
    printf("============================================================\n\n");

    wprintf(L"Usage: %s <mode> [args]\n\n", prog);
    printf("  --generate-keys           Generate RSA-4096 key pair (matches WerEnc.dll)\n");
    printf("  --scan-dll                Scan WerEnc.dll for RSA blobs\n");
    printf("  --encrypt <input>         BYOK encrypt via patched WerEnc.dll\n");
    printf("  --encrypt <in> <out>      Same, with explicit output path\n");
    printf("  --decrypt <input>         Decrypt BYOK-encrypted file\n");
    printf("  --decrypt <in> <out>      Same, with explicit output path\n");
    printf("  --decrypt <in> <out> <iv> Same, with content IV as 32 hex chars\n");
    printf("                            (from werenc_capture.log / --capture)\n");
    printf("  --capture <input>         Encrypt + log all BCrypt keys/IVs WerEnc uses\n");
    printf("  --capture <in> <out>      Same, with explicit output path\n");
    printf("  --analyze <encrypted>     Dump encrypted file format/structure\n");
    printf("Workflow:\n");
    printf("  1. %S --generate-keys\n", prog);
    printf("  2. %S --encrypt file.bin\n", prog);
    printf("  3. %S --decrypt file.byok.enc   (or KernelDumpDecrypt)\n", prog);
    printf("\n");
}


int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    const wchar_t *mode = argv[1];

    if (wcscmp(mode, L"--generate-keys") == 0 || wcscmp(mode, L"-g") == 0)
        return GenerateKeyPair();

    if (wcscmp(mode, L"--scan-dll") == 0 || wcscmp(mode, L"-s") == 0)
        return ScanDLL();

    if (wcscmp(mode, L"--encrypt") == 0 || wcscmp(mode, L"-e") == 0) {
        if (argc < 3) {
            printf("[!] --encrypt requires <input_file>\n");
            return 1;
        }
        const wchar_t *input = argv[2];
        wchar_t outBuf[512];
        const wchar_t *output;
        if (argc >= 4) {
            output = argv[3];
        } else {
            _snwprintf(outBuf, 512, L"%s.byok.enc", input);
            output = outBuf;
        }
        return EncryptWithBYOK(input, output);
    }

    if (wcscmp(mode, L"--decrypt") == 0 || wcscmp(mode, L"-d") == 0) {
        if (argc < 3) {
            printf("[!] --decrypt requires <input_file>\n");
            return 1;
        }
        const wchar_t *input = argv[2];
        wchar_t outBuf[512];
        const wchar_t *output;
        const wchar_t *ivHex = NULL;
        if (argc >= 5) {
            output = argv[3];
            ivHex  = argv[4];
        } else if (argc >= 4) {
            /* could be "<out>" or "<iv>" (32 hex chars, no path separators) */
            const wchar_t *a = argv[3];
            int hexOnly = 1;
            for (const wchar_t *p = a; *p; p++) {
                if (!((*p >= L'0' && *p <= L'9') ||
                      (*p >= L'a' && *p <= L'f') ||
                      (*p >= L'A' && *p <= L'F'))) {
                    hexOnly = 0;
                    break;
                }
            }
            if (hexOnly && wcslen(a) == 32) {
                ivHex = a;
                _snwprintf(outBuf, 512, L"%s.decrypted", input);
                output = outBuf;
            } else {
                output = argv[3];
            }
        } else {
            _snwprintf(outBuf, 512, L"%s.decrypted", input);
            output = outBuf;
        }
        return DecryptBYOK(input, output, ivHex);
    }

    if (wcscmp(mode, L"--capture") == 0 || wcscmp(mode, L"--hook-encrypt") == 0) {
        if (argc < 3) {
            printf("[!] --capture requires <input_file>\n");
            return 1;
        }
        const wchar_t *input = argv[2];
        wchar_t outBuf[512];
        const wchar_t *output;
        if (argc >= 4) {
            output = argv[3];
        } else {
            _snwprintf(outBuf, 512, L"%s.byok.enc", input);
            output = outBuf;
        }
        return CaptureEncrypt(input, output);
    }

    if (wcscmp(mode, L"--analyze") == 0 || wcscmp(mode, L"-a") == 0) {
        if (argc < 3) {
            printf("[!] --analyze requires <encrypted_file>\n");
            return 1;
        }
        return AnalyzeEncrypted(argv[2]);
    }

 

    if (wcscmp(mode, L"--help") == 0 || wcscmp(mode, L"-h") == 0 ||
        wcscmp(mode, L"/?") == 0) {
        PrintUsage(argv[0]);
        return 0;
    }

    printf("[!] unknown mode: %S\n", mode);
    PrintUsage(argv[0]);
    return 1;
}
