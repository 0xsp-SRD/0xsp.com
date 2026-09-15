/*
 * werenc_probe.c — WerEnc.dll LOLBin Encryption Primitive Probe
 *
 * Research PoC: Load WerEnc.dll and use EncryptDumpFile / EncryptDumpStream
 * to encrypt arbitrary data via a trusted Microsoft-signed library.
 *
 * WerEnc.dll exports:
 *   ordinal 1: EncryptDumpFile   — encrypt an entire file on disk
 *   ordinal 2: EncryptDumpStream — encrypt a data stream (in-memory)
 *
 *
 * Compile (MinGW cross):
 *   x86_64-w64-mingw32-gcc -O2 -o werenc_probe.exe werenc_probe.c -ladvapi32
 *
 * Usage:
 *   werenc_probe.exe       // it will start probing               
 *   werenc_probe.exe <input_file>        
 *
 * Author: @zux0x3a Lawrence Amer - 0xsp Labs  
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>


static jmp_buf  g_jmpBuf;
static volatile int g_inProbe = 0;

static LONG WINAPI ProbeVEH(PEXCEPTION_POINTERS ep)
{
    (void)ep;
    if (g_inProbe) {
        g_inProbe = 0;
        longjmp(g_jmpBuf, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#define SAFE_CALL_BEGIN()  do { g_inProbe = 1; if (setjmp(g_jmpBuf) != 0) { \
    printf("  [!] EXCEPTION — wrong signature\n"); return 0; } } while(0)
#define SAFE_CALL_END()    do { g_inProbe = 0; } while(0)



/* EncryptDumpFile candidates */
typedef HRESULT (WINAPI *pfn_EDF_PP)(LPCWSTR, LPCWSTR);
typedef HRESULT (WINAPI *pfn_EDF_HH)(HANDLE, HANDLE);
typedef HRESULT (WINAPI *pfn_EDF_PPF)(LPCWSTR, LPCWSTR, DWORD);
typedef HRESULT (WINAPI *pfn_EDF_HHF)(HANDLE, HANDLE, DWORD);

/* EncryptDumpStream candidates */
typedef HRESULT (WINAPI *pfn_EDS_BUF)(PVOID, DWORD, PVOID *, DWORD *);
typedef HRESULT (WINAPI *pfn_EDS_HH)(HANDLE, HANDLE);
typedef HRESULT (WINAPI *pfn_EDS_HHF)(HANDLE, HANDLE, DWORD);



static void hexdump(const unsigned char *buf, size_t len, size_t maxBytes)
{
    size_t show = (len < maxBytes) ? len : maxBytes;
    for (size_t i = 0; i < show; i++) {
        if (i && (i % 16 == 0)) printf("\n  ");
        printf("%02X ", buf[i]);
    }
    if (show < len) printf("\n  ... (%zu more bytes)", len - show);
    printf("\n");
}





static void enableDebugPriv(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

static int createTestFile(const wchar_t *path, const void *data, DWORD len)
{
    HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD written;
    WriteFile(hf, data, len, &written, NULL);
    CloseHandle(hf);
    return (written == len);
}

static DWORD getFileSz(const wchar_t *path)
{
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    DWORD sz = GetFileSize(hf, NULL);
    CloseHandle(hf);
    return sz;
}

static void read(const wchar_t *path, size_t maxBytes)
{
    HANDLE hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        wprintf(L"  [!] cannot read %s\n", path);
        return;
    }
    DWORD sz = GetFileSize(hf, NULL);
    if (sz == 0 || sz == INVALID_FILE_SIZE) {
        CloseHandle(hf);
        return;
    }
    unsigned char *buf = (unsigned char *)malloc(sz);
    DWORD rd;
    ReadFile(hf, buf, sz, &rd, NULL);
    CloseHandle(hf);
    wprintf(L"  file: %s (%lu bytes)\n", path, (unsigned long)rd);
    printf("  ");
    hexdump(buf, rd, maxBytes); // hex read output
    free(buf);
}

static FARPROC resolveExport(HMODULE hMod, const char *name, int ordinal)
{
    FARPROC p = GetProcAddress(hMod, name);
    if (!p) p = GetProcAddress(hMod, (LPCSTR)(intptr_t)ordinal);
    return p;
}



static int probe_EDF_paths(HMODULE h, const wchar_t *in, const wchar_t *out)
{
    pfn_EDF_PP fn = (pfn_EDF_PP)resolveExport(h, "EncryptDumpFile", 1);
    if (!fn) return 0;
    printf("\n--- Probe: EncryptDumpFile(LPCWSTR, LPCWSTR) ---\n");
    SAFE_CALL_BEGIN(); // start 
    HRESULT hr = fn(in, out);
    SAFE_CALL_END();
    printf("  HRESULT: 0x%08lX\n", (unsigned long)hr);
    DWORD sz = getFileSz(out);
    if (SUCCEEDED(hr) && sz > 0) {
        printf("  [+] SUCCESS — %lu bytes written\n", (unsigned long)sz);
        read(out, 128);
        return 1;
    }
    printf("  [-] no output or failure\n");
    return 0;
}

static int probe_EDF_handles(HMODULE h, const wchar_t *in, const wchar_t *out)
{
    pfn_EDF_HH fn = (pfn_EDF_HH)resolveExport(h, "EncryptDumpFile", 1);
    if (!fn) return 0;
    printf("\n--- Probe: EncryptDumpFile(HANDLE, HANDLE) ---\n");
    HANDLE hIn = CreateFileW(in, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
    HANDLE hOut = CreateFileW(out, GENERIC_WRITE | GENERIC_READ, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) {
        if (hIn  != INVALID_HANDLE_VALUE) CloseHandle(hIn);
        if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
        return 0;
    }
    SAFE_CALL_BEGIN();
    HRESULT hr = fn(hIn, hOut);
    SAFE_CALL_END();
    printf("  HRESULT: 0x%08lX\n", (unsigned long)hr);
    CloseHandle(hIn);
    CloseHandle(hOut);
    DWORD sz = getFileSz(out);
    if (SUCCEEDED(hr) && sz > 0) {
        printf("  [+] SUCCESS — %lu bytes written\n", (unsigned long)sz);
        read(out, 128);
        return 1;
    }
    printf("  [-] no output or failure\n");
    return 0;
}

static int probe_EDF_paths_flags(HMODULE h, const wchar_t *in, const wchar_t *out)
{
    pfn_EDF_PPF fn = (pfn_EDF_PPF)resolveExport(h, "EncryptDumpFile", 1);
    if (!fn) return 0;
    printf("\n--- Probe: EncryptDumpFile(LPCWSTR, LPCWSTR, 0) ---\n");
    SAFE_CALL_BEGIN();
    HRESULT hr = fn(in, out, 0);
    SAFE_CALL_END();
    printf("  HRESULT: 0x%08lX\n", (unsigned long)hr);
    DWORD sz = getFileSz(out);
    if (SUCCEEDED(hr) && sz > 0) {
        printf("  [+] SUCCESS — %lu bytes written\n", (unsigned long)sz);
        read(out, 128);
        return 1;
    }
    printf("  [-] no output or failure\n");
    return 0;
}

static int probe_EDF_handles_flags(HMODULE h, const wchar_t *in, const wchar_t *out)
{
    pfn_EDF_HHF fn = (pfn_EDF_HHF)resolveExport(h, "EncryptDumpFile", 1);
    if (!fn) return 0;
    printf("\n--- Probe: EncryptDumpFile(HANDLE, HANDLE, 0) ---\n");
    HANDLE hIn = CreateFileW(in, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
    HANDLE hOut = CreateFileW(out, GENERIC_WRITE | GENERIC_READ, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) {
        if (hIn  != INVALID_HANDLE_VALUE) CloseHandle(hIn);
        if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
        return 0;
    }
    SAFE_CALL_BEGIN();
    HRESULT hr = fn(hIn, hOut, 0);
    SAFE_CALL_END();
    printf("  HRESULT: 0x%08lX\n", (unsigned long)hr);
    CloseHandle(hIn);
    CloseHandle(hOut);
    DWORD sz = getFileSz(out);
    if (SUCCEEDED(hr) && sz > 0) {
        printf("  [+] SUCCESS — %lu bytes written\n", (unsigned long)sz);
        read(out, 128);
        return 1;
    }
    printf("  [-] no output or failure\n");
    return 0;
}



static int probe_EDS_buffers(HMODULE h)
{
    pfn_EDS_BUF fn = (pfn_EDS_BUF)resolveExport(h, "EncryptDumpStream", 2);
    if (!fn) return 0;
    printf("\n--- Probe: EncryptDumpStream(PVOID, DWORD, PVOID*, DWORD*) ---\n");

    char payload[] = "Demo data for testing purposes..probe probe";
    DWORD inSz = (DWORD)strlen(payload);
    PVOID outBuf = NULL;
    DWORD outSz  = 0;

    SAFE_CALL_BEGIN();
    HRESULT hr = fn(payload, inSz, &outBuf, &outSz);
    SAFE_CALL_END();
    printf("  HRESULT: 0x%08lX\n", (unsigned long)hr);
    if (SUCCEEDED(hr) && outBuf && outSz > 0) {
        printf("  [+] Works! — encrypted %lu bytes in-memory\n",
               (unsigned long)outSz);
        printf("  ");
        hexdump((unsigned char *)outBuf, outSz, 128);
        return 1;
    }
    printf("  [-] fail\n");
    return 0;
}

static int probe_EDS_handles(HMODULE h, const wchar_t *in, const wchar_t *out)
{
    pfn_EDS_HH fn = (pfn_EDS_HH)resolveExport(h, "EncryptDumpStream", 2);
    if (!fn) return 0;
    printf("\n--- Probe: EncryptDumpStream(HANDLE, HANDLE) ---\n");
    HANDLE hIn = CreateFileW(in, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
    HANDLE hOut = CreateFileW(out, GENERIC_WRITE | GENERIC_READ, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) {
        if (hIn  != INVALID_HANDLE_VALUE) CloseHandle(hIn);
        if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
        return 0;
    }
    SAFE_CALL_BEGIN();
    HRESULT hr = fn(hIn, hOut);
    SAFE_CALL_END();
    printf("  HRESULT: 0x%08lX\n", (unsigned long)hr);
    CloseHandle(hIn);
    CloseHandle(hOut);
    DWORD sz = getFileSz(out);
    if (SUCCEEDED(hr) && sz > 0) {
        printf("  [+] Works lekker — stream encrypted (%lu bytes)\n",
               (unsigned long)sz);
        read(out, 128);
        return 1;
    }
    printf("  [-] Nee\n");
    return 0;
}

static int probe_EDS_handles_flags(HMODULE h, const wchar_t *in, const wchar_t *out)
{
    pfn_EDS_HHF fn = (pfn_EDS_HHF)resolveExport(h, "EncryptDumpStream", 2);
    if (!fn) return 0;
    printf("\n--- Probe fun: EncryptDumpStream(HANDLE, HANDLE, 0) ---\n");
    HANDLE hIn = CreateFileW(in, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, 0, NULL);
    HANDLE hOut = CreateFileW(out, GENERIC_WRITE | GENERIC_READ, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) {
        if (hIn  != INVALID_HANDLE_VALUE) CloseHandle(hIn);
        if (hOut != INVALID_HANDLE_VALUE) CloseHandle(hOut);
        return 0;
    }
    SAFE_CALL_BEGIN();
    HRESULT hr = fn(hIn, hOut, 0);
    SAFE_CALL_END();
    printf("  HRESULT: 0x%08lX\n", (unsigned long)hr);
    CloseHandle(hIn);
    CloseHandle(hOut);
    DWORD sz = getFileSz(out);
    if (SUCCEEDED(hr) && sz > 0) {
        printf("  [+] Works — stream encrypted (%lu bytes)\n",
               (unsigned long)sz);
        read(out, 128);
        return 1;
    }
    printf("  [-] no \n");
    return 0;
}


int main(int argc, wchar_t *argv[])
{
    printf("\n============================================================\n");
    printf("  WerEnc.dll LOLBin Encryption Primitive - Probe PoC\n");
    printf("  0xsp Labs 0xsp.com - Mr.Z @zux0x3a \n");
    printf("============================================================\n\n");

    enableDebugPriv();
    AddVectoredExceptionHandler(1, ProbeVEH);

   
    HMODULE hEnc = LoadLibraryW(L"WerEnc.dll");
    if (!hEnc) hEnc = LoadLibraryW(L"C:\\Windows\\System32\\WerEnc.dll"); //ghosted and living alone 
    if (!hEnc) {
        printf("[!] cannot load WerEnc.dll (error %lu)\n",
               (unsigned long)GetLastError());
        printf("    present on Windows 10 1607+ and all Windows 11\n");
        return 1;
    }

    FARPROC pEncFile   = resolveExport(hEnc, "EncryptDumpFile", 1);
    FARPROC pEncStream = resolveExport(hEnc, "EncryptDumpStream", 2);

    printf("[*] WerEnc.dll loaded\n");
    printf("[*] EncryptDumpFile:   %s (%p)\n",
           pEncFile ? "FOUND" : "NOT FOUND", (void *)pEncFile);
    printf("[*] EncryptDumpStream: %s (%p)\n",
           pEncStream ? "FOUND" : "NOT FOUND", (void *)pEncStream);

    if (!pEncFile && !pEncStream) {
        printf("[!] no exports found\n");
        FreeLibrary(hEnc);
        return 1;
    }

    /* Prepare test data */
    wchar_t testIn[MAX_PATH]   = L".\\werenc_test_input.bin";
    wchar_t testOut[MAX_PATH]  = L".\\werenc_test_output.enc";
    wchar_t testOut2[MAX_PATH] = L".\\werenc_test_stream.enc";

    const wchar_t *inputFile = testIn;
    if (argc > 1) {
        inputFile = argv[1];
        wprintf(L"[*] user input: %s\n", inputFile);
    } else {
        printf("[*] creating synthetic MDMP test file (4096 bytes)...\n");
        unsigned char buf[4096];
        memset(buf, 0, sizeof(buf));
        buf[0]='M'; buf[1]='D'; buf[2]='M'; buf[3]='P';
        buf[4]=0x93; buf[5]=0xa7;
        for (int i = 8; i < (int)sizeof(buf); i++)
            buf[i] = (unsigned char)(i & 0xFF);
        createTestFile(testIn, buf, sizeof(buf));
    }


    printf("\n============================================================\n");
    printf("  Phase 1: Signature Discovery\n");
    printf("============================================================\n");

    int fileOk = 0, streamOk = 0;

   
    if (!fileOk) fileOk = probe_EDF_paths(hEnc, inputFile, testOut);
    if (!fileOk) fileOk = probe_EDF_handles(hEnc, inputFile, testOut);
    if (!fileOk) fileOk = probe_EDF_paths_flags(hEnc, inputFile, testOut);
    if (!fileOk) fileOk = probe_EDF_handles_flags(hEnc, inputFile, testOut);

    if (fileOk)
        printf("\n  >>> EncryptDumpFile signature discovered <<<\n");
    else
        printf("\n  EncryptDumpFile: no probe succeeded \n");

    
    if (!streamOk) streamOk = probe_EDS_buffers(hEnc);
    if (!streamOk) streamOk = probe_EDS_handles(hEnc, inputFile, testOut2);
    if (!streamOk) streamOk = probe_EDS_handles_flags(hEnc, inputFile, testOut2);

    if (streamOk)
        printf("\n  >>> EncryptDumpStream signature DISCOVERED <<<\n");
    else
        printf("\n  EncryptDumpStream: no probe succeeded\n");


    printf("\n============================================================\n");
    printf("  Summary\n");
    printf("============================================================\n\n");

    if (fileOk || streamOk) {
        printf("  [+] WerEnc.dll is available\n");
   
    
    } else {
        printf("  [-] probes did not discover a working signature\n");
      
    }

    printf("\n");
    FreeLibrary(hEnc);
    return 0;
}
