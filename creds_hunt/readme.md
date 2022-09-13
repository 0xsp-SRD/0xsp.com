refer to the following CredUI flags if willing to change 
```
[Flags]
    private enum PromptForWindowsCredentialsFlags
    {
      /// <summary>
      /// The caller is requesting that the credential provider return the user name and password in plain text.
      /// This value cannot be combined with SECURE_PROMPT.
      /// </summary>
      CREDUIWIN_GENERIC = 0x1,
      /// <summary>
      /// The Save check box is displayed in the dialog box.
      /// </summary>
      CREDUIWIN_CHECKBOX = 0x2,
      /// <summary>
      /// Only credential providers that support the authentication package specified by the authPackage parameter should be enumerated.
      /// This value cannot be combined with CREDUIWIN_IN_CRED_ONLY.
      /// </summary>
      CREDUIWIN_AUTHPACKAGE_ONLY = 0x10,
      /// <summary>
      /// Only the credentials specified by the InAuthBuffer parameter for the authentication package specified by the authPackage parameter should be enumerated.
      /// If this flag is set, and the InAuthBuffer parameter is NULL, the function fails.
      /// This value cannot be combined with CREDUIWIN_AUTHPACKAGE_ONLY.
      /// </summary>
      CREDUIWIN_IN_CRED_ONLY = 0x20,
      /// <summary>
      /// Credential providers should enumerate only administrators. This value is intended for User Account Control (UAC) purposes only. We recommend that external callers not set this flag.
      /// </summary>
      CREDUIWIN_ENUMERATE_ADMINS = 0x100,
      /// <summary>
      /// Only the incoming credentials for the authentication package specified by the authPackage parameter should be enumerated.
      /// </summary>
      CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200,
      /// <summary>
      /// The credential dialog box should be displayed on the secure desktop. This value cannot be combined with CREDUIWIN_GENERIC.
      /// Windows Vista: This value is not supported until Windows Vista with SP1.
      /// </summary>
      CREDUIWIN_SECURE_PROMPT = 0x1000,
      /// <summary>
      /// The credential provider should align the credential BLOB pointed to by the refOutAuthBuffer parameter to a 32-bit boundary, even if the provider is running on a 64-bit system.
      /// </summary>
      CREDUIWIN_PACK_32_WOW = 0x10000000,
    }
```

and for LogonUser, refer to following logon types

```
const int LOGON32_LOGON_INTERACTIVE       = 2;
const int LOGON32_LOGON_NETWORK       = 3;
const int LOGON32_LOGON_BATCH         = 4;
const int LOGON32_LOGON_SERVICE       = 5;
const int LOGON32_LOGON_UNLOCK        = 7;
const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
const int LOGON32_LOGON_NEW_CREDENTIALS   = 9;


```
