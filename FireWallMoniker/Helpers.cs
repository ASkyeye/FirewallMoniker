using System;
using System.Collections;
using System.Runtime.InteropServices;

namespace FireWallMoniker
{
    internal class Helpers
    {
        #region Structures

        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public int InheritedFromUniqueProcessId;

            public int Size => Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Reserved1;
            public Byte BeingDebugged;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public Byte[] Reserved2;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public IntPtr[] Reserved3;
            public IntPtr Ldr;
            public IntPtr ProcessParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public IntPtr[] Reserved4;
            public IntPtr AtlThunkSListPtr;
            public IntPtr Reserved5;
            public ulong Reserved6;
            public IntPtr Reserved7;
            public ulong Reserved8;
            public ulong AtlThunkSListPtr32;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 45)]
            public IntPtr[] Reserved9;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public Byte[] Reserved10;
            public IntPtr PostProcessInitRoutine;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
            public Byte[] Reserved11;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public IntPtr[] Reserved12;
            public ulong SessionId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct PEB_LDR_DATA
        {
            public UInt32 Length;
            public UInt32 Initialized;
            public UInt64 SsHandleIntPtr;
            public LIST_ENTRY InLoadOrderModuleList;
            public LIST_ENTRY InMemoryOrderModuleList;
            public LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public LIST_ENTRY InLoadOrderLinks;
            public LIST_ENTRY InMemoryOrderLinks;
            public LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public IntPtr SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BIND_OPTS3
        {
            public uint cbStruct;
            public int grfFlags;
            public int grfMode;
            public int dwTickCountDeadline;
            public int dwTrackFlags;
            public CLSCTX dwClassContext;
            public int locale;
            public IntPtr pServerInfo;
            public IntPtr hwnd; // HWND is a pointer
        }

        #endregion

        #region Enums

        [Flags]
        public enum CLSCTX : int
        {
            CLSCTX_INPROC_SERVER = 0x1,
            CLSCTX_INPROC_HANDLER = 0x2,
            CLSCTX_LOCAL_SERVER = 0x4,
            CLSCTX_REMOTE_SERVER = 0x10,
            CLSCTX_ALL = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER
        }

        public enum NET_FW_PROFILE_TYPE2_
        {
            NET_FW_PROFILE2_DOMAIN = 1,
            NET_FW_PROFILE2_PRIVATE = 2,
            NET_FW_PROFILE2_PUBLIC = 4,
            NET_FW_PROFILE2_ALL = 2147483647
        }

        public enum NET_FW_RULE_DIRECTION_
        {
            NET_FW_RULE_DIR_IN = 1,
            NET_FW_RULE_DIR_MAX = 3,
            NET_FW_RULE_DIR_OUT = 2
        }

        public enum NET_FW_ACTION_
        {
            NET_FW_ACTION_BLOCK,
            NET_FW_ACTION_ALLOW,
            NET_FW_ACTION_MAX
        }

        public enum NET_FW_MODIFY_STATE_
        {
            NET_FW_MODIFY_STATE_OK,
            NET_FW_MODIFY_STATE_GP_OVERRIDE,
            NET_FW_MODIFY_STATE_INBOUND_BLOCKED
        }

        #endregion

        #region COM Interfaces

        [ComImport, Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
        public interface INetFwPolicy2
        {
            [DispId(1)]
            int CurrentProfileTypes { get; }

            [DispId(2)]
            bool get_FirewallEnabled(NET_FW_PROFILE_TYPE2_ profileType);

            [DispId(2)]
            void put_FirewallEnabled(NET_FW_PROFILE_TYPE2_ profileType, bool enabled);

            [DispId(3)]
            object ExcludedInterfaces { get; set; }

            [DispId(4)]
            bool BlockAllInboundTraffic { get; set; }

            [DispId(5)]
            bool NotificationsDisabled { get; set; }

            [DispId(6)]
            bool UnicastResponsesToMulticastBroadcastDisabled { get; set; }

            [DispId(7)]
            INetFwRules Rules { get; }

            [DispId(8)]
            INetFwServiceRestriction ServiceRestriction { get; }

            [DispId(12)]
            NET_FW_ACTION_ DefaultInboundAction { get; set; }

            [DispId(13)]
            NET_FW_ACTION_ DefaultOutboundAction { get; set; }

            [DispId(14)]
            bool IsRuleGroupCurrentlyEnabled { get; }

            [DispId(15)]
            NET_FW_MODIFY_STATE_ LocalPolicyModifyState { get; }

            [DispId(9)]
            void EnableRuleGroup(int profileTypesBitmask, string group, bool enable);

            [DispId(10)]
            bool IsRuleGroupEnabled(int profileTypesBitmask, string group);

            [DispId(11)]
            void RestoreLocalFirewallDefaults();
        }

        [ComImport, Guid("8267BBE3-F890-491C-B7B6-2DB1EF0E5D2B")]
        public interface INetFwServiceRestriction
        {
            [DispId(1)]
            void RestrictService(string serviceName, string appName, bool RestrictService, bool serviceSidRestricted);

            [DispId(2)]
            bool ServiceRestricted(string serviceName, string appName);

            [DispId(3)]
            INetFwRules Rules { get; }
        }

        [ComImport, Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
        public interface INetFwRules : IEnumerable
        {
            [DispId(1)]
            int Count { get; }

            [DispId(2)]
            void Add(INetFwRule rule);

            [DispId(3)]
            void Remove(string Name);

            [DispId(4)]
            NetFwRule Item(string Name);
        }

        [ComImport, Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2"), CoClass(typeof(NetFwRuleClass))]
        public interface NetFwRule : INetFwRule
        {
        }

        [ComImport, Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
        public interface INetFwRule
        {
            [DispId(1)]
            string Name { get; set; }

            [DispId(2)]
            string Description { get; set; }

            [DispId(3)]
            string ApplicationName { get; set; }

            [DispId(4)]
            string serviceName { get; set; }

            [DispId(5)]
            int Protocol { get; set; }

            [DispId(6)]
            string LocalPorts { get; set; }

            [DispId(7)]
            string RemotePorts { get; set; }

            [DispId(8)]
            string LocalAddresses { get; set; }

            [DispId(9)]
            string RemoteAddresses { get; set; }

            [DispId(10)]
            string IcmpTypesAndCodes { get; set; }

            [DispId(11)]
            NET_FW_RULE_DIRECTION_ Direction { get; set; }

            [DispId(12)]
            object Interfaces { get; set; }

            [DispId(13)]
            string InterfaceTypes { get; set; }

            [DispId(14)]
            bool Enabled { get; set; }

            [DispId(15)]
            string Grouping { get; set; }

            [DispId(16)]
            int Profiles { get; set; }

            [DispId(17)]
            bool EdgeTraversal { get; set; }

            [DispId(18)]
            NET_FW_ACTION_ Action { get; set; }
        }

        [ClassInterface(ClassInterfaceType.None), Guid("2C5BC43E-3369-4C33-AB0C-BE9469677AF4")]
        [ComImport]
        public class NetFwRuleClass : INetFwRule, NetFwRule
        {
            [DispId(1)]
            public virtual extern string Name { get; set; }

            [DispId(2)]
            public virtual extern string Description { get; set; }

            [DispId(3)]
            public virtual extern string ApplicationName { get; set; }

            [DispId(4)]
            public virtual extern string serviceName { get; set; }

            [DispId(5)]
            public virtual extern int Protocol { get; set; }

            [DispId(6)]
            public virtual extern string LocalPorts { get; set; }

            [DispId(7)]
            public virtual extern string RemotePorts { get; set; }

            [DispId(8)]
            public virtual extern string LocalAddresses { get; set; }

            [DispId(9)]
            public virtual extern string RemoteAddresses { get; set; }

            [DispId(10)]
            public virtual extern string IcmpTypesAndCodes { get; set; }

            [DispId(11)]
            public virtual extern NET_FW_RULE_DIRECTION_ Direction { get; set; }

            [DispId(12)]
            public virtual extern object Interfaces { get; set; }

            [DispId(13)]
            public virtual extern string InterfaceTypes { get; set; }

            [DispId(14)]
            public virtual extern bool Enabled { get; set; }

            [DispId(15)]
            public virtual extern string Grouping { get; set; }

            [DispId(16)]
            public virtual extern int Profiles { get; set; }

            [DispId(17)]
            public virtual extern bool EdgeTraversal { get; set; }

            [DispId(18)]
            public virtual extern NET_FW_ACTION_ Action { get; set; }
        }

        #endregion

        #region P/Invoke Methods

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("ole32", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        [return: MarshalAs(UnmanagedType.Interface)]
        public static extern object CoGetObject(string pszName, [In] ref BIND_OPTS3 pBindOptions, [In][MarshalAs(UnmanagedType.LPStruct)] Guid riid);

        [DllImport("ole32.dll")]
        public static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);

        [DllImport("ole32.dll")]
        public static extern void CoUninitialize();

        [DllImport("ntdll.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr RtlGetCurrentPeb();

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern void RtlInitUnicodeString(IntPtr desc, string str);

        [DllImport("ole32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int CoCreateInstance(
            ref Guid rclsid,
            IntPtr pUnkOuter,
            CLSCTX dwClsContext,
            ref Guid riid,
            [MarshalAs(UnmanagedType.Interface)] out object ppv
        );

        #endregion

        #region Constants

        public static readonly Guid CLSID_NetFwPolicy2 = new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD");
        public static readonly Guid IID_INetFwPolicy2 = new Guid("98325047-C671-4174-8D81-DEFCD3F03186");

        #endregion
    }
}
