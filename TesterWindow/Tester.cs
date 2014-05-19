using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;


namespace TesterWindow
{
    public class Tester
    {

        [DllImport("Loader.dll")]
        private static unsafe extern uint Load(string exe, string dll, string func, void* dllData, int dataLen, out uint pid);

        [DllImport("Crypt.dll")]
        private static unsafe extern IntPtr GetSharedAddress();

        [DllImport("Crypt.dll")]
        private static unsafe extern void Log(char* msg);

        [DllImport("Crypt.dll")]
        private static unsafe extern void LogPacket(char* msg, char* packet, int packetlen);

        [DllImport("Crypt.dll")]
        private static unsafe extern void WaitForWindow(int pid);

        [DllImport("Crypt.dll")]
        private static unsafe extern void SetServer(uint ip, ushort port);

        [DllImport("Crypt.dll")]
        private static unsafe extern int InstallLibrary(IntPtr thisWnd, int procid, int features);

        [DllImport("Crypt.dll")]
        internal static unsafe extern int GetPacketLength(byte* data, int bufLen);

        [DllImport("Crypt.dll")]
        internal static unsafe extern int GetClientPacketLength(byte* data, int bufLen);

        [DllImport("Crypt.dll")]
        internal static unsafe extern bool IsDynLength(byte packetId);

        [DllImport("Crypt.dll")]
        private static unsafe extern IntPtr GetCommMutex();

        [DllImport("Crypt.dll")]
        public static unsafe extern string GetUOVersion();

        [DllImport("msvcrt.dll")]
        internal static unsafe extern void memcpy(void* to, void* from, int len);



        private const int SHARED_BUFF_SIZE = 524288; // 262144; // 250k

        [StructLayout(LayoutKind.Explicit, Size = 8 + SHARED_BUFF_SIZE)]
        private struct Buffer
        {
            [FieldOffset(0)]
            public int Length;
            [FieldOffset(4)]
            public int Start;
            [FieldOffset(8)]
            public byte Buff0;
        }

        static unsafe byte* baseAddr;
        static Mutex CommMutex;

        public unsafe static void Launch(IntPtr hWnd)
        {
            uint pid = 0;
            Load(@"C:\Users\John\Desktop\UO-Patched\client.exe", @"C:\Users\John\Documents\Visual Studio 2012\Projects\RazorRE\Output\crypt.dll", "OnAttach", null, 0, out pid);
            WaitForWindow((int)pid);

            InstallLibrary(hWnd, (int)pid, 0);
            IPAddress srv = IPAddress.Parse("127.0.0.1");
            uint address = (uint)srv.Address;
            ushort port = 2593;

            SetServer(address, port);
            CommMutex = new Mutex();
            CommMutex.Handle = GetCommMutex();
            baseAddr = (byte*)GetSharedAddress().ToPointer();

            Buffer* m_InRecv = (Buffer*)baseAddr;
            Buffer* m_InSend = (Buffer*)((char*)baseAddr + 1048592);
        }

        internal static bool OnMessage(Form1 razor, uint wParam, int lParam)
        {
            switch (wParam)
            {
                case 1:
                    {
                        OnSend();
                        break;
                    }
                case 2:
                    {
                        OnRecv();
                        break;
                    }
            }
            return true;
        }

        static unsafe void OnSend()
        {
            CommMutex.WaitOne();
            Buffer* inBuff = (Buffer*)(baseAddr + sizeof(Buffer) * 2);
            Buffer* outBuff = (Buffer*)(baseAddr + sizeof(Buffer) * 3);

            while (inBuff->Length > 0)
            {
                byte* buff = (&inBuff->Buff0) + inBuff->Start;

                byte packetid = buff[0];

                int len = GetClientPacketLength(buff, inBuff->Length);
                if (len > inBuff->Length || len <= 0)
                {
                    break;
                }

                string msg = "Client -> Server";

                fixed (byte* ptr = System.Text.Encoding.ASCII.GetBytes(msg))
                {
                    LogPacket((char*)ptr, (char*)buff, len);
                }

                inBuff->Start += len;
                inBuff->Length -= len;

                CopyToBuffer(outBuff, buff, len);

            }
            CommMutex.ReleaseMutex();
        }

        private unsafe static void CopyToBuffer(Buffer* buffer, byte* data, int len)
        {
            memcpy((&buffer->Buff0) + buffer->Start + buffer->Length, data, len);
            buffer->Length += len;
        }

        static unsafe void OnRecv()
        {
            CommMutex.WaitOne();
            Buffer* inBuff = (Buffer*)baseAddr;
            Buffer* outBuff = (Buffer*)(baseAddr + sizeof(Buffer));
            while (inBuff->Length > 0)
            {
                byte* buff = (&inBuff->Buff0) + inBuff->Start;

                byte packetid = buff[0];

                int len = GetPacketLength(buff, inBuff->Length);
                string msg = "Server -> Client";
                if (len > inBuff->Length || len <= 0)
                {
                    fixed (byte* ptr = System.Text.Encoding.ASCII.GetBytes(String.Format("Mismatched length: ID = {0:X}, Expected = {1}, Len = {2}\r\n", buff[0], len, inBuff->Length)))
                    {
                        Log((char*)ptr);
                    }                    
                    break;
                }

                fixed (byte* ptr = System.Text.Encoding.ASCII.GetBytes(msg))
                {
                    LogPacket((char*)ptr, (char*)buff, len);
                }

                inBuff->Start += len;
                inBuff->Length -= len;

                CopyToBuffer(outBuff, buff, len);
            }
            CommMutex.ReleaseMutex();
        }
    }
}
