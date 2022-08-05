using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    [StructLayout(LayoutKind.Sequential)]
    unsafe ref struct GssOid
    {
        public uint Length;
        public byte* Elements;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    unsafe ref struct GssOidTwoPack
    {
        public uint Length;
        public byte* Elements;
    }
}
