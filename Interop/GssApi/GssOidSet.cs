using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    [StructLayout(LayoutKind.Sequential)]
    unsafe struct GssOidSet
    {
        nint count;
        void *elements;
    }
}
