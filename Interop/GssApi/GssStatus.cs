using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    [Flags]
    internal enum GssStatus : uint
    {
        Completed = 0,
        ContinueNeeded = 1,
        Unavailable = 16 << 16
    }
}
