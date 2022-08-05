using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    [Flags]
    internal enum GssContextFlags
    {
        Delegation = 1,
        Mutual = 2,
        Replay = 4,
        Sequence = 8,
        Confidentiality = 16,
        Integrity = 32,
        Anonymous = 64,
        ProtocolReady = 128,
        Transferable = 256,
        DelegationPolicy = 32768,
    }
}
