using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    internal enum GssCredentialUsage : uint
    {
        Both = 0,
        Initiate = 1,
        Accept = 2,
    }
}
