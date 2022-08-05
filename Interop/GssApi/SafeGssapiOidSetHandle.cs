using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    class SafeGssapiOidSetHandle : SafeHandle
    {
        public SafeGssapiOidSetHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GssApi.ReleaseOidSet(out _, ref handle) == GssStatus.Completed;
        }
    }
}
