﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    class SafeGssapiSecurityContextHandle : SafeHandle
    {
        public SafeGssapiSecurityContextHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            return GssApi.ReleaseSecurityContext(out _, ref handle) == GssStatus.Completed;
        }
    }
}
