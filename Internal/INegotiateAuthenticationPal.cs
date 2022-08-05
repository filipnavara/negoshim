using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Internal
{
    internal interface INegotiateAuthenticationPal
    {
        bool IsAuthenticated { get; }
        bool IsSigned { get; }
        bool IsEncrypted { get; }
        bool IsMutuallyAuthenticated { get; }
        string Package { get; }
        string? TargetName { get; }
        IIdentity RemoteIdentity { get; }
        TokenImpersonationLevel ImpersonationLevel { get; }

        byte[]? GetOutgoingBlob(ReadOnlySpan<byte> incomingBlob, out NegotiateAuthenticationStatusCode statusCode);

        NegotiateAuthenticationStatusCode Wrap(ReadOnlySpan<byte> input, IBufferWriter<byte> outputWriter, bool requestEncryption, out bool isEncrypted);
        NegotiateAuthenticationStatusCode Unwrap(ReadOnlySpan<byte> input, IBufferWriter<byte> outputWriter, out bool wasEncrypted);
        NegotiateAuthenticationStatusCode UnwrapInPlace(Span<byte> input, out int unwrappedOffset, out int unwrappedLength, out bool wasEncrypted);
    }
}
