using NegotiateAuthenticationShim.Interop.GssApi;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace NegotiateAuthenticationShim.Internal
{
    internal class GssApiNegotiateAuthenticationPal : INegotiateAuthenticationPal
    {
        private readonly SafeGssapiCredentialHandle _credential;
        private readonly SafeGssapiNameHandle _targetName;
        private SafeGssapiSecurityContextHandle _securityContext;
        private GssStatus _lastStatus;
        private GssContextFlags _contextFlags;
        private readonly ChannelBinding? _channelBinding;
        private readonly bool _isServer;
        private SafeGssapiCredentialHandle? _delegatedCredential;
        private string _package;

        public GssApiNegotiateAuthenticationPal(NegotiateAuthenticationClientOptions clientOptions)
        {
            _isServer = false;
            _channelBinding = clientOptions.Binding;
            _package = clientOptions.Package;

            _contextFlags = clientOptions.RequiredProtectionLevel switch
            {
                ProtectionLevel.EncryptAndSign => GssContextFlags.Confidentiality | GssContextFlags.Integrity,
                ProtectionLevel.Sign => GssContextFlags.Integrity,
                _ => 0
            };

            if (clientOptions.RequireMutualAuthentication)
            {
                _contextFlags |= GssContextFlags.Mutual;
            }

            if (clientOptions.AllowedImpersonationLevel == TokenImpersonationLevel.Delegation)
            {
                _contextFlags |= GssContextFlags.Delegation;
            }

            _securityContext = new SafeGssapiSecurityContextHandle();

            try
            {
                if (clientOptions.TargetName != null)
                {
                    _lastStatus = GssApi.ImportName(
                        out _,
                        Encoding.UTF8.GetBytes(clientOptions.TargetName),
                        GssApi.GSS_C_NT_HOSTBASED_SERVICE,
                        out _targetName);
                    if (_lastStatus != GssStatus.Completed)
                    {
                        return;
                    }
                }
                else
                {
                    _targetName = new SafeGssapiNameHandle();
                }

                _lastStatus = GssApi.ImportName(
                    out _,
                    Encoding.UTF8.GetBytes(clientOptions.Credential.UserName),
                    GssApi.GSS_C_NT_USER_NAME,
                    out SafeGssapiNameHandle userName);
                if (_lastStatus != GssStatus.Completed)
                {
                    return;
                }

                GssApi.CreateEmptyOidSet(out _, out SafeGssapiOidSetHandle desiredMechanisms);
                // FIXME: Check return value
                // FIXME: Case-insensitive? Oids?
                ReadOnlySpan<byte> mechanismOid = clientOptions.Package switch
                {
                    "Negotiate" => GssApi.GSS_SPNEGO_MECHANISM,
                    "Kerberos" => GssApi.GSS_KRB5_MECHANISM,
                    "NTLM" => GssApi.GSS_NTLM_MECHANISM,
                    _ => default // _lastStatus = GssStatus.Unavailable
                };
                GssApi.AddOidSetMember(out _, mechanismOid, ref desiredMechanisms);
                // FIXME: Check return value

                if (string.IsNullOrEmpty(clientOptions.Credential.Password))
                {
                    _lastStatus = GssApi.AcquireCredential(
                        out _,
                        userName,
                        uint.MaxValue,
                        desiredMechanisms,
                        GssCredentialUsage.Initiate,
                        out _credential,
                        out SafeGssapiOidSetHandle actualMechanisms,
                        out _);
                    actualMechanisms.Dispose();
                }
                else
                {
                    _lastStatus = GssApi.AcquireCredentialWithPassword(
                        out _,
                        userName,
                        Encoding.UTF8.GetBytes(clientOptions.Credential.Password),
                        uint.MaxValue,
                        desiredMechanisms,
                        GssCredentialUsage.Initiate,
                        out _credential,
                        out SafeGssapiOidSetHandle actualMechanisms,
                        out _);
                    actualMechanisms.Dispose();
                }
            }
            finally
            {
                if (_lastStatus != GssStatus.Completed)
                {
                    //userName.Dispose();
                    _credential?.Dispose();
                }
            }
        }

        public GssApiNegotiateAuthenticationPal(NegotiateAuthenticationServerOptions serverOptions)
        {
            _isServer = true;
            _channelBinding = serverOptions.Binding;
            _securityContext = new SafeGssapiSecurityContextHandle();
            _targetName = new SafeGssapiNameHandle();
            _delegatedCredential = new SafeGssapiCredentialHandle();
            _package = serverOptions.Package;

            var noOidSet = new SafeGssapiOidSetHandle();

            var userName = new SafeGssapiNameHandle();
            _lastStatus = GssApi.AcquireCredential(
                out _,
                userName,
                uint.MaxValue,
                noOidSet,
                GssCredentialUsage.Accept,
                out _credential,
                out SafeGssapiOidSetHandle actualMechanisms,
                out _);
            actualMechanisms.Dispose();
        }

        public bool IsAuthenticated => !_securityContext.IsInvalid && _lastStatus == GssStatus.Completed;

        public bool IsSigned => _contextFlags.HasFlag(GssContextFlags.Integrity);

        public bool IsEncrypted => _contextFlags.HasFlag(GssContextFlags.Confidentiality);

        public bool IsMutuallyAuthenticated => _contextFlags.HasFlag(GssContextFlags.Mutual);

        public string Package => _package;

        public string? TargetName => throw new NotImplementedException();

        public IIdentity RemoteIdentity => throw new NotImplementedException();

        public TokenImpersonationLevel ImpersonationLevel => throw new NotImplementedException();

        public byte[]? GetOutgoingBlob(ReadOnlySpan<byte> incomingBlob, out NegotiateAuthenticationStatusCode statusCode)
        {
            if (_lastStatus != GssStatus.Completed && _lastStatus != GssStatus.ContinueNeeded)
            {
                statusCode = GssStatusToNegotiateAuthenticationStatus(_lastStatus);
                return null;
            }

            byte[]? outputToken;
            ReadOnlySpan<byte> mechanismOid;
            if (!_isServer)
            {
                _lastStatus = GssApi.InitializeSecurityContext(
                    out _,
                    _credential,
                    ref _securityContext,
                    _targetName,
                    GssApi.GSS_SPNEGO_MECHANISM, // FIXME
                    _contextFlags,
                    0,
                    _channelBinding,
                    incomingBlob,
                    out mechanismOid,
                    out outputToken,
                    out _contextFlags,
                    out _);
            }
            else
            {
                _lastStatus = GssApi.AcceptSecurityContext(
                    out var minorStatus,
                    ref _securityContext,
                    _credential,
                    incomingBlob,
                    _channelBinding,
                    _targetName,
                    out mechanismOid,
                    out outputToken,
                    out _contextFlags,
                    out _,
                    ref _delegatedCredential!);
            }

            /*if (!_targetName.IsInvalid)
            {
                GssApi.DisplayName(out _, _targetName, out var sourceName, out var nameTypeOid);
            }*/

            if (_lastStatus == GssStatus.Completed)
            {
                if (mechanismOid.SequenceEqual(GssApi.GSS_NTLM_MECHANISM))
                {
                    _package = "NTLM";
                }
                else if (mechanismOid.SequenceEqual(GssApi.GSS_KRB5_MECHANISM))
                {
                    _package = "Kerberos";
                }
                else if (mechanismOid.SequenceEqual(GssApi.GSS_SPNEGO_MECHANISM))
                {
                    _package = "Negotiate";
                }
                else
                {
                    var lengthPrefixedMechanismOid = new byte[mechanismOid.Length + 2];
                    lengthPrefixedMechanismOid[0] = 6;
                    lengthPrefixedMechanismOid[1] = (byte)mechanismOid.Length;
                    mechanismOid.CopyTo(lengthPrefixedMechanismOid.AsSpan(2));
                    _package = AsnDecoder.ReadObjectIdentifier(lengthPrefixedMechanismOid, AsnEncodingRules.DER, out _);
                }
            }

            statusCode = GssStatusToNegotiateAuthenticationStatus(_lastStatus);
            return outputToken;
        }

        public NegotiateAuthenticationStatusCode Unwrap(ReadOnlySpan<byte> input, IBufferWriter<byte> outputWriter, out bool wasEncrypted)
        {
            Debug.Assert(!_securityContext.IsInvalid);
            Debug.Assert(IsAuthenticated);
            var gssStatus = GssApi.Unwrap(
                out _,
                _securityContext,
                input,
                outputWriter,
                out int confidentialityState,
                out _);
            wasEncrypted = confidentialityState > 0;
            return GssStatusToNegotiateAuthenticationStatus(gssStatus);
        }

        public NegotiateAuthenticationStatusCode UnwrapInPlace(Span<byte> input, out int unwrappedOffset, out int unwrappedLength, out bool wasEncrypted)
        {
            throw new NotImplementedException();
        }

        public NegotiateAuthenticationStatusCode Wrap(ReadOnlySpan<byte> input, IBufferWriter<byte> outputWriter, bool requestEncryption, out bool isEncrypted)
        {
            Debug.Assert(!_securityContext.IsInvalid);
            Debug.Assert(IsAuthenticated);
            var gssStatus = GssApi.Wrap(
                out _,
                _securityContext,
                requestEncryption ? 1 : 0,
                0,
                input,
                out int confidentialityState,
                outputWriter);
            isEncrypted = confidentialityState > 0;
            return GssStatusToNegotiateAuthenticationStatus(gssStatus);
        }

        private NegotiateAuthenticationStatusCode GssStatusToNegotiateAuthenticationStatus(GssStatus status)
        {
            return status switch
            {
                GssStatus.Completed => NegotiateAuthenticationStatusCode.Completed,
                GssStatus.ContinueNeeded => NegotiateAuthenticationStatusCode.ContinueNeeded,
                _ => NegotiateAuthenticationStatusCode.GenericFailure
            };
        }
    }
}
