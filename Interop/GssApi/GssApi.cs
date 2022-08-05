using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace NegotiateAuthenticationShim.Interop.GssApi
{
    class GssApi
    {
        static GssApi()
        {
            NativeLibrary.SetDllImportResolver(typeof(GssApi).Assembly, DllImportResolver);
        }

        private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            IntPtr libraryHandle = IntPtr.Zero;
            if (libraryName == "gssapi")
            {
                // TODO: Other lib names/locations
                libraryHandle = NativeLibrary.Load("libgssapi_krb5.so.2", assembly, searchPath);
            }
            return libraryHandle;
        }

        // 1.2.840.113554.1.2.1.4
        public static ReadOnlySpan<byte> GSS_C_NT_HOSTBASED_SERVICE => new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x04 };

        // 1.2.840.113554.1.2.1.1
        public static ReadOnlySpan<byte> GSS_C_NT_USER_NAME => new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x01, 0x01 };

        // 1.2.840.113554.1.2.2
        public static ReadOnlySpan<byte> GSS_KRB5_MECHANISM => new byte[] { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 };

        // 1.3.6.1.4.1.311.2.2.10
        public static ReadOnlySpan<byte> GSS_NTLM_MECHANISM => new byte[] { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A };

        // 1.3.6.1.5.5.2
        public static ReadOnlySpan<byte> GSS_SPNEGO_MECHANISM => new byte[] { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 };

        [DllImport("gssapi", EntryPoint = "gss_create_empty_oid_set")]
        internal static extern GssStatus CreateEmptyOidSet(
            out uint minorStatus,
            out SafeGssapiOidSetHandle targetSet);

        [DllImport("gssapi", EntryPoint = "gss_add_oid_set_member")]
        private static unsafe extern GssStatus AddOidSetMember(
            out uint minorStatus,
            void* member,
            ref SafeGssapiOidSetHandle targetSet);

        internal static unsafe GssStatus AddOidSetMember(
            out uint minorStatus,
            ReadOnlySpan<byte> memberOid,
            ref SafeGssapiOidSetHandle targetSet)
        {
            fixed (byte* memberOidPtr = memberOid)
            {
                if (OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
                {
                    GssOidTwoPack oid = new() { Length = (uint)memberOid.Length, Elements = memberOidPtr };
                    return AddOidSetMember(out minorStatus, &oid, ref targetSet);
                }
                else
                {
                    GssOid oid = new() { Length = (uint)memberOid.Length, Elements = memberOidPtr };
                    return AddOidSetMember(out minorStatus, &oid, ref targetSet);
                }
            }
        }

        [DllImport("gssapi", EntryPoint = "gss_release_oid_set")]
        internal static extern GssStatus ReleaseOidSet(
            out uint minorStatus,
            ref IntPtr targetSet);

        [DllImport("gssapi", EntryPoint = "gss_import_name")]
        private static unsafe extern GssStatus ImportName(
            out uint minorStatus,
            in GssBuffer inputBuffer,
            void* nameType,
            out SafeGssapiNameHandle outputName);

        internal static unsafe GssStatus ImportName(
            out uint minorStatus,
            ReadOnlySpan<byte> name,
            ReadOnlySpan<byte> nameTypeOid,
            out SafeGssapiNameHandle outputName)
        {
            fixed (byte* namePtr = name)
            fixed (byte* nameTypeOidPtr = nameTypeOid)
            {
                GssBuffer inputBuffer = new() { Length = name.Length, Value = namePtr };
                if (OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
                {
                    GssOidTwoPack oid = new() { Length = (uint)nameTypeOid.Length, Elements = nameTypeOidPtr };
                    return ImportName(out minorStatus, inputBuffer, &oid, out outputName);
                }
                else
                {
                    GssOid oid = new() { Length = (uint)nameTypeOid.Length, Elements = nameTypeOidPtr };
                    return ImportName(out minorStatus, inputBuffer, &oid, out outputName);
                }
            }
        }

        [DllImport("gssapi", EntryPoint = "gss_display_name")]
        private static unsafe extern GssStatus DisplayName(
            out uint minorStatus,
            SafeGssapiNameHandle inputName,
            ref GssBuffer outputNameBuffer,
            ref void* nameType);

        internal static unsafe GssStatus DisplayName(
            out uint minorStatus,
            SafeGssapiNameHandle inputName,
            out byte[] outputName,
            out ReadOnlySpan<byte> nameTypeOid)
        {
            GssBuffer outputNameBuffer = new GssBuffer();
            void* nameType = null;
            GssStatus status = DisplayName(out minorStatus, inputName, ref outputNameBuffer, ref nameType);
            if (OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
            {
                nameTypeOid = nameType != null ?
                    new ReadOnlySpan<byte>(((GssOidTwoPack*)nameType)->Elements, (int)((GssOidTwoPack*)nameType)->Length) :
                    default;
            }
            else
            {
                nameTypeOid = nameType != null ?
                    new ReadOnlySpan<byte>(((GssOid*)nameType)->Elements, (int)((GssOid*)nameType)->Length) :
                    default;
            }
            outputName = new ReadOnlySpan<byte>(outputNameBuffer.Value, (int)outputNameBuffer.Length).ToArray();
            ReleaseBuffer(out _, ref outputNameBuffer);
            return status;
        }

        [DllImport("gssapi", EntryPoint = "gss_release_name")]
        internal static extern GssStatus ReleaseName(
            out uint minorStatus,
            ref IntPtr name);

        [DllImport("gssapi", EntryPoint = "gss_acquire_cred")]
        internal static unsafe extern GssStatus AcquireCredential(
            out uint minorStatus,
            SafeGssapiNameHandle desiredName,
            uint ttl,
            SafeGssapiOidSetHandle desiredMechanisms,
            GssCredentialUsage credentialUsage,
            out SafeGssapiCredentialHandle outputCredentialHandle,
            out SafeGssapiOidSetHandle actualMechanisms,
            out uint actualTtl);

        [DllImport("gssapi", EntryPoint = "gss_acquire_cred_with_password")]
        private static unsafe extern GssStatus AcquireCredentialWithPassword(
            out uint minorStatus,
            SafeGssapiNameHandle desiredName,
            in GssBuffer password,
            uint ttl,
            SafeGssapiOidSetHandle desiredMechanisms,
            GssCredentialUsage credentialUsage,
            out SafeGssapiCredentialHandle outputCredentialHandle,
            out SafeGssapiOidSetHandle actualMechanisms,
            out uint actualTtl);

        internal static unsafe GssStatus AcquireCredentialWithPassword(
            out uint minorStatus,
            SafeGssapiNameHandle desiredName,
            ReadOnlySpan<byte> password,
            uint ttl,
            SafeGssapiOidSetHandle desiredMechanisms,
            GssCredentialUsage credentialUsage,
            out SafeGssapiCredentialHandle outputCredentialHandle,
            out SafeGssapiOidSetHandle actualMechanisms,
            out uint actualTtl)
        {
            fixed (byte* passwordPtr = password)
            {
                GssBuffer passwordBuffer = new() { Length = password.Length, Value = passwordPtr };
                return AcquireCredentialWithPassword(
                    out minorStatus,
                    desiredName,
                    passwordBuffer,
                    ttl,
                    desiredMechanisms,
                    credentialUsage,
                    out outputCredentialHandle,
                    out actualMechanisms,
                    out actualTtl);
            }
        }

        [DllImport("gssapi", EntryPoint = "gss_release_cred")]
        internal static extern GssStatus ReleaseCredential(
            out uint minorStatus,
            ref IntPtr credentialHandle);

        [DllImport("gssapi", EntryPoint = "gss_release_buffer")]
        private static unsafe extern GssStatus ReleaseBuffer(
            out uint minorStatus,
            ref GssBuffer bufferPtr);

        [DllImport("gssapi", EntryPoint = "gss_init_sec_context")]
        private static unsafe extern GssStatus InitializeSecurityContext(
            out uint minorStatus,
            SafeGssapiCredentialHandle credentialHandle,
            ref SafeGssapiSecurityContextHandle contextHandle,
            SafeGssapiNameHandle targetName,
            void* mechanismType,
            GssContextFlags requestedFlags,
            uint timeRequested,
            IntPtr channelBinding,
            in GssBuffer inputToken,
            ref void* actualMechanism,
            ref GssBuffer outputToken,
            out GssContextFlags returnedFlags,
            out uint timeReceived);

        internal static unsafe GssStatus InitializeSecurityContext(
            out uint minorStatus,
            SafeGssapiCredentialHandle credentialHandle,
            ref SafeGssapiSecurityContextHandle contextHandle,
            SafeGssapiNameHandle targetName,
            ReadOnlySpan<byte> mechanismTypeOid,
            GssContextFlags requestedFlags,
            uint timeRequested,
            ChannelBinding? channelBinding,
            ReadOnlySpan<byte> inputToken,
            out ReadOnlySpan<byte> actualMechanismOid,
            out byte[] outputToken,
            out GssContextFlags returnedFlags,
            out uint timeReceived)
        {
            bool releaseChannelBinding = false;
            try
            {
                channelBinding?.DangerousAddRef(ref releaseChannelBinding);
                fixed (byte* mechanismTypeOidPtr = mechanismTypeOid)
                fixed (byte* inputTokenPtr = inputToken)
                {
                    GssBuffer inputTokenBuffer = new() { Length = inputToken.Length, Value = inputTokenPtr };
                    GssBuffer outputTokenBuffer = new();
                    GssStatus status;
                    if (OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
                    {
                        GssOidTwoPack mechanismType = new() { Length = (uint)mechanismTypeOid.Length, Elements = mechanismTypeOidPtr };
                        void* mechanismTypeOut = null;
                        status = InitializeSecurityContext(
                            out minorStatus,
                            credentialHandle,
                            ref contextHandle,
                            targetName,
                            &mechanismType,
                            requestedFlags,
                            timeRequested,
                            channelBinding?.DangerousGetHandle() ?? IntPtr.Zero,
                            inputTokenBuffer,
                            ref mechanismTypeOut,
                            ref outputTokenBuffer,
                            out returnedFlags,
                            out timeReceived);
                        actualMechanismOid = mechanismTypeOut != null ?
                            new ReadOnlySpan<byte>(((GssOidTwoPack*)mechanismTypeOut)->Elements, (int)((GssOidTwoPack*)mechanismTypeOut)->Length) :
                            default;
                    }
                    else
                    {
                        GssOid mechanismType = new() { Length = (uint)mechanismTypeOid.Length, Elements = mechanismTypeOidPtr };
                        void* mechanismTypeOut = null;
                        status = InitializeSecurityContext(
                            out minorStatus,
                            credentialHandle,
                            ref contextHandle,
                            targetName,
                            &mechanismType,
                            requestedFlags,
                            timeRequested,
                            channelBinding?.DangerousGetHandle() ?? IntPtr.Zero,
                            inputTokenBuffer,
                            ref mechanismTypeOut,
                            ref outputTokenBuffer,
                            out returnedFlags,
                            out timeReceived);
                        actualMechanismOid = mechanismTypeOut != null ?
                            new ReadOnlySpan<byte>(((GssOid*)mechanismTypeOut)->Elements, (int)((GssOid*)mechanismTypeOut)->Length) :
                            default;
                    }
                    outputToken = new ReadOnlySpan<byte>(outputTokenBuffer.Value, (int)outputTokenBuffer.Length).ToArray();
                    ReleaseBuffer(out _, ref outputTokenBuffer);
                    return status;
                }
            }
            finally
            {
                if (releaseChannelBinding)
                {
                    channelBinding!.DangerousRelease();
                }
            }
        }

        [DllImport("gssapi", EntryPoint = "gss_accept_sec_context")]
        private static unsafe extern GssStatus AcceptSecurityContext(
            out uint minorStatus,
            ref SafeGssapiSecurityContextHandle contextHandle,
            SafeGssapiCredentialHandle acceptorCredentialHandle,
            in GssBuffer inputToken,
            IntPtr channelBinding,
            SafeGssapiNameHandle sourceName,
            ref void* actualMechanism,
            ref GssBuffer outputToken,
            out GssContextFlags returnedFlags,
            out int timeReceived,
            ref SafeGssapiCredentialHandle delegatedCredentialHandle);

        internal static unsafe GssStatus AcceptSecurityContext(
            out uint minorStatus,
            ref SafeGssapiSecurityContextHandle contextHandle,
            SafeGssapiCredentialHandle acceptorCredentialHandle,
            ReadOnlySpan<byte> inputToken,
            ChannelBinding? channelBinding,
            SafeGssapiNameHandle sourceName,
            out ReadOnlySpan<byte> actualMechanismOid,
            out byte[] outputToken,
            out GssContextFlags returnedFlags,
            out int timeReceived,
            ref SafeGssapiCredentialHandle delegatedCredentialHandle)
        {
            bool releaseChannelBinding = false;
            try
            {
                channelBinding?.DangerousAddRef(ref releaseChannelBinding);
                fixed (byte* inputTokenPtr = inputToken)
                {
                    GssBuffer inputTokenBuffer = new() { Length = inputToken.Length, Value = inputTokenPtr };
                    GssBuffer outputTokenBuffer = new();
                    GssStatus status;
                    void* mechanismTypeOut = null;
                    status = AcceptSecurityContext(
                        out minorStatus,
                        ref contextHandle,
                        acceptorCredentialHandle,
                        inputTokenBuffer,
                        channelBinding?.DangerousGetHandle() ?? IntPtr.Zero,
                        sourceName,
                        ref mechanismTypeOut,
                        ref outputTokenBuffer,
                        out returnedFlags,
                        out timeReceived,
                        ref delegatedCredentialHandle);
                    if (OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture != Architecture.Arm64)
                    {
                        actualMechanismOid = mechanismTypeOut != null ?
                            new ReadOnlySpan<byte>(((GssOidTwoPack*)mechanismTypeOut)->Elements, (int)((GssOidTwoPack*)mechanismTypeOut)->Length) :
                            default;
                    }
                    else
                    {
                        actualMechanismOid = mechanismTypeOut != null ?
                            new ReadOnlySpan<byte>(((GssOid*)mechanismTypeOut)->Elements, (int)((GssOid*)mechanismTypeOut)->Length) :
                            default;
                    }
                    outputToken = new ReadOnlySpan<byte>(outputTokenBuffer.Value, (int)outputTokenBuffer.Length).ToArray();
                    ReleaseBuffer(out _, ref outputTokenBuffer);
                    return status;
                }
            }
            finally
            {
                if (releaseChannelBinding)
                {
                    channelBinding!.DangerousRelease();
                }
            }
        }

        [DllImport("gssapi", EntryPoint = "gss_release_sec_context")]
        internal static unsafe extern GssStatus ReleaseSecurityContext(
            out uint minorStatus,
            ref IntPtr securityContextHandle);

        [DllImport("gssapi", EntryPoint = "gss_wrap")]
        private static unsafe extern GssStatus Wrap(
            out uint minorStatus,
            SafeGssapiSecurityContextHandle contextHandle,
            int confidentialityRequired,
            int qopRequired,
            ref GssBuffer inputMessage,
            out int confidentialityState,
            ref GssBuffer outputMessage);

        internal static unsafe GssStatus Wrap(
            out uint minorStatus,
            SafeGssapiSecurityContextHandle contextHandle,
            int confidentialityRequired,
            int qopRequired,
            ReadOnlySpan<byte> inputMessage,
            out int confidentialityState,
            IBufferWriter<byte> outputWriter)
        {
            fixed (byte* inputMessagePtr = inputMessage)
            {
                GssBuffer inputMessageBuffer = new() { Length = inputMessage.Length, Value = inputMessagePtr };
                GssBuffer outputMessageBuffer = new();
                GssStatus status;
                status = Wrap(
                    out minorStatus,
                    contextHandle,
                    confidentialityRequired,
                    qopRequired,
                    ref inputMessageBuffer,
                    out confidentialityState,
                    ref outputMessageBuffer);
                if (status == GssStatus.Completed)
                {
                    var outputMessage = new ReadOnlySpan<byte>(outputMessageBuffer.Value, (int)outputMessageBuffer.Length);
                    outputMessage.CopyTo(outputWriter.GetSpan(outputMessage.Length));
                    outputWriter.Advance(outputMessage.Length);
                }
                ReleaseBuffer(out _, ref outputMessageBuffer);
                return status;
            }
        }

        [DllImport("gssapi", EntryPoint = "gss_unwrap")]
        private static unsafe extern GssStatus Unwrap(
            out uint minorStatus,
            SafeGssapiSecurityContextHandle contextHandle,
            ref GssBuffer inputMessage,
            ref GssBuffer outputMessage,
            out int confidentialityState,
            out int qopState);

        internal static unsafe GssStatus Unwrap(
            out uint minorStatus,
            SafeGssapiSecurityContextHandle contextHandle,
            ReadOnlySpan<byte> inputMessage,
            IBufferWriter<byte> outputWriter,
            out int confidentialityState,
            out int qopState)
        {
            fixed (byte* inputMessagePtr = inputMessage)
            {
                GssBuffer inputMessageBuffer = new() { Length = inputMessage.Length, Value = inputMessagePtr };
                GssBuffer outputMessageBuffer = new();
                GssStatus status;
                status = Unwrap(
                    out minorStatus,
                    contextHandle,
                    ref inputMessageBuffer,
                    ref outputMessageBuffer,
                    out confidentialityState,
                    out qopState);
                if (status == GssStatus.Completed)
                {
                    var outputMessage = new ReadOnlySpan<byte>(outputMessageBuffer.Value, (int)outputMessageBuffer.Length);
                    outputMessage.CopyTo(outputWriter.GetSpan(outputMessage.Length));
                    outputWriter.Advance(outputMessage.Length);
                }
                ReleaseBuffer(out _, ref outputMessageBuffer);
                return status;
            }
        }
    }
}
