using NegotiateAuthenticationShim.Internal;
using NegotiateAuthenticationShim.Interop.GssApi;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Security.Kerberos;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;
using System.Text;
using System.Threading.Tasks;


namespace NegotiateAuthenticationShim
{
    public class Program
    {
        [DllImport("libc", CharSet = CharSet.Ansi)]
        private static extern int setenv(string name, string value, bool overwrite);

        public static async Task Main()
        {
            setenv("KRB5_TRACE", "/dev/stdout", true);

            using var ke = new KerberosExecutor("OTHER.EMCLIENT.COM");
            ke.AddUser("bao", "gzYBDXEtgRVwH6n");
            ke.AddService("HOST/exchangetest.other.emclient.com");
            await ke.Invoke(() =>
            {
                var ntAuth = new GssApiNegotiateAuthenticationPal(new NegotiateAuthenticationClientOptions
                {
                    TargetName = "HOST@exchangetest.other.emclient.com",
                    Credential = new System.Net.NetworkCredential("bao@OTHER.EMCLIENT.COM", "gzYBDXEtgRVwH6n")
                });
                var serverAuth = new GssApiNegotiateAuthenticationPal(new NegotiateAuthenticationServerOptions { });

                var outputToken = ntAuth.GetOutgoingBlob(default, out NegotiateAuthenticationStatusCode status);
                Console.WriteLine(status);
                Console.WriteLine("outputToken " + Convert.ToHexString(outputToken ?? Array.Empty<byte>()));
                outputToken = serverAuth.GetOutgoingBlob(outputToken, out status);
                Console.WriteLine(status);
                Console.WriteLine("outputToken " + Convert.ToHexString(outputToken ?? Array.Empty<byte>()));
                outputToken = ntAuth.GetOutgoingBlob(outputToken, out status);



                var buffer = new ArrayBufferWriter<byte>();
                serverAuth.Wrap("foo"u8, buffer, false, out var isEncrypted);
                Console.WriteLine("outputWrap " + Convert.ToHexString(buffer.WrittenSpan));
                var unwrapBuffer = new ArrayBufferWriter<byte>();
                ntAuth.Unwrap(buffer.WrittenSpan, unwrapBuffer, out _);
                Console.WriteLine("outputUnwrap " + Convert.ToHexString(unwrapBuffer.WrittenSpan));
            });

            /*
            //Class1.gss_create_empty_oid_set(out int _, out _);
            var status = GssApi.CreateEmptyOidSet(out _, out SafeGssapiOidSetHandle desiredMechanisms);
            status = GssApi.AddOidSetMember(out _, GssApi.GSS_SPNEGO_MECHANISM, ref desiredMechanisms);
            Console.WriteLine(status);

            status = GssApi.ImportName(out _, "bao@OTHER.EMCLIENT.COM"u8, GssApi.GSS_C_NT_USER_NAME, out var userName);
            Console.WriteLine(status);

            status = GssApi.AcquireCredentialWithPassword(
                out _,
                userName,
                "gzYBDXEtgRVwH6n"u8,
                0,
                desiredMechanisms,
                GssCredentialUsage.Initiate,
                out var credentialHandle,
                out var actualMechanisms,
                out _);
            Console.WriteLine($"{status:x}");

            status = GssApi.ImportName(out _, "HOST@exchangetest.other.emclient.com"u8, GssApi.GSS_C_NT_HOSTBASED_SERVICE, out var targetName);
            Console.WriteLine(status);

            SafeGssapiSecurityContextHandle contextHandle = new();
            status = GssApi.InitializeSecurityContext(
                out _,
                credentialHandle,
                ref contextHandle,
                targetName,
                GssApi.GSS_SPNEGO_MECHANISM,
                0,
                0,
                null,
                default,
                out var mechanismOid,
                out var outputToken,
                out var contextFlags,
                out _);
            Console.WriteLine(status);
            Console.WriteLine("outputToken " + Convert.ToHexString(outputToken));




            credentialHandle.Dispose();
            actualMechanisms.Dispose();
            desiredMechanisms.Dispose();
*/
        }
    }
}
