using System.Reflection;
using System.Runtime.InteropServices;

namespace NegotiateAuthenticationShim;

[StructLayout(LayoutKind.Sequential)]
public struct gss_OID_set_desc
{
    public IntPtr count;
    public IntPtr elements;
}

public class Class1
{
    static Class1()
    {
        NativeLibrary.SetDllImportResolver(typeof(Class1).Assembly, DllImportResolver);
    }

    private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        IntPtr libraryHandle = IntPtr.Zero;
        if (libraryName == "gssapi")
        {
            libraryHandle = NativeLibrary.Load("libgssapi_krb5.so.2", assembly, searchPath);
        }
        return libraryHandle;
    }

    [DllImport("gssapi")]
    public static unsafe extern int gss_create_empty_oid_set(
        out int min_stat,
        out gss_OID_set_desc* target_set);
}
