
///I use powershell commands because there was no documentation on RegQueryInfoKey class parameter.
///I have not successfully extracted the right information by just using winapi.
///I hope in the future to make it fully Rust.

pub fn get_imports() -> String {
    return 
    r#"
try{
    & {
        $ErrorActionPreference = 'Stop'
        [void] [ntlmx.win32]
    }
} catch {
    Add-Type -TypeDefinition @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices;
        namespace ntlmx {
            public class win32 {
                [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern int RegOpenKeyEx(
                    IntPtr hKey,
                    string subKey,
                    int ulOptions,
                    int samDesired,
                    out IntPtr hkResult);
                [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern int RegQueryInfoKey(
                    IntPtr hkey,
                    StringBuilder lpClass,
                    ref int lpcbClass,
                    int lpReserved,
                    out int lpcSubKeys,
                    out int lpcbMaxSubKeyLen,
                    out int lpcbMaxClassLen,
                    out int lpcValues,
                    out int lpcbMaxValueNameLen,
                    out int lpcbMaxValueLen,
                    out int lpcbSecurityDescriptor,
                    IntPtr lpftLastWriteTime);
                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern int RegCloseKey(
                    IntPtr hKey);
            }
        }
"@
}"#.to_string();
}

pub fn get_keyclass(key: &str) -> String {
    return format!(
    "
    $hKey = [IntPtr]::Zero
        if ([ntlmx.win32]::RegOpenKeyEx(
                0x80000002,
                'SYSTEM\\CurrentControlSet\\Control\\Lsa\\{}',
                0x0,
                0x19,
                [ref]$hKey))
        {{
            $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw [ComponentModel.Win32Exception]$e
        }}
        
        $lpClass = New-Object Text.StringBuilder 1024
        [int]$lpcbClass = 1024
        if ([ntlmx.win32]::RegQueryInfoKey(
                $hkey,
                $lpClass,
                [ref]$lpcbClass,
                0x0,
                [ref]$null,
                [ref]$null,
                [ref]$null,
                [ref]$null,
                [ref]$null,
                [ref]$null,
                [ref]$null,
                [IntPtr]::Zero))
        {{
            $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw [ComponentModel.Win32Exception]$e
        }}
        
        [void] [ntlmx.win32]::RegCloseKey($hKey)
        
        $lpClass.ToString()", key);
}   