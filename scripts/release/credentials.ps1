# Доступ к диспетчеру учётных данных для скриптов выпуска: закрытый ключ
# подписи обновлений хранится там, а не в файлах.

if (-not ('DnsSwitcherRelease.Cred' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DnsSwitcherRelease {
    public static class Cred {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CREDENTIAL {
            public int Flags;
            public int Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredWriteW(ref CREDENTIAL credential, int flags);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredReadW(string target, int type, int flags, out IntPtr credential);
        [DllImport("advapi32.dll")]
        static extern void CredFree(IntPtr buffer);

        const int GENERIC = 1;
        const int PERSIST_LOCAL_MACHINE = 2;

        public static void Write(string target, string secret) {
            byte[] blob = Encoding.UTF8.GetBytes(secret);
            var c = new CREDENTIAL {
                Type = GENERIC,
                TargetName = target,
                CredentialBlobSize = blob.Length,
                CredentialBlob = Marshal.AllocHGlobal(blob.Length),
                Persist = PERSIST_LOCAL_MACHINE,
                UserName = "release",
            };
            try {
                Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length);
                if (!CredWriteW(ref c, 0)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
            } finally {
                Marshal.FreeHGlobal(c.CredentialBlob);
            }
        }

        public static string Read(string target) {
            IntPtr p;
            if (!CredReadW(target, GENERIC, 0, out p)) {
                return null;
            }
            try {
                var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
                byte[] blob = new byte[c.CredentialBlobSize];
                Marshal.Copy(c.CredentialBlob, blob, 0, blob.Length);
                return Encoding.UTF8.GetString(blob);
            } finally {
                CredFree(p);
            }
        }
    }
}
'@
}

$UpdaterKeyTarget = 'dns-switcher-release:updater-key'

function Set-ReleaseSecret([string]$Target, [string]$Secret) {
    [DnsSwitcherRelease.Cred]::Write($Target, $Secret)
}

function Get-ReleaseSecret([string]$Target) {
    $value = [DnsSwitcherRelease.Cred]::Read($Target)
    if ($null -eq $value) {
        throw "В диспетчере учётных данных нет «$Target». Создайте ключ: scripts\release\new-updater-key.ps1"
    }
    $value
}
