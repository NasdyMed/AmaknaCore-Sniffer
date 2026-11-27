// NoiseClientHooks.cs — équivalent C# de noise_bridge.js (Frida), à exécuter DANS le processus Dofus.exe.
//
// Neutralise la crypto Noise du client pour qu'il parle en clair à ton proxy :
//   readHandshakeResponse -> toujours vrai
//   sealPacket            -> en-tête + corps clair + 16 octets nuls après chaque chunk de 65519
//   openPacket            -> retire ces 16 octets nuls, renvoie en-tête + corps
//
// Hypothèses reprises du script Frida :
//   - Dofus.exe est en 64 bits (FREByteArray = { uint32 length; <pad>; uint8_t* bytes @ +8 }).
//   - les 3 offsets ci-dessous sont ceux de TA version de NoiseTransportANE.dll.
//     Après une mise à jour du client, il faut les redécouvrir (c'est ce que faisait noise_discover_handshake.js).
//
// Dépendance NuGet pour poser les hooks natifs : EasyHook (voir Detour(), seul endroit à adapter
// si ta Hooks.dll utilise déjà MinHook / Detours / Reloaded.Hooks).

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using EasyHook;

namespace AmaknaProxy.Hooks
{
    public static class NoiseClientHooks
    {
        private const string AirDll = "Adobe AIR.dll";
        private const string AneDll = "NoiseTransportANE.dll";

        // Adresses « intérieures » (retour d'appel) découvertes par backtrace ; le début de fonction est retrouvé en
        // remontant jusqu'au padding 0xCC 0xCC qui précède.
        private const long SealInterior = 0x3e78;
        private const long OpenInterior = 0x2eff;
        private const long RhrInterior = 0x65ec;

        private const int Tag = 16;
        private const int MaxChunk = 65519;

        // FREObject fn(FREContext ctx, void* funcData, uint32 argc, FREObject argv[])
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr FreFunction(IntPtr ctx, IntPtr funcData, uint argc, IntPtr argv);

        // API FRE d'Adobe AIR.dll
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint FreAcquireByteArray(IntPtr obj, IntPtr byteArray);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint FreReleaseByteArray(IntPtr obj);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint FreNewByteArray(IntPtr byteArray, out IntPtr result);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint FreGetObjectAsUint32(IntPtr obj, out uint value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint FreNewObjectFromBool(uint value, out IntPtr result);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] private static extern IntPtr GetProcAddress(IntPtr module, string name);

        private static FreAcquireByteArray freAcquire;
        private static FreReleaseByteArray freRelease;
        private static FreNewByteArray freNewBA;
        private static FreGetObjectAsUint32 freGetUint;
        private static FreNewObjectFromBool freNewBool;

        // Les delegates et les hooks doivent rester référencés, sinon le GC libère les thunks natifs.
        private static readonly List<object> keepAlive = new List<object>();
        private static volatile bool installed;

        /// <summary>À appeler une fois dans le processus du jeu (ex. depuis le point d'entrée de ta DLL injectée).</summary>
        public static void InstallWhenReady()
        {
            if (IntPtr.Size != 8) throw new PlatformNotSupportedException("ces offsets/structures supposent un Dofus.exe 64 bits");
            var t = new Thread(() =>
            {
                // Tant que NoiseTransportANE.dll n'est pas mappée, on sonde de très près :
                // le hook doit être posé avant le premier handshake du client.
                while (!installed)
                {
                    try { if (TryInstall()) break; } catch (Exception ex) { Log("erreur d'installation : " + ex.Message); }
                    Thread.Sleep(2);
                }
            }) { IsBackground = true, Name = "NoiseBridgeInstall" };
            t.Start();
        }

        private static bool TryInstall()
        {
            IntPtr air = GetModuleHandleW(AirDll);
            IntPtr ane = GetModuleHandleW(AneDll);
            if (air == IntPtr.Zero || ane == IntPtr.Zero) return false;

            freAcquire = Bind<FreAcquireByteArray>(air, "FREAcquireByteArray");
            freRelease = Bind<FreReleaseByteArray>(air, "FREReleaseByteArray");
            freNewBA = Bind<FreNewByteArray>(air, "FRENewByteArray");
            freGetUint = Bind<FreGetObjectAsUint32>(air, "FREGetObjectAsUint32");
            freNewBool = Bind<FreNewObjectFromBool>(air, "FRENewObjectFromBool");

            IntPtr seal = FuncStart(Add(ane, SealInterior));
            IntPtr open = FuncStart(Add(ane, OpenInterior));
            IntPtr rhr = FuncStart(Add(ane, RhrInterior));
            if (seal == IntPtr.Zero || open == IntPtr.Zero || rhr == IntPtr.Zero)
            {
                Log("début de fonction introuvable (offsets à redécouvrir ?)");
                return false;
            }

            Detour(seal, new FreFunction(SealPacket));
            Detour(open, new FreFunction(OpenPacket));
            Detour(rhr, new FreFunction(ReadHandshakeResponse));

            installed = true;
            Log("Noise du client neutralisé — il parle en clair au proxy.");
            return true;
        }

        // ─────────────────────────────── les 3 remplacements ───────────────────────────────

        // sealPacket(argv[1] = ByteArray en-tête+corps, argv[2] = longueur d'en-tête)
        private static IntPtr SealPacket(IntPtr ctx, IntPtr funcData, uint argc, IntPtr argv)
        {
            try
            {
                byte[] plain = ReadBA(Marshal.ReadIntPtr(argv, 1 * IntPtr.Size));
                int headerLen = (int)GetUint(Marshal.ReadIntPtr(argv, 2 * IntPtr.Size));
                if (plain == null || plain.Length < headerLen) return IntPtr.Zero;

                int bodyLen = plain.Length - headerLen;
                int chunks = bodyLen == 0 ? 1 : (bodyLen + MaxChunk - 1) / MaxChunk;
                var output = new byte[headerLen + bodyLen + chunks * Tag]; // pads = zéros
                Buffer.BlockCopy(plain, 0, output, 0, headerLen);
                int dst = headerLen;
                for (int i = 0; i < chunks; i++)
                {
                    int take = bodyLen == 0 ? 0 : Math.Min(MaxChunk, bodyLen - i * MaxChunk);
                    Buffer.BlockCopy(plain, headerLen + i * MaxChunk, output, dst, take);
                    dst += take + Tag;
                }
                return NewBA(output);
            }
            catch (Exception ex) { Log("seal : " + ex.Message); return IntPtr.Zero; }
        }

        // openPacket(argv[1] = ByteArray reçu, argv[2] = longueur d'en-tête, argv[3] = longueur du corps clair)
        private static IntPtr OpenPacket(IntPtr ctx, IntPtr funcData, uint argc, IntPtr argv)
        {
            try
            {
                byte[] wire = ReadBA(Marshal.ReadIntPtr(argv, 1 * IntPtr.Size));
                int headerLen = (int)GetUint(Marshal.ReadIntPtr(argv, 2 * IntPtr.Size));
                int plainLen = (int)GetUint(Marshal.ReadIntPtr(argv, 3 * IntPtr.Size));
                if (wire == null) return IntPtr.Zero;

                int chunks = plainLen == 0 ? 1 : (plainLen + MaxChunk - 1) / MaxChunk;
                var output = new byte[headerLen + plainLen];
                Buffer.BlockCopy(wire, 0, output, 0, headerLen);
                int src = headerLen, dst = headerLen, remaining = plainLen;
                for (int i = 0; i < chunks; i++)
                {
                    int take = plainLen == 0 ? 0 : Math.Min(MaxChunk, remaining);
                    Buffer.BlockCopy(wire, src, output, dst, take);
                    src += take + Tag; dst += take; remaining -= take;
                }
                return NewBA(output);
            }
            catch (Exception ex) { Log("open : " + ex.Message); return IntPtr.Zero; }
        }

        // readHandshakeResponse -> true : le client accepte la réponse « jetable » du proxy
        private static IntPtr ReadHandshakeResponse(IntPtr ctx, IntPtr funcData, uint argc, IntPtr argv)
        {
            IntPtr res;
            return freNewBool(1, out res) == 0 ? res : IntPtr.Zero;
        }

        // ─────────────────────────────── FRE / mémoire ───────────────────────────────

        private static byte[] ReadBA(IntPtr freObj)
        {
            IntPtr slot = Marshal.AllocHGlobal(16);
            try
            {
                if (freAcquire(freObj, slot) != 0) return null;
                int len = Marshal.ReadInt32(slot, 0);
                IntPtr ptr = Marshal.ReadIntPtr(slot, 8);
                var data = new byte[len];
                if (len > 0 && ptr != IntPtr.Zero) Marshal.Copy(ptr, data, 0, len);
                freRelease(freObj);
                return data;
            }
            finally { Marshal.FreeHGlobal(slot); }
        }

        // Cette build d'AIR : FRENewByteArray(FREByteArray* {len, bytes}, FREObject* out) alloue ET copie.
        private static IntPtr NewBA(byte[] data)
        {
            IntPtr fba = Marshal.AllocHGlobal(16);
            IntPtr buf = IntPtr.Zero;
            try
            {
                Marshal.WriteInt64(fba, 0, 0);
                Marshal.WriteInt64(fba, 8, 0);
                Marshal.WriteInt32(fba, 0, data.Length);
                if (data.Length > 0)
                {
                    buf = Marshal.AllocHGlobal(data.Length);
                    Marshal.Copy(data, 0, buf, data.Length);
                    Marshal.WriteIntPtr(fba, 8, buf);
                }
                IntPtr res;
                return freNewBA(fba, out res) == 0 ? res : IntPtr.Zero;
            }
            finally
            {
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
                Marshal.FreeHGlobal(fba);
            }
        }

        private static uint GetUint(IntPtr freObj)
        {
            uint v;
            return freGetUint(freObj, out v) == 0 ? v : 0;
        }

        private static T Bind<T>(IntPtr module, string export) where T : class
        {
            IntPtr p = GetProcAddress(module, export);
            if (p == IntPtr.Zero) throw new EntryPointNotFoundException(export);
            var d = Marshal.GetDelegateForFunctionPointer(p, typeof(T));
            keepAlive.Add(d);
            return (T)(object)d;
        }

        // Début de fonction = premier octet après le padding 0xCC 0xCC qui précède l'adresse intérieure.
        private static IntPtr FuncStart(IntPtr interior)
        {
            long p = interior.ToInt64();
            for (int i = 0; i < 0x2000; i++, p--)
                if (Marshal.ReadByte(new IntPtr(p - 1)) == 0xCC && Marshal.ReadByte(new IntPtr(p - 2)) == 0xCC)
                    return new IntPtr(p);
            return IntPtr.Zero;
        }

        private static IntPtr Add(IntPtr b, long off) { return new IntPtr(b.ToInt64() + off); }

        // ───────────── seul point dépendant de la bibliothèque de hooks (ici EasyHook) ─────────────
        private static void Detour(IntPtr target, Delegate replacement)
        {
            var hook = LocalHook.Create(target, replacement, null);
            hook.ThreadACL.SetExclusiveACL(new[] { 0 }); // hooke tous les threads (le thread AS3/AIR en particulier)
            keepAlive.Add(replacement);
            keepAlive.Add(hook);
        }

        /// <summary>Destination des logs (dans Main : _interface.Message, pour les voir dans le Sniffer).</summary>
        public static Action<string> LogSink;

        private static void Log(string msg)
        {
            var sink = LogSink;
            if (sink == null) { Console.Error.WriteLine("[NoiseClientHooks] " + msg); return; }
            try { sink(msg); } catch (Exception) { /* le canal IPC peut être fermé */ }
        }
    }
}

// ───────── Exemple de point d'entrée EasyHook (si ta DLL est managée et injectée par EasyHook) ─────────
//
//   public class Main : EasyHook.IEntryPoint
//   {
//       public Main(EasyHook.RemoteHooking.IContext ctx) { }
//       public void Run(EasyHook.RemoteHooking.IContext ctx)
//       {
//           AmaknaProxy.Hooks.NoiseClientHooks.InstallWhenReady();
//           EasyHook.RemoteHooking.WakeUpProcess();   // si lancé via CreateAndInject (processus suspendu)
//           while (true) Thread.Sleep(1000);
//       }
//   }
//
//   // Côté proxy (lancement + injection avant que le jeu ne tourne) :
//   RemoteHooking.CreateAndInject(dofusExe, args, 0, InjectionOptions.DoNotRequireStrongName,
//                                 hooksDllPath, hooksDllPath, out int pid);
