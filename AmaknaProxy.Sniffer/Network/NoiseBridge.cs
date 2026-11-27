// NoiseBridge.cs — pont Noise pour AmaknaProxy (port de ce que fait BotHors).
//
//   Client Dofus (crypto Noise neutralisée par Frida)
//        │  paquets EN CLAIR : en-tête | corps | 16 octets nuls (par chunk)
//        ▼
//   ClientLeg  ──►  paquet clair (en-tête + corps)  ──►  PacketFilter  ──►  NoiseUpstream
//                                                                                │ vrai Noise NK
//                                                                                ▼
//                                                                        Serveur de jeu
//
// Dépendance NuGet : BouncyCastle.Cryptography (2.x) — X25519, ChaCha20-Poly1305, BLAKE2s.
// Cible : .NET Framework 4.7+ / .NET 6+. Rien d'autre à installer.

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AmaknaProxy.API.Managers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Security;
using BcChaChaPoly = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305; // évite le conflit avec System.Security.Cryptography

namespace AmaknaProxy.API.Network
{
    // ───────────────────────────── utilitaires fil ─────────────────────────────
    internal static class Wire
    {
        public const int Tag = 16;
        public const int MaxChunk = 65519;

        public static async Task<byte[]> ReadExactAsync(Stream s, int count)
        {
            var buf = new byte[count];
            int got = 0;
            while (got < count)
            {
                int n = await s.ReadAsync(buf, got, count - got).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException();
                got += n;
            }
            return buf;
        }

        public static int ChunkCount(int len) { return len == 0 ? 1 : (len + MaxChunk - 1) / MaxChunk; }

        public static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            var r = new byte[total];
            int o = 0;
            foreach (var p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; }
            return r;
        }

        public static byte[] Slice(byte[] b, int off, int len)
        {
            var r = new byte[len];
            Buffer.BlockCopy(b, off, r, 0, len);
            return r;
        }

        public static int ReadBE(byte[] b, int off, int count)
        {
            int v = 0;
            for (int i = 0; i < count; i++) v = (v << 8) | b[off + i];
            return v;
        }

        // Données authentifiées de chaque chunk : [1, sens, len(en-tête), en-tête, idx, total, longueur]
        // sens : 0 = client→serveur, 1 = serveur→client
        public static byte[] Aad(byte dir, byte[] header, int idx, int total, int len)
        {
            var r = new byte[3 + header.Length + 6];
            r[0] = 1; r[1] = dir; r[2] = (byte)header.Length;
            Buffer.BlockCopy(header, 0, r, 3, header.Length);
            int o = 3 + header.Length;
            r[o] = (byte)(idx >> 8);   r[o + 1] = (byte)idx;
            r[o + 2] = (byte)(total >> 8); r[o + 3] = (byte)total;
            r[o + 4] = (byte)(len >> 8);   r[o + 5] = (byte)len;
            return r;
        }

        /// <summary>Découpe un paquet clair : id du message et corps. En-tête = 6+w (client) ou 2+w (serveur).</summary>
        public static void ParsePacket(bool fromClient, byte[] packet, out int id, out byte[] body)
        {
            int enc = (packet[0] << 8) | packet[1];
            id = enc >> 2;
            int headerLen = (fromClient ? 6 : 2) + (enc & 3);
            body = Slice(packet, headerLen, packet.Length - headerLen);
        }
    }

    // ───────────────────────────── primitives Noise ─────────────────────────────
    internal sealed class NoisePin
    {
        public readonly string KeyId;
        public readonly string PublicKey; // base64, 32 octets (X25519)
        public NoisePin(string keyId, string publicKey) { KeyId = keyId; PublicKey = publicKey; }
    }

    internal static class NoiseCrypto
    {
        public static readonly byte[] ProtocolName = Encoding.ASCII.GetBytes("Noise_NK_25519_ChaChaPoly_BLAKE2s");
        public static readonly byte[] PrologueBase = Encoding.UTF8.GetBytes("bubble.dofus.2.66.game-tcp.packet-protection");

        // Clés statiques publiques du serveur (recopiées de ton index.js). À mettre à jour si le jeu change.
        public static readonly NoisePin[] Pins =
        {
            new NoisePin("a324d09691b1428c", "xCDIHMGrufu1I2p9v/iJDBLpM82iqmnI2UJ02ONT8hE="),
            new NoisePin("677c13445d80b2f4", "GWDmqMZJoPGW0xDHwXn7pF5XOl68DVeIQXYq8uLhCHU="),
            new NoisePin("991fae4fcc327652", "F1bQ2cWN720tNnexSRXGUUUpJCUcgdPypl0nmIaoTA4="),
        };

        public static byte[] Hash(params byte[][] data)
        {
            var d = new Blake2sDigest(); // 256 bits
            foreach (var x in data) d.BlockUpdate(x, 0, x.Length);
            var o = new byte[32];
            d.DoFinal(o, 0);
            return o;
        }

        public static byte[] Hmac(byte[] key, params byte[][] data)
        {
            var h = new HMac(new Blake2sDigest()); // bloc de 64 octets, comme la spec Noise
            h.Init(new KeyParameter(key));
            foreach (var x in data) h.BlockUpdate(x, 0, x.Length);
            var o = new byte[h.GetMacSize()];
            h.DoFinal(o, 0);
            return o;
        }

        // HKDF Noise à 2 sorties
        public static byte[][] Hkdf2(byte[] ck, byte[] input)
        {
            byte[] temp = Hmac(ck, input);
            byte[] o1 = Hmac(temp, new byte[] { 1 });
            byte[] o2 = Hmac(temp, o1, new byte[] { 2 });
            return new[] { o1, o2 };
        }

        // Nonce ChaChaPoly de Noise : 4 octets nuls + compteur 64 bits little-endian
        private static byte[] Nonce(ulong n)
        {
            var b = new byte[12];
            for (int i = 0; i < 8; i++) b[4 + i] = (byte)(n >> (8 * i));
            return b;
        }

        public static byte[] Seal(byte[] key, ulong n, byte[] ad, byte[] plain)
        {
            var c = new BcChaChaPoly();
            c.Init(true, new AeadParameters(new KeyParameter(key), 128, Nonce(n), ad));
            var o = new byte[c.GetOutputSize(plain.Length)];
            int l = c.ProcessBytes(plain, 0, plain.Length, o, 0);
            c.DoFinal(o, l);
            return o; // texte chiffré || tag(16)
        }

        public static byte[] Open(byte[] key, ulong n, byte[] ad, byte[] ct)
        {
            var c = new BcChaChaPoly();
            c.Init(false, new AeadParameters(new KeyParameter(key), 128, Nonce(n), ad));
            var o = new byte[c.GetOutputSize(ct.Length)];
            int l = c.ProcessBytes(ct, 0, ct.Length, o, 0);
            l += c.DoFinal(o, l); // lève InvalidCipherTextException si le tag est faux
            if (l != o.Length) Array.Resize(ref o, l);
            return o;
        }

        public static void NewKeyPair(out byte[] priv, out byte[] pub)
        {
            priv = new byte[32];
            X25519.GeneratePrivateKey(new SecureRandom(), priv);
            pub = new byte[32];
            X25519.GeneratePublicKey(priv, 0, pub, 0);
        }

        public static byte[] Dh(byte[] priv, byte[] pub)
        {
            var o = new byte[32];
            if (!X25519.CalculateAgreement(priv, 0, pub, 0, o, 0))
                throw new InvalidDataException("secret DH nul");
            return o;
        }
    }

    internal sealed class NoiseCipher
    {
        private readonly byte[] key;
        private ulong n;
        public NoiseCipher(byte[] key) { this.key = key; }
        public byte[] Encrypt(byte[] ad, byte[] plain) { var r = NoiseCrypto.Seal(key, n, ad, plain); n++; return r; }
        public byte[] Decrypt(byte[] ad, byte[] ct)    { var r = NoiseCrypto.Open(key, n, ad, ct); n++; return r; }
    }

    /// <summary>Initiateur Noise_NK : le client connaît la clé statique du serveur. Message 1 = (e, es), message 2 = (e, ee).</summary>
    internal sealed class NoiseInitiator
    {
        private byte[] ck, h, k;
        private ulong n;
        private byte[] ePriv;
        private readonly byte[] rs;

        public NoiseCipher Send { get; private set; }
        public NoiseCipher Recv { get; private set; }

        public NoiseInitiator(byte[] responderStatic, byte[] prologue)
        {
            if (responderStatic.Length != 32) throw new ArgumentException("la clé statique doit faire 32 octets");
            rs = responderStatic;
            byte[] name = NoiseCrypto.ProtocolName;
            if (name.Length <= 32) { h = new byte[32]; Buffer.BlockCopy(name, 0, h, 0, name.Length); }
            else h = NoiseCrypto.Hash(name); // 33 octets → haché
            ck = h;
            MixHash(prologue);
            MixHash(rs); // pré-message « ← s »
        }

        private void MixHash(byte[] data) { h = NoiseCrypto.Hash(h, data); }

        private void MixKey(byte[] ikm)
        {
            var o = NoiseCrypto.Hkdf2(ck, ikm);
            ck = o[0]; k = o[1]; n = 0;
        }

        private byte[] EncryptAndHash(byte[] plain)
        {
            if (k == null) { MixHash(plain); return plain; }
            byte[] ct = NoiseCrypto.Seal(k, n, h, plain); n++;
            MixHash(ct);
            return ct;
        }

        private byte[] DecryptAndHash(byte[] ct)
        {
            if (k == null) { MixHash(ct); return ct; }
            byte[] pt = NoiseCrypto.Open(k, n, h, ct); n++;
            MixHash(ct);
            return pt;
        }

        public byte[] WriteMsg1() // 32 (e) + 16 (tag du payload vide) = 48 octets
        {
            byte[] ePub;
            NoiseCrypto.NewKeyPair(out ePriv, out ePub);
            MixHash(ePub);
            MixKey(NoiseCrypto.Dh(ePriv, rs));
            return Wire.Concat(ePub, EncryptAndHash(new byte[0]));
        }

        public void ReadMsg2(byte[] msg) // 48 octets
        {
            if (msg.Length != 48) throw new InvalidDataException("msg2 doit faire 48 octets");
            byte[] re = Wire.Slice(msg, 0, 32);
            MixHash(re);
            MixKey(NoiseCrypto.Dh(ePriv, re));
            DecryptAndHash(Wire.Slice(msg, 32, 16));
            var o = NoiseCrypto.Hkdf2(ck, new byte[0]); // Split()
            Send = new NoiseCipher(o[0]);
            Recv = new NoiseCipher(o[1]);
        }
    }

    // ───────────────────────── jambe serveur : vrai Noise ─────────────────────────
    internal sealed class NoiseUpstream
    {
        private readonly Stream stream;
        private readonly NoiseCipher send, recv;
        private readonly SemaphoreSlim sendLock = new SemaphoreSlim(1, 1);

        private NoiseUpstream(Stream s, NoiseCipher send, NoiseCipher recv)
        {
            stream = s; this.send = send; this.recv = recv;
        }

        public static async Task<NoiseUpstream> ConnectAsync(Stream s)
        {
            // 1) server hello : "BNOI", version 1, nombre de clés, puis N × keyId(8)
            byte[] head = await Wire.ReadExactAsync(s, 6).ConfigureAwait(false);
            if (Encoding.ASCII.GetString(head, 0, 4) != "BNOI") throw new InvalidDataException("magic du server hello invalide");
            if (head[4] != 1) throw new InvalidDataException("version du hello non supportée");
            int count = head[5];
            if (count < 1 || count > 4) throw new InvalidDataException("nombre de clés invalide");
            byte[] ids = await Wire.ReadExactAsync(s, count * 8).ConfigureAwait(false);
            byte[] hello = Wire.Concat(head, ids);

            // 2) première clé annoncée qui correspond à une clé épinglée
            byte[] keyId = null, pub = null;
            for (int i = 0; i < count && keyId == null; i++)
            {
                byte[] id = Wire.Slice(ids, i * 8, 8);
                string hex = BitConverter.ToString(id).Replace("-", "").ToLowerInvariant();
                foreach (var pin in NoiseCrypto.Pins)
                    if (string.Equals(pin.KeyId, hex, StringComparison.OrdinalIgnoreCase))
                    { keyId = id; pub = Convert.FromBase64String(pin.PublicKey); break; }
            }
            if (keyId == null) throw new InvalidDataException("aucune clé Noise épinglée annoncée par le serveur");

            // 3) prologue = nom + 0x00 + hello complet + keyId choisi ; message 1
            byte[] prologue = Wire.Concat(NoiseCrypto.PrologueBase, new byte[] { 0 }, hello, keyId);
            var init = new NoiseInitiator(pub, prologue);
            byte[] msg1 = init.WriteMsg1();
            byte[] clientHello = Wire.Concat(Encoding.ASCII.GetBytes("BNOI"), new byte[] { 1 }, keyId, new byte[] { 0, 48 }, msg1);
            await s.WriteAsync(clientHello, 0, clientHello.Length).ConfigureAwait(false);
            await s.FlushAsync().ConfigureAwait(false);

            // 4) réponse (63 octets) : "BNOI", version, keyId, longueur 48, message 2
            byte[] resp = await Wire.ReadExactAsync(s, 63).ConfigureAwait(false);
            if (Encoding.ASCII.GetString(resp, 0, 4) != "BNOI" || resp[4] != 1) throw new InvalidDataException("réponse Noise invalide");
            for (int i = 0; i < 8; i++)
                if (resp[5 + i] != keyId[i]) throw new InvalidDataException("le serveur a répondu avec une autre clé");
            if (Wire.ReadBE(resp, 13, 2) != 48) throw new InvalidDataException("longueur du message 2 invalide");
            init.ReadMsg2(Wire.Slice(resp, 15, 48));

            return new NoiseUpstream(s, init.Send, init.Recv);
        }

        /// <summary>Lit un paquet serveur→client et renvoie en-tête (2+w) + corps déchiffré.</summary>
        public async Task<byte[]> ReadPacketAsync()
        {
            byte[] h2 = await Wire.ReadExactAsync(stream, 2).ConfigureAwait(false);
            int w = ((h2[0] << 8) | h2[1]) & 3;
            byte[] lenB = w > 0 ? await Wire.ReadExactAsync(stream, w).ConfigureAwait(false) : new byte[0];
            int len = Wire.ReadBE(lenB, 0, w);
            byte[] header = Wire.Concat(h2, lenB);
            int chunks = Wire.ChunkCount(len);
            byte[] wire = await Wire.ReadExactAsync(stream, len + chunks * Wire.Tag).ConfigureAwait(false);

            var output = new byte[header.Length + len];
            Buffer.BlockCopy(header, 0, output, 0, header.Length);
            int src = 0, dst = header.Length, remaining = len;
            for (int i = 0; i < chunks; i++)
            {
                int d = len == 0 ? 0 : Math.Min(Wire.MaxChunk, remaining);
                byte[] pt = recv.Decrypt(Wire.Aad(1, header, i, chunks, d), Wire.Slice(wire, src, d + Wire.Tag));
                Buffer.BlockCopy(pt, 0, output, dst, pt.Length);
                src += d + Wire.Tag; dst += d; remaining -= d;
            }
            return output;
        }

        /// <summary>Scelle et envoie un paquet client→serveur (en-tête 6+w + corps clair).</summary>
        public async Task WritePacketAsync(byte[] plain)
        {
            int hl = 6 + (((plain[0] << 8) | plain[1]) & 3);
            if (plain.Length < hl) throw new InvalidDataException("paquet trop court");
            byte[] header = Wire.Slice(plain, 0, hl);
            int bodyLen = plain.Length - hl;
            int chunks = Wire.ChunkCount(bodyLen);

            await sendLock.WaitAsync().ConfigureAwait(false); // le compteur de nonce doit suivre l'ordre d'envoi
            try
            {
                var ms = new MemoryStream(plain.Length + chunks * Wire.Tag);
                ms.Write(header, 0, hl);
                for (int i = 0; i < chunks; i++)
                {
                    int take = bodyLen == 0 ? 0 : Math.Min(Wire.MaxChunk, bodyLen - i * Wire.MaxChunk);
                    byte[] ct = send.Encrypt(Wire.Aad(0, header, i, chunks, take), Wire.Slice(plain, hl + i * Wire.MaxChunk, take));
                    ms.Write(ct, 0, ct.Length);
                }
                byte[] buf = ms.ToArray();
                await stream.WriteAsync(buf, 0, buf.Length).ConfigureAwait(false);
            }
            finally { sendLock.Release(); }
        }
    }

    // ───────────────────── jambe client : serveur factice en clair ─────────────────────
    // Le client exécute encore son handshake BNOI (inoffensif) : on lui sert un hello puis une réponse
    // « jetable » de 63 octets que le hook readHandshakeResponse accepte sans la vérifier.
    // Ensuite, sealPacket/openPacket (hookés) échangent des paquets EN CLAIR + 16 octets nuls par chunk.
    internal sealed class ClientLeg
    {
        private static readonly byte[] FakeKeyId = { 0xa3, 0x24, 0xd0, 0x96, 0x91, 0xb1, 0x42, 0x8c }; // = 1re clé épinglée
        private readonly Stream stream;
        private readonly SemaphoreSlim writeLock = new SemaphoreSlim(1, 1);

        public ClientLeg(Stream s) { stream = s; }

        public async Task HandshakeAsync()
        {
            byte[] hello = Wire.Concat(Encoding.ASCII.GetBytes("BNOI"), new byte[] { 1, 1 }, FakeKeyId); // 14 octets
            await stream.WriteAsync(hello, 0, hello.Length).ConfigureAwait(false);
            await Wire.ReadExactAsync(stream, 63).ConfigureAwait(false); // client hello : ignoré
            byte[] resp = Wire.Concat(Encoding.ASCII.GetBytes("BNOI"), new byte[] { 1 }, FakeKeyId, new byte[] { 0, 48 }, new byte[48]); // 63 octets
            await stream.WriteAsync(resp, 0, resp.Length).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }

        /// <summary>Lit un paquet client→serveur : en-tête (6+w) + corps, pads retirés.</summary>
        public async Task<byte[]> ReadPacketAsync()
        {
            byte[] h6 = await Wire.ReadExactAsync(stream, 6).ConfigureAwait(false); // 2 + compteur d'instance (4)
            int w = ((h6[0] << 8) | h6[1]) & 3;
            byte[] lenB = w > 0 ? await Wire.ReadExactAsync(stream, w).ConfigureAwait(false) : new byte[0];
            int len = Wire.ReadBE(lenB, 0, w);
            byte[] header = Wire.Concat(h6, lenB);
            int chunks = Wire.ChunkCount(len);
            byte[] wire = await Wire.ReadExactAsync(stream, len + chunks * Wire.Tag).ConfigureAwait(false);

            var output = new byte[header.Length + len];
            Buffer.BlockCopy(header, 0, output, 0, header.Length);
            int src = 0, dst = header.Length, remaining = len;
            for (int i = 0; i < chunks; i++)
            {
                int d = len == 0 ? 0 : Math.Min(Wire.MaxChunk, remaining);
                Buffer.BlockCopy(wire, src, output, dst, d);
                src += d + Wire.Tag; dst += d; remaining -= d;
            }
            return output;
        }

        /// <summary>Envoie un paquet serveur→client : en-tête (2+w) + corps, avec 16 octets nuls après chaque chunk.</summary>
        public async Task WritePacketAsync(byte[] packet)
        {
            int hl = 2 + (((packet[0] << 8) | packet[1]) & 3);
            int bodyLen = packet.Length - hl;
            int chunks = Wire.ChunkCount(bodyLen);
            var buf = new byte[hl + bodyLen + chunks * Wire.Tag]; // les pads restent à 0
            Buffer.BlockCopy(packet, 0, buf, 0, hl);
            int dst = hl;
            for (int i = 0; i < chunks; i++)
            {
                int take = bodyLen == 0 ? 0 : Math.Min(Wire.MaxChunk, bodyLen - i * Wire.MaxChunk);
                Buffer.BlockCopy(packet, hl + i * Wire.MaxChunk, buf, dst, take);
                dst += take + Wire.Tag;
            }
            await writeLock.WaitAsync().ConfigureAwait(false);
            try { await stream.WriteAsync(buf, 0, buf.Length).ConfigureAwait(false); }
            finally { writeLock.Release(); }
        }
    }

    // Flux qui rejoue d'abord des octets déjà lus (le « peek »), puis lit le flux réel. Ne ferme pas le flux réel.
    internal sealed class PrefixedStream : Stream
    {
        private readonly Stream inner;
        private readonly byte[] prefix;
        private int pos;

        public PrefixedStream(Stream inner, byte[] prefix) { this.inner = inner; this.prefix = prefix; }

        private int TakePrefix(byte[] buffer, int offset, int count)
        {
            int n = Math.Min(count, prefix.Length - pos);
            Buffer.BlockCopy(prefix, pos, buffer, offset, n);
            pos += n;
            return n;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return pos < prefix.Length ? TakePrefix(buffer, offset, count) : inner.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            return pos < prefix.Length ? Task.FromResult(TakePrefix(buffer, offset, count)) : inner.ReadAsync(buffer, offset, count, ct);
        }

        public override void Write(byte[] buffer, int offset, int count) { inner.Write(buffer, offset, count); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) { return inner.WriteAsync(buffer, offset, count, ct); }
        public override void Flush() { inner.Flush(); }
        public override Task FlushAsync(CancellationToken ct) { return inner.FlushAsync(ct); }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
    }

    // ─────────────────────────────── le pont ───────────────────────────────
    internal sealed class NoiseBridge
    {
        /// <summary>
        /// (fromClient, paquet clair) → paquet à transmettre, ou null pour l'avaler.
        /// Le paquet = en-tête + corps ; Wire.ParsePacket donne l'id et le corps.
        /// </summary>
        public Func<bool, byte[], byte[]> PacketFilter;

        private NoiseUpstream upstream;
        private ClientLeg clientLeg;

        /// <summary>
        /// Lit le premier envoi du serveur (une seule lecture) : le serveur parle en premier, et ce qu'il envoie
        /// dit si la connexion est en Noise (« BNOI… ») ou en clair (login). Ces octets sont déjà consommés :
        /// il faut les retransmettre (chemin clair) ou les passer à RunAsync (chemin Noise).
        /// </summary>
        public static async Task<byte[]> PeekAsync(Stream server, int timeoutMs = 10000)
        {
            var buf = new byte[16 * 1024];
            Task<int> read = server.ReadAsync(buf, 0, buf.Length);
            if (await Task.WhenAny(read, Task.Delay(timeoutMs)).ConfigureAwait(false) != read)
                throw new TimeoutException("pas de premier paquet du serveur");
            int n = await read.ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException();
            return Wire.Slice(buf, 0, n);
        }

        public static bool IsNoise(byte[] first)
        {
            return first.Length >= 4 && first[0] == 'B' && first[1] == 'N' && first[2] == 'O' && first[3] == 'I';
        }

        public async Task RunAsync(Stream client, Stream server, byte[] peeked)
        {
            upstream = await NoiseUpstream.ConnectAsync(new PrefixedStream(server, peeked)).ConfigureAwait(false);
            ConsoleManager.Info("[Pont Noise] transport serveur établi.");

            clientLeg = new ClientLeg(client);
            await clientLeg.HandshakeAsync().ConfigureAwait(false);
            ConsoleManager.Info("[Pont Noise] jambe client prête.");

            Task toServer = PumpAsync(true, clientLeg.ReadPacketAsync, upstream.WritePacketAsync);
            Task toClient = PumpAsync(false, upstream.ReadPacketAsync, clientLeg.WritePacketAsync);

            Task first = await Task.WhenAny(toServer, toClient).ConfigureAwait(false);
            client.Dispose();
            server.Dispose();
            try { await Task.WhenAll(toServer, toClient).ConfigureAwait(false); }
            catch (Exception) { /* fin de connexion : EOF / flux fermé */ }
            if (first.IsFaulted && !(first.Exception.InnerException is EndOfStreamException))
                throw first.Exception.InnerException;
        }

        // Injection depuis ailleurs dans le proxy (les écritures sont sérialisées par des verrous).
        public Task SendToServerAsync(byte[] plainPacket) { return upstream.WritePacketAsync(plainPacket); }
        public Task SendToClientAsync(byte[] plainPacket) { return clientLeg.WritePacketAsync(plainPacket); }

        private async Task PumpAsync(bool fromClient, Func<Task<byte[]>> read, Func<byte[], Task> write)
        {
            while (true)
            {
                byte[] packet = await read().ConfigureAwait(false);
                var filter = PacketFilter;
                if (filter != null)
                {
                    packet = filter(fromClient, packet);
                    if (packet == null) continue;
                }
                await write(packet).ConfigureAwait(false);
            }
        }
    }
}
