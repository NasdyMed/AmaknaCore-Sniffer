using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace AmaknaProxy.API.Network
{
    internal sealed class NoiseHeaderReader
    {
        private enum Phase { ServerHello, Handshake, Messages, Unsupported }

        private const int TransportVersion = 1;
        private const int HelloHeaderLength = 6;
        private const int HandshakeHeaderLength = 15;
        private const int HandshakeBodyLength = 48;
        private const int TagLength = 16;
        private const int MaxPlainChunkLength = 65519;

        private readonly byte[] header = new byte[HandshakeHeaderLength];
        private readonly int fixedHeaderLength;
        private readonly Action<int, int> messageSeen;
        private Phase phase;
        private int headerBytes;
        private int bytesToSkip;
        private int? pendingId;
        private int pendingLength;

        public NoiseHeaderReader(bool fromClient, Action<int, int> messageSeen)
        {
            // Outgoing headers include a four-byte instance counter.
            fixedHeaderLength = fromClient ? 6 : 2;
            phase = fromClient ? Phase.Handshake : Phase.ServerHello;
            this.messageSeen = messageSeen;
        }

        public void Observe(byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count && phase != Phase.Unsupported)
            {
                if (bytesToSkip > 0)
                {
                    int skipped = Math.Min(bytesToSkip, count - offset);
                    offset += skipped;
                    bytesToSkip -= skipped;
                    if (bytesToSkip == 0 && pendingId.HasValue)
                    {
                        messageSeen(pendingId.Value, pendingLength);
                        pendingId = null;
                    }
                    continue;
                }

                if (phase != Phase.Messages)
                {
                    int prefixLength = phase == Phase.ServerHello ? HelloHeaderLength : HandshakeHeaderLength;
                    if (ReadHeader(buffer, count, ref offset, prefixLength))
                        SkipHandshakeRecord();
                    continue;
                }

                if (!ReadHeader(buffer, count, ref offset, fixedHeaderLength))
                    continue;

                int encodedHeader = (header[0] << 8) | header[1];
                int lengthWidth = encodedHeader & 3;
                if (!ReadHeader(buffer, count, ref offset, fixedHeaderLength + lengthWidth))
                    continue;

                int plainLength = 0;
                for (int index = fixedHeaderLength; index < headerBytes; index++)
                    plainLength = (plainLength << 8) | header[index];

                pendingId = encodedHeader >> 2;
                pendingLength = plainLength;
                int chunks = Math.Max(1, (plainLength + MaxPlainChunkLength - 1) / MaxPlainChunkLength);
                bytesToSkip = plainLength + chunks * TagLength;
                headerBytes = 0;
            }
        }

        private bool ReadHeader(byte[] buffer, int count, ref int offset, int targetLength)
        {
            int copied = Math.Min(targetLength - headerBytes, count - offset);
            if (copied > 0)
            {
                Buffer.BlockCopy(buffer, offset, header, headerBytes, copied);
                headerBytes += copied;
                offset += copied;
            }
            return headerBytes >= targetLength;
        }

        private void SkipHandshakeRecord()
        {
            headerBytes = 0;
            if (header[0] != 'B' || header[1] != 'N' || header[2] != 'O' || header[3] != 'I' ||
                header[4] != TransportVersion)
            {
                phase = Phase.Unsupported;
                return;
            }

            if (phase == Phase.ServerHello)
            {
                int entryCount = header[5];
                if (entryCount < 1 || entryCount > 4)
                {
                    phase = Phase.Unsupported;
                    return;
                }

                bytesToSkip = entryCount * 8;
                phase = Phase.Handshake;
            }
            else
            {
                int bodyLength = (header[13] << 8) | header[14];
                if (bodyLength != HandshakeBodyLength)
                {
                    phase = Phase.Unsupported;
                    return;
                }

                bytesToSkip = bodyLength;
                phase = Phase.Messages;
            }
        }
    }

    internal static class MustamMessageNames
    {
        private static readonly Dictionary<int, string> names = LoadNames();

        public static string GetName(int id)
        {
            return names.TryGetValue(id, out string name) ? name : "Message inconnu";
        }

        private static Dictionary<int, string> LoadNames()
        {
            var result = new Dictionary<int, string>();
            using (Stream stream = typeof(MustamMessageNames).Assembly.GetManifestResourceStream("AmaknaProxy.MustamMessageNames"))
            {
                if (stream == null)
                    return result;

                using (var reader = new StreamReader(stream))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        int separator = line.IndexOf('\t');
                        if (separator > 0 && int.TryParse(line.Substring(0, separator), NumberStyles.None,
                            CultureInfo.InvariantCulture, out int id))
                            result[id] = line.Substring(separator + 1);
                    }
                }
            }
            return result;
        }
    }
}
