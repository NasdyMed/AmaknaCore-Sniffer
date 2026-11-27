using AmaknaProxy.API.Managers;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace AmaknaProxy.API.Network
{
    internal sealed class TcpRelay : IDisposable
    {
        private readonly object sync = new object();
        private readonly HashSet<Socket> connections = new HashSet<Socket>();
        private volatile bool stopped;

        public async Task ForwardAsync(Socket client, IPEndPoint endpoint)
        {
            using (client)
            using (var server = new TcpClient(AddressFamily.InterNetwork))
            {
                Socket upstream = server.Client;
                lock (sync)
                {
                    if (stopped)
                        return;

                    connections.Add(client);
                    connections.Add(upstream);
                }

                try
                {
                    await server.ConnectAsync(endpoint.Address, endpoint.Port).ConfigureAwait(false);
                    ConsoleManager.Info($"[Relais TCP] Connexion au serveur établie ({endpoint}).");

                    using (var clientStream = new NetworkStream(client))
                    using (NetworkStream serverStream = server.GetStream())
                    {
                        // Le serveur parle en premier : "BNOI..." = connexion de jeu en Noise, sinon login en clair.
                        byte[] peeked = await NoiseBridge.PeekAsync(serverStream).ConfigureAwait(false);
                        if (NoiseBridge.IsNoise(peeked))
                        {
                            ConsoleManager.Info("[Relais TCP] Connexion Noise détectée : pont en clair côté client.");
                            var bridge = new NoiseBridge { PacketFilter = OnPlainPacket };
                            await bridge.RunAsync(clientStream, serverStream, peeked).ConfigureAwait(false);
                            return;
                        }

                        await clientStream.WriteAsync(peeked, 0, peeked.Length).ConfigureAwait(false);

                        Task toServer = CopyAsync(clientStream, serverStream, upstream, fromClient: true);
                        Task toClient = CopyAsync(serverStream, clientStream, client, fromClient: false);
                        Task first = await Task.WhenAny(toServer, toClient).ConfigureAwait(false);

                        if (first.IsFaulted || first.IsCanceled)
                        {
                            client.Dispose();
                            upstream.Dispose();
                        }

                        await Task.WhenAll(toServer, toClient).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    if (!stopped)
                        ConsoleManager.Warning($"[Relais TCP] {endpoint} : {ex.Message}");
                }
                finally
                {
                    lock (sync)
                    {
                        connections.Remove(client);
                        connections.Remove(upstream);
                    }
                }
            }
        }

        // Appelé pour chaque paquet EN CLAIR (en-tête + corps) du pont Noise. Retourner null pour l'avaler.
        private static byte[] OnPlainPacket(bool fromClient, byte[] packet)
        {
            try
            {
                Wire.ParsePacket(fromClient, packet, out int id, out byte[] body);
                ConsoleManager.PostRelayMessage(fromClient, id, MustamMessageNames.GetName(id), body.Length);
                // Pour décoder le contenu avec ton protocole :
                // var msg = MessageReceiver.BuildMessage((uint)id, new AmaknaProxy.API.IO.BigEndianReader(body));
            }
            catch (Exception) { /* l'observation ne doit jamais casser le relais */ }
            return packet;
        }

        private static async Task CopyAsync(NetworkStream source, NetworkStream destination, Socket destinationSocket, bool fromClient)
        {
            var reader = new NoiseHeaderReader(fromClient, (id, length) =>
                ConsoleManager.PostRelayMessage(fromClient, id, MustamMessageNames.GetName(id), length));
            var buffer = new byte[16 * 1024];
            int count;
            while ((count = await source.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                await destination.WriteAsync(buffer, 0, count).ConfigureAwait(false);
                if (reader != null)
                {
                    try
                    {
                        reader.Observe(buffer, count);
                    }
                    catch (Exception)
                    {
                        // Observation is optional. Keep forwarding if the reader fails.
                        reader = null;
                    }
                }
            }
            destinationSocket.Shutdown(SocketShutdown.Send);
        }

        public void Dispose()
        {
            lock (sync)
            {
                stopped = true;
                foreach (Socket socket in connections)
                    socket.Dispose();
                connections.Clear();
            }
        }
    }
}
