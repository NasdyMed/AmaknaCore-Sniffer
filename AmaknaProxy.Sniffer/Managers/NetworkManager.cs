using AmaknaProxy.API.Managers;
using AmaknaProxy.API.Network;
using AmaknaProxy.Sniffer;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace AmaknaProxy.Engine.Managers
{
    public class NetworkManager
    {

        #region Variables

        private static SimpleServer Login_Server;

        private static SimpleServer Game_Server;
        private static TcpRelay loginRelay;

        public static bool Running;

        #endregion

        #region Builder

        static NetworkManager()
        {
            Running = false;
        }

        #endregion

        #region Methods

        public static void StartServers()
        {
            if (Running == true)
                return;

            try
            {
                Login_Server = new SimpleServer();
                if (Constants.RelayLoginTcp)
                {
                    var relay = new TcpRelay();
                    loginRelay = relay;
                    Login_Server.ConnectionAccepted += client => { _ = ForwardLoginAsync(relay, client); };
                    Login_Server.Start(5555, IPAddress.Loopback);
                    ConsoleManager.Info("[Relais TCP] Écoute sur 127.0.0.1:5555.");
                }
                else
                {
                    Game_Server = new SimpleServer();
                    Login_Server.ConnectionAccepted += Login_ConnectionAccepted;
                    Game_Server.ConnectionAccepted += Game_ConnectionAccepted;
                    Login_Server.Start(5555);
                    Game_Server.Start(443);
                }

                Running = true;
            }
            catch(Exception ex)
            {
                StopServers();
                WindowManager.MainWindow.Logger.Error("[Network] " + ex.Message);
            }
        }

        public static void StopServers()
        {
            try
            {
                Login_Server?.Stop();
                Login_Server = null;

                Game_Server?.Stop();
                Game_Server = null;
                loginRelay?.Dispose();
                loginRelay = null;

                Running = false;
            }
            catch (Exception ex)
            {
                WindowManager.MainWindow.Logger.Error("[Network] " + ex.Message);
            }
        }

        #endregion

        #region Events

        private static void Login_ConnectionAccepted(Socket sender)
        {
            WindowManager.MainWindow.Logger.Info("Nouveau client sur le serveur d'authentification.");
            ClientsManager.RegisterClient(sender, true);
        }

        private static void Game_ConnectionAccepted(Socket sender)
        {
            WindowManager.MainWindow.Logger.Info("Nouveau client sur le serveur de jeu.");
            ClientsManager.RegisterClient(sender, false);
        }

        private static async Task ForwardLoginAsync(TcpRelay relay, Socket client)
        {
            try
            {
                string[] addresses = Constants.ResolveLoginAddresses();
                var random = new Random(Guid.NewGuid().GetHashCode());
                IPAddress address = IPAddress.Parse(addresses[random.Next(addresses.Length)]);
                int port = Constants.LoginPorts[random.Next(Constants.LoginPorts.Length)];
                await relay.ForwardAsync(client, new IPEndPoint(address, port)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                client.Dispose();
                ConsoleManager.Warning($"[Relais TCP] {ex.Message}");
            }
        }

        #endregion
    }
}
