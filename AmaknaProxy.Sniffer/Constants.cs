using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace AmaknaProxy.Sniffer
{
    public static class Constants
    {

        //public static string[] LoginAddresses = { "37.59.57.29" };
        public static string[] LoginAddresses = { "game.mustam.net" };

        public static int[] LoginPorts = { 16561 };

        public static readonly bool RelayLoginTcp = true;

        internal static string[] ResolveLoginAddresses()
        {
            var addresses = LoginAddresses
                .SelectMany(host => IPAddress.TryParse(host, out var address)
                    ? new[] { address }
                    : Dns.GetHostAddresses(host))
                .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
                .Distinct()
                .Select(address => address.ToString())
                .ToArray();

            if (addresses.Length == 0)
                throw new InvalidOperationException("Aucune adresse IPv4 trouvée pour le serveur d’authentification.");

            return addresses;
        }

    }
}
