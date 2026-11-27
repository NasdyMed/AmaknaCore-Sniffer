using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace AmaknaProxy.API.Network
{
    public class SimpleServer
    {

        #region Variables

        private Socket socketListener;
        private volatile bool runing = false;

        public SimpleServer()
        {
            socketListener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        }

        #endregion

        #region Methods

        public void Start(short listenPort, IPAddress listenAddress = null)
        {
            runing = true;
            socketListener.Bind(new IPEndPoint(listenAddress ?? IPAddress.Any, listenPort));
            socketListener.Listen(5);
            socketListener.BeginAccept(BeiginAcceptCallBack, socketListener);
        }

        public void Stop()
        {
            runing = false;
            socketListener.Dispose();
        }

        private void BeiginAcceptCallBack(IAsyncResult result)
        {
            try
            {
                Socket listener = (Socket)result.AsyncState;
                Socket acceptedSocket = listener.EndAccept(result);
                if (!runing)
                {
                    acceptedSocket.Dispose();
                    return;
                }
                OnConnectionAccepted(acceptedSocket);
                listener.BeginAccept(BeiginAcceptCallBack, listener);
            }
            catch (ObjectDisposedException) when (!runing) { }
            catch (SocketException) when (!runing) { }
        }

        #endregion

        #region Events

        public delegate void ConnectionAcceptedDelegate(Socket acceptedSocket);
        public event ConnectionAcceptedDelegate ConnectionAccepted;
        private void OnConnectionAccepted(Socket client)
        {
            if (ConnectionAccepted != null)
                ConnectionAccepted(client);
        }

        #endregion

    }
}
