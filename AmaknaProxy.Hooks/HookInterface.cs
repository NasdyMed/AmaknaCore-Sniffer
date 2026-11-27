using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AmaknaProxy.Hooks
{
    public class HookInterface : MarshalByRefObject
    {
        private int _count;

        /// <summary>Renseigné par le Sniffer (processus hôte du canal IPC) pour afficher les messages dans sa console.</summary>
        public static Action<string> Sink;

        private static void Write(string text) { if (Sink != null) Sink(text); else Console.WriteLine(text); }

        public void NotifyInstalled(string processName) => Write($"Successfully injected to {processName}.exe !");

        public void Message(string message) => Write(message);

        public void OnError(Exception ex) => Write(ex.ToString());

        /// <summary>
        /// Called to confirm that the IPC channel is still open / host application has not closed
        /// </summary>
        public void Ping()
        {
            // Output token animation to visualise Ping
            var oldTop = Console.CursorTop;
            var oldLeft = Console.CursorLeft;
            Console.CursorVisible = false;

            var chars = "\\|/-";
            Console.Write(chars[_count++ % chars.Length]);

            Console.SetCursorPosition(oldLeft, oldTop);
            Console.CursorVisible = true;
        }
    }
}
