using NdisApi;
using System;
using System.Net;

namespace TrafficReddirect {
    public static class NetworkAdapterHelper {
        public static NetworkAdapter GetAdapter(NdisApiDotNet ndisapi) {
            var adapterList = ndisapi.GetTcpipBoundAdaptersInfo();

            if (!adapterList.Item1) {
                Console.WriteLine("WinpkFilter failed to query active interfaces. Exiting.");
                return null;
            }

            if (adapterList.Item2.Count > 0)
                Console.WriteLine("Available network interfaces: ");

            Console.WriteLine();

            int counter = 0;
            foreach (var adapter in adapterList.Item2) {
                Console.WriteLine($"{++counter}) {adapter.FriendlyName}");
                Console.WriteLine($"\t Internal name: {adapter.Name}");
                Console.WriteLine($"\t Handle: {adapter.Handle.ToString("x")}");
                Console.WriteLine($"\t MAC: {adapter.CurrentAddress}");
                Console.WriteLine($"\t Medium: {adapter.Medium}");
                Console.WriteLine($"\t MTU: {adapter.Mtu}");

                if (adapter.Medium == NDIS_MEDIUM.NdisMediumWan) {
                    var rasLinkInfoList = ndisapi.GetRasLinks(adapter.Handle);

                    if (rasLinkInfoList.Item1 && (rasLinkInfoList.Item2.Count > 0)) {
                        foreach (var e in rasLinkInfoList.Item2) {
                            Console.WriteLine($"----------------------------------------------------------------");
                            Console.WriteLine($"\t\tLinkSpeed = {e.LinkSpeed}");
                            Console.WriteLine($"\t\tMTU: {e.MaximumTotalSize}");
                            Console.WriteLine($"\t\tLocalAddress: {e.LocalAddress}");
                            Console.WriteLine($"\t\tRemoteAddress: {e.RemoteAddress}");

                            Byte[] ipAddress = new Byte[4];
                            Array.Copy(e.ProtocolBuffer, 584, ipAddress, 0, 4);
                            IPAddress ipV4 = new IPAddress(ipAddress);
                            Array.Copy(e.ProtocolBuffer, 588, ipAddress, 0, 4);
                            IPAddress ipMaskV4 = new IPAddress(ipAddress);

                            Console.WriteLine($"\t\tIPv4: {ipV4} Mask: {ipMaskV4}");
                            Console.WriteLine($"----------------------------------------------------------------");
                        }
                    }
                }

                Console.WriteLine();
            }

            Console.Write("Select network interface: ");
            int index = Convert.ToInt32(Console.ReadLine());

            if (index > adapterList.Item2.Count) {
                Console.WriteLine($"Wrong interface index {index}");
                return null;
            }

            return adapterList.Item2[index - 1];
        }

        public static NetworkAdapter GetVpnAdapter(NdisApiDotNet ndisapi) {
            var adapterList = ndisapi.GetTcpipBoundAdaptersInfo();
            foreach (var adapter in adapterList.Item2) {
                if (adapter.Name.Contains("{45518F1E-1644-4CE0-8267-D4FC37690B17}", StringComparison.InvariantCultureIgnoreCase)) {
                    return adapter;
                }
            }
            return null;
        }

        public static NetworkAdapter GetNormalAdapter(NdisApiDotNet ndisapi) {
            var adapterList = ndisapi.GetTcpipBoundAdaptersInfo();
            foreach (var adapter in adapterList.Item2) {
                if (adapter.Name.Contains("{BEC37E55-8901-46E8-BF94-5A30879F30AF}", StringComparison.InvariantCultureIgnoreCase)) {
                    return adapter;
                }
            }
            return null;
        }
    }
}
