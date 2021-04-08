using NdisApi;
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace TrafficReddirect {
    public static class NetworkAdapterHelper {
        public static NetworkAdapter GetAdapterById(NdisApiDotNet ndisapi, string id) {
            var adapterList = ndisapi.GetTcpipBoundAdaptersInfo();
            foreach (var adapter in adapterList.Item2) {
                if (adapter.Name.Contains(id, StringComparison.InvariantCultureIgnoreCase)) {
                    return adapter;
                }
            }
            return null;
        }

        public static IPAddress GetAdapterLocalIP(string adapterId) {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var inter in interfaces) {
                if (inter.Id.Equals(adapterId, StringComparison.InvariantCultureIgnoreCase)) {
                    var ipProps = inter.GetIPProperties();

                    foreach (var ip in ipProps.UnicastAddresses) {
                        if ((inter.OperationalStatus == OperationalStatus.Up) && (ip.Address.AddressFamily == AddressFamily.InterNetwork)) {
                            return ip.Address;
                        }
                    }
                }
            }
            return null;
        }

        public static PhysicalAddress GetAdapterPhisicalAddress(string adapterId) {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var inter in interfaces) {
                if (inter.Id.Equals(adapterId, StringComparison.InvariantCultureIgnoreCase)) {
                    if ((inter.OperationalStatus == OperationalStatus.Up) && (inter.NetworkInterfaceType != NetworkInterfaceType.Loopback)) {
                        return inter.GetPhysicalAddress();
                    }
                }
            }
            return null;
        }
    }
}
