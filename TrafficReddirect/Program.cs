using NdisApi;
using PacketDotNet;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

namespace TrafficReddirect {
    class Program {
        private static bool stopCapturing = false;

        private static ManualResetEvent outPacketEvent = new ManualResetEvent(false);

        private static ManualResetEvent inPacketEvent = new ManualResetEvent(false);

        private static IPAddress localIp;
        private static IPAddress vpnIP;

        private static PhysicalAddress localMacAddress; 
        private static PhysicalAddress vpnMacAddress;

        private static readonly BackgroundWorker inWorker = new BackgroundWorker();
        private static readonly BackgroundWorker outWorker = new BackgroundWorker();

        private static List<StaticFilter> filterList = new List<StaticFilter>(3);

        private static string normalAdapterID = "{BEC37E55-8901-46E8-BF94-5A30879F30AF}";
        private static string vpnAdapterID = "{45518F1E-1644-4CE0-8267-D4FC37690B17}";

        static void Main(string[] args) {
            NdisApiDotNet ndisapi = new NdisApiDotNet(null);
            Console.ResetColor();

            Console.CancelKeyPress += HandleCancelKeyPress;

            if (!ndisapi.IsDriverLoaded()) {
                Console.WriteLine("WinpkFilter driver is not loaded. Exiting.");
                return;
            }

            var vpnAdapter = NetworkAdapterHelper.GetAdapterById(ndisapi, vpnAdapterID);
            vpnIP = NetworkAdapterHelper.GetAdapterLocalIP(vpnAdapterID);
            vpnMacAddress = NetworkAdapterHelper.GetAdapterPhisicalAddress(vpnAdapterID);

            var normalAdapter = NetworkAdapterHelper.GetAdapterById(ndisapi, normalAdapterID);
            localIp = NetworkAdapterHelper.GetAdapterLocalIP(normalAdapterID);
            localMacAddress = NetworkAdapterHelper.GetAdapterPhisicalAddress(normalAdapterID);
            Console.WriteLine($"======================================================================================");
            Console.WriteLine($"Found Ethernet Adapter MAC: {localMacAddress} IP: {localIp}");
            Console.WriteLine($"Found VPN Adapter      MAC: {vpnMacAddress} IP: {vpnIP}");
            Console.WriteLine($"======================================================================================");

            if (vpnIP == null) {
                throw new Exception("VPN not connected");
            }

            var tableList = IpHelperWrapper.GetTcpConnections("firefox");

            Console.WriteLine();
            Console.WriteLine($"==============================FireFox sockets=========================================");
            Console.WriteLine($"======================================================================================");
            foreach (var line in tableList) {
                Console.WriteLine($"Source: {line.Local.Address} Port: {line.Local.Port} -> Destination: {line.Remote.Address} Port: {line.Remote.Port}");
            }
            Console.WriteLine($"======================================================================================");

            Console.ReadLine();

            LoadOutFilter(vpnAdapter.Handle, tableList);
            LoadInFilter(normalAdapter.Handle, tableList);

            //LoadTESTInFilter(normalAdapter.Handle, tableList);
            //LoadTESTOutFilter(normalAdapter.Handle, tableList);

            //LoadTESTInFilter(vpnAdapter.Handle, tableList);

            LoadFilterEverythingElseFilter(vpnAdapter.Handle);
            LoadFilterEverythingElseFilter(normalAdapter.Handle);

            var loaded = ndisapi.SetPacketFilterTable(filterList);

            outWorker.DoWork += (s, e) => { TreatOUTPacketsVPNtoNormal(ndisapi, vpnAdapter, normalAdapter); };

            inWorker.DoWork += (s, e) => { TreatINPacketsNormaltoVPN(ndisapi, normalAdapter, vpnAdapter); };

            Console.WriteLine("-- Filtering started");

            outWorker.RunWorkerAsync();
            inWorker.RunWorkerAsync();

            Console.ReadLine();

            Console.WriteLine("-- Filtering stopped");

            DumpStaticFilters(ndisapi);

            Console.WriteLine("Stopped!");
            Console.ReadLine();
        }


        // LISTENS TO VPN ADAPTER AND SENDS THE SPECIFIC PACKETS OUT THE NORMAL ADAPTER
        private static void TreatOUTPacketsVPNtoNormal(NdisApiDotNet outNdisapi, NetworkAdapter vpnAdapter, NetworkAdapter normalAdapter) {
            // Lists for re-injecting packets
            List<RawPacket> toAdapter = new List<RawPacket>();
            List<RawPacket> toMstcp = new List<RawPacket>();

            // Unmanaged memory resource for sending receiving bulk of packets
            // Maximum number of packets to send/receive = 64
            NdisBufferResource buffer = new NdisBufferResource(64);

            outNdisapi.SetAdapterMode(vpnAdapter.Handle, MSTCP_FLAGS.MSTCP_FLAG_TUNNEL);
            outNdisapi.SetPacketEvent(vpnAdapter.Handle, outPacketEvent);

            do {
                outPacketEvent.WaitOne();
                var packetList = outNdisapi.ReadPackets(vpnAdapter.Handle, buffer);

                while (packetList.Item1) {
                    foreach (var packet in packetList.Item2) {
                        Packet p = null;
                        EthernetPacket ethernetPacket = null;
                        TcpPacket tcpPacket = null;
                        IPv4Packet ipv4Packet = null;
                        ushort sport = 0;
                        ushort dport = 0;
                        try {
                            p = Packet.ParsePacket(LinkLayers.Ethernet, packet.Data);
                            ethernetPacket = (EthernetPacket)p;
                            tcpPacket = (TcpPacket)((IPPacket)((EthernetPacket)p).PayloadPacket).PayloadPacket;
                            ipv4Packet = (IPv4Packet)((EthernetPacket)p).PayloadPacket;
                            sport = tcpPacket.SourcePort;
                            dport = tcpPacket.DestinationPort;
                        } catch (Exception ex) {
                            if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE) { toMstcp.Add(packet); } else { toAdapter.Add(packet); }
                            Console.WriteLine($"An exeption {ex.Message} occured while trying to parse network packet. Packet will be let thru without any changes");
                            continue;
                        }

                        DumpSourceChangingFilteredPacket(packet.DeviceFlags,
                                                         ipv4Packet.SourceAddress.ToString(),
                                                         sport.ToString(),
                                                         ipv4Packet.DestinationAddress.ToString(),
                                                         dport.ToString(),
                                                         p.Bytes.Length,
                                                         packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE);

                        if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE) {
                            // Packet was received on VPN adapter, leave it as it is
                            toMstcp.Add(packet);
                        } else {
                            if (ipv4Packet.SourceAddress.Equals(vpnIP)) {
                                // Change the Source for outgoing packets that will later be sent thru normal adapter
                                ipv4Packet.SourceAddress = localIp;
                                ethernetPacket.SourceHardwareAddress = localMacAddress;
                                ipv4Packet.UpdateIPChecksum();
                                tcpPacket.UpdateTcpChecksum();
                                ethernetPacket.UpdateCalculatedValues();
                                var newPackage = new RawPacket() {
                                    Data = p.Bytes,
                                    FilterId = packet.FilterId,
                                    Dot1q = packet.Dot1q,
                                    NdisFlags = packet.NdisFlags,
                                    DeviceFlags = packet.DeviceFlags
                                };
                                toAdapter.Add(newPackage);
                            } else {
                                toAdapter.Add(packet);
                            }
                        }
                    }

                    if (toMstcp.Count > 0) {
                        // If we have packets to forward upwards the network stack then do it here
                        // RECEIVED SHOULD BE TREATED BY VPN ADAPTER
                        outNdisapi.SendPacketsToMstcp(vpnAdapter.Handle, buffer, toMstcp);
                        toMstcp.Clear();
                    }

                    if (toAdapter.Count > 0) {
                        // If we have packets to forward downwards the network stack then do it here
                        // SENT SHOULD BE TREATED BY NORMAL ADAPTER
                        outNdisapi.SendPacketsToAdapter(normalAdapter.Handle, buffer, toAdapter);
                        toAdapter.Clear();
                    }

                    packetList = outNdisapi.ReadPackets(vpnAdapter.Handle, buffer);
                };
                outPacketEvent.Reset();

            } while (!stopCapturing);

            //
            // Release driver and associated resources
            //
            buffer.Dispose();

            outNdisapi.SetPacketEvent(vpnAdapter.Handle, null);

            outNdisapi.SetAdapterMode(vpnAdapter.Handle, 0);
        }


        // LISTENS TO NORMAL ADAPTER AND SENDS THE SPECIFIC PACKETS OUT THE VPN ADAPTER

        private static void TreatINPacketsNormaltoVPN(NdisApiDotNet inNdisapi, NetworkAdapter normalAdapter, NetworkAdapter vpnAdapter) {
            // Lists for re-injecting packets
            List<RawPacket> toAdapter = new List<RawPacket>();
            List<RawPacket> toMstcp = new List<RawPacket>();

            // Unmanaged memory resource for sending receiving bulk of packets
            // Maximum number of packets to send/receive = 64
            NdisBufferResource buffer = new NdisBufferResource(64);

            inNdisapi.SetAdapterMode(normalAdapter.Handle, MSTCP_FLAGS.MSTCP_FLAG_TUNNEL);
            inNdisapi.SetPacketEvent(normalAdapter.Handle, inPacketEvent);

            do {
                inPacketEvent.WaitOne();
                var packetList = inNdisapi.ReadPackets(normalAdapter.Handle, buffer);

                while (packetList.Item1) {
                    foreach (var packet in packetList.Item2) {
                        Packet p = null;
                        EthernetPacket ethernetPacket = null;
                        TcpPacket tcpPacket = null;
                        IPv4Packet ipv4Packet = null;
                        ushort sport = 0;
                        ushort dport = 0;
                        try {
                            p = Packet.ParsePacket(LinkLayers.Ethernet, packet.Data);
                            ethernetPacket = (EthernetPacket)p;
                            tcpPacket = (TcpPacket)((IPPacket)((EthernetPacket)p).PayloadPacket).PayloadPacket;
                            ipv4Packet = (IPv4Packet)((EthernetPacket)p).PayloadPacket;
                            sport = tcpPacket.SourcePort;
                            dport = tcpPacket.DestinationPort;
                        } catch (Exception ex) {
                            if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE) { toMstcp.Add(packet); } else { toAdapter.Add(packet); }
                            Console.WriteLine($"An exeption {ex.Message} occured while trying to parse network packet. Packet will be let thru without any changes");
                            continue;
                        }

                        DumpSourceChangingFilteredPacket(packet.DeviceFlags,
                                                         ipv4Packet.SourceAddress.ToString(),
                                                         sport.ToString(),
                                                         ipv4Packet.DestinationAddress.ToString(),
                                                         dport.ToString(),
                                                         p.Bytes.Length,
                                                         packet.DeviceFlags != PACKET_FLAG.PACKET_FLAG_ON_RECEIVE);

                        if (packet.DeviceFlags == PACKET_FLAG.PACKET_FLAG_ON_RECEIVE) {
                            // Change the Destination for incoming packets that will later be sent thru VPN adapter
                            if (ipv4Packet.DestinationAddress.Equals(localIp)) {
                                ipv4Packet.DestinationAddress = vpnIP;
                                ethernetPacket.DestinationHardwareAddress = vpnMacAddress;
                                ipv4Packet.UpdateIPChecksum();
                                tcpPacket.UpdateTcpChecksum();
                                ethernetPacket.UpdateCalculatedValues();
                                var newPackage = new RawPacket() {
                                    Data = p.Bytes,
                                    FilterId = packet.FilterId,
                                    Dot1q = packet.Dot1q,
                                    NdisFlags = packet.NdisFlags,
                                    DeviceFlags = packet.DeviceFlags
                                };
                                toMstcp.Add(newPackage);
                            } else {
                                toMstcp.Add(packet);
                            }
                        } else {
                            // Packet was sent on VPN adapter, leave it as it is
                            toAdapter.Add(packet);
                        }
                    }

                    if (toMstcp.Count > 0) {
                        // If we have packets to forward upwards the network stack then do it here
                        // RECEIVED SHOULD BE TREATED BY VPN ADAPTER
                        inNdisapi.SendPacketsToMstcp(vpnAdapter.Handle, buffer, toMstcp);
                        toMstcp.Clear();
                    }

                    if (toAdapter.Count > 0) {
                        // If we have packets to forward downwards the network stack then do it here
                        // SENT SHOULD BE TREATED BY NORMAL ADAPTER
                        inNdisapi.SendPacketsToAdapter(normalAdapter.Handle, buffer, toAdapter);
                        toAdapter.Clear();
                    }

                    packetList = inNdisapi.ReadPackets(normalAdapter.Handle, buffer);
                };
                inPacketEvent.Reset();

            } while (!stopCapturing);

            //
            // Release driver and associated resources
            //
            buffer.Dispose();

            inNdisapi.SetPacketEvent(normalAdapter.Handle, null);

            inNdisapi.SetAdapterMode(normalAdapter.Handle, 0);
        }

        private static void LoadInFilter(IntPtr adapterHandle, List<TCPUDPConnection> list) {
            // Incoming HTTP filter: REDIRECT IN TCP packets with source PORT 80
            foreach (var line in list) {
                var ipAddressFilter =
                    new IpAddressFilter(
                        AddressFamily.InterNetwork,
                        IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_DEST_ADDRESS | IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_SRC_ADDRESS,
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, line.Remote.Address, line.Remote.Address),
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, localIp, localIp),
                        6
                    );
                var portFilter =
                    new TcpUdpFilter(
                        TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_DEST_PORT,
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Remote.Port, endRange = (ushort)line.Remote.Port },
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Local.Port, endRange = (ushort)line.Local.Port },
                        0);
                var filter =
                    new StaticFilter(
                    adapterHandle,
                    PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                    StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                    StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                    null,
                    ipAddressFilter,
                    portFilter
                    );
                Console.WriteLine($"FILTER IN Source:{line.Remote.Address}:{line.Remote.Port} Destination:{localIp}:{line.Remote.Port}");
                filterList.Add(filter);
            }
        }

        private static void LoadOutFilter(IntPtr adapterHandle, List<TCPUDPConnection> list) {
            // Outgoing HTTP filter: REDIRECT OUT TCP packets with destination PORT 80
            foreach (var line in list) {
                var ipAddressFilter =
                    new IpAddressFilter(
                        AddressFamily.InterNetwork,
                        IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_DEST_ADDRESS | IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_SRC_ADDRESS,
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, line.Local.Address, line.Local.Address),
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, line.Remote.Address, line.Remote.Address),
                        6
                    );
                var portFilter =
                    new TcpUdpFilter(
                        TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_DEST_PORT,
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Local.Port, endRange = (ushort)line.Local.Port },
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Remote.Port, endRange = (ushort)line.Remote.Port },
                        0);
                var filter =
                    new StaticFilter(
                    adapterHandle,
                    PACKET_FLAG.PACKET_FLAG_ON_SEND,
                    StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                    StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                    null,
                    ipAddressFilter,
                    portFilter
                    );
                Console.WriteLine($"FILTER OUT Source:{line.Local.Address}:{line.Local.Port} Destination:{line.Remote.Address}:{line.Remote.Port}");
                filterList.Add(filter);
            }
        }

        private static void LoadTESTOutFilter(IntPtr adapterHandle, List<TCPUDPConnection> list) {
            // Outgoing HTTP filter: REDIRECT OUT TCP packets with destination PORT 80
            foreach (var line in list) {
                var ipAddressFilter =
                    new IpAddressFilter(
                        AddressFamily.InterNetwork,
                        IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_DEST_ADDRESS | IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_SRC_ADDRESS,
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, line.Local.Address, line.Local.Address),
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, line.Remote.Address, line.Remote.Address),
                        6
                    );
                var portFilter =
                    new TcpUdpFilter(
                        TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_DEST_PORT,
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Local.Port, endRange = (ushort)line.Local.Port },
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Remote.Port, endRange = (ushort)line.Remote.Port },
                        0);
                var filter =
                    new StaticFilter(
                    adapterHandle,
                    PACKET_FLAG.PACKET_FLAG_ON_SEND,
                    StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                    StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                    null,
                    ipAddressFilter,
                    portFilter
                    );
                Console.WriteLine($"FILTER OUT Source:{line.Local.Address}:{line.Local.Port} Destination:{line.Remote.Address}:{line.Remote.Port}");
                filterList.Add(filter);
            }
        }

        private static void LoadTESTInFilter(IntPtr adapterHandle, List<TCPUDPConnection> list) {
            // Incoming HTTP filter: REDIRECT IN TCP packets with source PORT 80
            foreach (var line in list) {
                var ipAddressFilter =
                    new IpAddressFilter(
                        AddressFamily.InterNetwork,
                        IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_DEST_ADDRESS | IpAddressFilter.IP_FILTER_FIELDS.IP_FILTER_SRC_ADDRESS,
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, line.Remote.Address, line.Remote.Address),
                        new IpNetRange(IpNetRange.ADDRESS_TYPE.IP_RANGE_TYPE, line.Local.Address, line.Local.Address),
                        6
                    );
                var portFilter =
                    new TcpUdpFilter(
                        TcpUdpFilter.TCPUDP_FILTER_FIELDS.TCPUDP_DEST_PORT,
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Remote.Port, endRange = (ushort)line.Remote.Port },
                        new TcpUdpFilter.PortRange { startRange = (ushort)line.Local.Port, endRange = (ushort)line.Local.Port },
                        0);
                var filter =
                    new StaticFilter(
                    adapterHandle,
                    PACKET_FLAG.PACKET_FLAG_ON_SEND_RECEIVE,
                    StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_REDIRECT,
                    StaticFilter.STATIC_FILTER_FIELDS.NETWORK_LAYER_VALID | StaticFilter.STATIC_FILTER_FIELDS.TRANSPORT_LAYER_VALID,
                    null,
                    ipAddressFilter,
                    portFilter
                    );
                Console.WriteLine($"FILTER IN Source:{line.Remote.Address}:{line.Remote.Port} Destination:{localIp}:{line.Remote.Port}");
                filterList.Add(filter);
            }
        }

        private static void LoadFilterEverythingElseFilter(IntPtr adapterHandle) {
            // Pass over everything else
            filterList.Add(
                new StaticFilter(
                adapterHandle,
                PACKET_FLAG.PACKET_FLAG_ON_SEND | PACKET_FLAG.PACKET_FLAG_ON_RECEIVE,
                StaticFilter.FILTER_PACKET_ACTION.FILTER_PACKET_PASS,
                0,
                null,
                null,
                null
                ));
        }

        private static void DumpStaticFilters(NdisApiDotNet ndisapi) {
            // Query current filters and print the stats
            var currentFilters = ndisapi.GetPacketFilterTable();

            if (currentFilters.Item1) {
                if (currentFilters.Item2.Count > 0) {
                    Console.WriteLine($"{currentFilters.Item2.Count} static filters were loaded into the driver:");
                    Console.WriteLine();

                    foreach (var filter in currentFilters.Item2) {
                        Console.WriteLine(filter);
                        Console.WriteLine();
                    }
                } else {
                    Console.WriteLine("No static filters were loaded into the driver");
                }
            } else {
                Console.WriteLine("Failed to query filters stats from the driver");
            }
        }

        static void HandleCancelKeyPress(Object sender, ConsoleCancelEventArgs e) {
            Console.WriteLine("-- Stopping packet filter");
            stopCapturing = true;
            outPacketEvent.Set();
            inPacketEvent.Set();

            e.Cancel = true;
        }

        private static void DumpSourceChangingFilteredPacket(PACKET_FLAG packetFlag, string sourceIP, string sourcePort, string destinationIP, string destinationPort, int packetSize, bool error = false) {
            var isSend = packetFlag == PACKET_FLAG.PACKET_FLAG_ON_SEND;
            if (error) {
                Console.ForegroundColor = ConsoleColor.Red;
            } else if (isSend) {
                Console.ForegroundColor = ConsoleColor.Yellow;
            } else {
                Console.ForegroundColor = ConsoleColor.Green;
            }
            Console.WriteLine($"{(isSend ? "SENT    " : "RECEIVED")} Reddirecting VPN -> NORMAL: Source: {sourceIP}:{sourcePort} Destination: {destinationIP}:{destinationPort} SIZE: {packetSize}  ---- Source changed to {localIp}");
            Console.ResetColor();
        }
    }
}
