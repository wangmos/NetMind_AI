using System.Buffers.Binary;
using System.Net;

namespace NetMind.Core;

/// <summary>从 IP 报文解析出的 TCP 报文事实：地址、端口、序号、标志位与负载。</summary>
public sealed record SilentTcpPacket(
    IPAddress SourceAddress,
    ushort SourcePort,
    IPAddress DestinationAddress,
    ushort DestinationPort,
    uint Sequence,
    bool Syn,
    bool Ack,
    bool Fin,
    bool Rst,
    byte[] Payload);

/// <summary>从 IP 报文解析出的 UDP 报文事实：地址、端口与负载（QUIC 捕获用）。</summary>
public sealed record SilentUdpPacket(
    IPAddress SourceAddress,
    ushort SourcePort,
    IPAddress DestinationAddress,
    ushort DestinationPort,
    byte[] Payload);

/// <summary>
/// IPv4/IPv6 + TCP/UDP 头部解析（纯函数，不依赖驱动与套接字）。
/// IPv6 仅处理常见扩展头（逐跳、路由、目的选项、分片）；未知扩展头按放弃处理。
/// </summary>
public static class SilentPacketParser
{
    private const byte ProtocolTcp = 6;
    private const byte ProtocolUdp = 17;

    public static bool TryParseTcpPacket(ReadOnlySpan<byte> packet, bool ipv6, out SilentTcpPacket parsed)
    {
        parsed = null!;
        ReadOnlySpan<byte> tcp;
        IPAddress source;
        IPAddress destination;
        if (ipv6)
        {
            if (packet.Length < 40) return false;
            var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
            var nextHeader = packet[6];
            var offset = 40;
            while (nextHeader is 0 or 43 or 60)
            {
                if (packet.Length < offset + 2) return false;
                var extensionNext = packet[offset];
                offset += (packet[offset + 1] + 1) * 8;
                nextHeader = extensionNext;
            }
            if (nextHeader == 44) // 分片头固定 8 字节
            {
                if (packet.Length < offset + 8) return false;
                nextHeader = packet[offset];
                offset += 8;
            }
            if (nextHeader != ProtocolTcp) return false;
            var tcpLength = Math.Min(payloadLength - (offset - 40), packet.Length - offset);
            if (tcpLength < 20) return false;
            tcp = packet.Slice(offset, tcpLength);
            source = new IPAddress(packet[8..24].ToArray());
            destination = new IPAddress(packet[24..40].ToArray());
        }
        else
        {
            if (packet.Length < 20) return false;
            var headerLength = (packet[0] & 0x0F) * 4;
            if (headerLength < 20 || packet.Length < headerLength || packet[9] != ProtocolTcp) return false;
            var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
            var tcpLength = Math.Min(totalLength - headerLength, packet.Length - headerLength);
            if (tcpLength < 20) return false;
            tcp = packet.Slice(headerLength, tcpLength);
            source = new IPAddress(packet.Slice(12, 4).ToArray());
            destination = new IPAddress(packet.Slice(16, 4).ToArray());
        }

        var dataOffset = (tcp[12] >> 4) * 4;
        if (dataOffset < 20 || tcp.Length < dataOffset) return false;
        var flags = tcp[13];
        parsed = new SilentTcpPacket(
            source, BinaryPrimitives.ReadUInt16BigEndian(tcp),
            destination, BinaryPrimitives.ReadUInt16BigEndian(tcp[2..]),
            BinaryPrimitives.ReadUInt32BigEndian(tcp[4..]),
            Syn: (flags & 0x02) != 0,
            Ack: (flags & 0x10) != 0,
            Fin: (flags & 0x01) != 0,
            Rst: (flags & 0x04) != 0,
            Payload: tcp[dataOffset..].ToArray());
        return true;
    }

    public static bool TryParseUdpPacket(ReadOnlySpan<byte> packet, bool ipv6, out SilentUdpPacket parsed)
    {
        parsed = null!;
        ReadOnlySpan<byte> udp;
        IPAddress source;
        IPAddress destination;
        if (ipv6)
        {
            if (packet.Length < 40) return false;
            var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
            var nextHeader = packet[6];
            var offset = 40;
            while (nextHeader is 0 or 43 or 60)
            {
                if (packet.Length < offset + 2) return false;
                var extensionNext = packet[offset];
                offset += (packet[offset + 1] + 1) * 8;
                nextHeader = extensionNext;
            }
            if (nextHeader == 44)
            {
                if (packet.Length < offset + 8) return false;
                nextHeader = packet[offset];
                offset += 8;
            }
            if (nextHeader != ProtocolUdp) return false;
            var udpLength = Math.Min(payloadLength - (offset - 40), packet.Length - offset);
            if (udpLength < 8) return false;
            udp = packet.Slice(offset, udpLength);
            source = new IPAddress(packet[8..24].ToArray());
            destination = new IPAddress(packet[24..40].ToArray());
        }
        else
        {
            if (packet.Length < 20) return false;
            var headerLength = (packet[0] & 0x0F) * 4;
            if (headerLength < 20 || packet.Length < headerLength || packet[9] != ProtocolUdp) return false;
            var totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
            var udpLength = Math.Min(totalLength - headerLength, packet.Length - headerLength);
            if (udpLength < 8) return false;
            udp = packet.Slice(headerLength, udpLength);
            source = new IPAddress(packet.Slice(12, 4).ToArray());
            destination = new IPAddress(packet.Slice(16, 4).ToArray());
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(udp[4..]);
        if (length < 8 || udp.Length < 8) return false;
        var payloadEnd = Math.Min(length, udp.Length);
        parsed = new SilentUdpPacket(
            source, BinaryPrimitives.ReadUInt16BigEndian(udp),
            destination, BinaryPrimitives.ReadUInt16BigEndian(udp[2..]),
            Payload: udp[8..payloadEnd].ToArray());
        return true;
    }

    /// <summary>判定负载首部是否为 TLS ClientHello（记录类型 0x16 + 版本主字节 0x03）。</summary>
    public static bool LooksLikeTlsClientHello(ReadOnlySpan<byte> payload) =>
        payload.Length >= 6 && payload[0] == 0x16 && payload[1] == 0x03;

    /// <summary>从 TLS ClientHello 中提取 SNI 主机名；解析失败返回 null。</summary>
    public static string? TryParseTlsServerName(ReadOnlySpan<byte> payload)
    {
        try
        {
            if (payload.Length < 6 || payload[0] != 0x16) return null;
            var recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload[3..]);
            var handshake = payload.Slice(5, Math.Min(recordLength, payload.Length - 5));
            if (handshake.Length < 4 || handshake[0] != 0x01) return null; // ClientHello
            var helloLength = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
            var hello = handshake.Slice(4, Math.Min(helloLength, handshake.Length - 4));
            if (hello.Length < 34) return null; // 版本(2) + 随机数(32)
            var offset = 34;
            var sessionIdLength = hello[offset]; offset += 1 + sessionIdLength;
            if (offset + 2 > hello.Length) return null;
            offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]); // 密码套件
            if (offset + 1 > hello.Length) return null;
            offset += 1 + hello[offset]; // 压缩方法
            if (offset + 2 > hello.Length) return null;
            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
            offset += 2;
            var extensionsEnd = offset + Math.Min(extensionsLength, hello.Length - offset);
            while (offset + 4 <= extensionsEnd)
            {
                var type = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
                var length = BinaryPrimitives.ReadUInt16BigEndian(hello[(offset + 2)..]);
                offset += 4;
                if (offset + length > hello.Length) break;
                if (type == 0 && length > 5) // server_name
                {
                    var list = hello.Slice(offset, length);
                    var entryType = list[2];
                    var nameLength = BinaryPrimitives.ReadUInt16BigEndian(list[3..]);
                    if (entryType == 0 && nameLength > 0 && 5 + nameLength <= list.Length)
                        return System.Text.Encoding.ASCII.GetString(list.Slice(5, nameLength));
                }
                offset += length;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }
}
