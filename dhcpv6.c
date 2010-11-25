/*
 *  TAP-Win32/TAP-Win64 -- A kernel driver to provide virtual tap
 *                         device functionality on Windows.
 *
 *  This code was inspired by the CIPE-Win32 driver by Damion K. Wilson.
 *
 *  This source code is Copyright (C) 2002-2010 OpenVPN Technologies, Inc.,
 *  and is released under the GPL version 2 (see below).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

USHORT
ipv6_checksum (const UCHAR *buf,
	       const int buf_len,
	       const IP6HDR *ip6)
{
  int i, checksum = 0;

  // Add IPv6 pseudo header into the checksum
  for (i = 0; i < sizeof (IP6ADDR); ++i)
    {
      checksum += ip6->saddr[i] << ((i%2 == 0)?8:0);
      checksum += ip6->daddr[i] << ((i%2 == 0)?8:0);
    }
  checksum += ntohs (ip6->payload_len);
  checksum += ip6->next_header;

  // Calculate checksum over the actual data
  for (i = 0; i < buf_len; ++i)
    checksum += buf[i] << ((i%2 == 0)?8:0);

  // Finalize checksum
  if (checksum > 0xffff)
    checksum = (checksum & 0xffff) + (checksum >> 16);
  checksum = ~checksum;

  return (USHORT) checksum;
}

BOOLEAN
ProcessNDRouterSolicitation (TapAdapterPointer p_Adapter,
			     const ETH_HEADER *eth,
			     const IP6HDR *ip6,
			     const ICMP6 *icmp6,
			     int optlen)
{
  NDRAMsg *pkt;
  IP6ADDR unspecified = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

  // Check packet according to RFC4861 6.1.1.
  if (ip6->hop_limit != 255
	|| ip6->payload_len < 8
	|| icmp6->code != 0
	|| (IP6ADDR_EQUAL(ip6->saddr, unspecified) && optlen != 0))
    return FALSE;

  pkt = (NDRAMsg *) MemAlloc (sizeof (NDRAMsg), TRUE);

  if (pkt)
    {
      int i;
      USHORT checksum;

      //--------------------------------------------
      // Build ICMPv6 ND Router Advertisement packet
      //--------------------------------------------

      // Build ethernet header

      COPY_MAC (pkt->eth.src, p_Adapter->m_dhcpv6_server_mac);
      COPY_MAC (pkt->eth.dest, eth->src);
      pkt->eth.proto = htons (ETH_P_IPV6);

      // Build IPv6 header

      pkt->ip6.version_traffic = (6 << 4);
      pkt->ip6.payload_len = htons (sizeof (ICMP6NDRA));
      pkt->ip6.next_header = IPPROTO_ICMPV6;
      pkt->ip6.hop_limit = 255;
      COPY_IP6ADDR (pkt->ip6.saddr, p_Adapter->m_dhcpv6_server_ip);
      COPY_IP6ADDR (pkt->ip6.daddr, ip6->saddr);

      // Build ICMPv6 ND Router Advertisement packet

      pkt->radv.type = ICMPV6_ROUTER_ADVERTISEMENT;
      pkt->radv.code = 0;
      pkt->radv.cur_hop_limit = 0;            // Unspecified (default)
      pkt->radv.flags = 0xc0;                 // Managed | Other
      pkt->radv.router_lifetime = htons (0);  // Do not route packets
      pkt->radv.reachable_time = htonl (0);   // Unspecified (default)
      pkt->radv.retrans_timer = htonl (0);    // Unspecified (default)

      // Build ICMPv6 ND Router Advertisement options

      pkt->radv.slla_type = 1;
      pkt->radv.slla_len = 1;
      COPY_MAC (pkt->radv.slla_value, p_Adapter->m_dhcpv6_server_mac);

      pkt->radv.mtu_type = 5;
      pkt->radv.mtu_len = 1;
      if (p_Adapter->m_dhcpv6_mtu && p_Adapter->m_dhcpv6_mtu < p_Adapter->m_MTU)
        pkt->radv.mtu_value = htonl (p_Adapter->m_dhcpv6_mtu);
      else
        pkt->radv.mtu_value = htonl (p_Adapter->m_MTU);

      pkt->radv.pi_type = 3;
      pkt->radv.pi_len = 4;
      pkt->radv.pi_prefixlen = p_Adapter->m_dhcpv6_prefixlen;
      pkt->radv.pi_flags = 0x80;  // On-link prefix, not autonomous
      pkt->radv.pi_valid_lifetime = htonl (p_Adapter->m_dhcpv6_lease_time);
      pkt->radv.pi_preferred_lifetime = htonl (p_Adapter->m_dhcpv6_lease_time);
      COPY_IP6ADDR (pkt->radv.pi_prefix, p_Adapter->m_dhcpv6_addr);
      for (i = p_Adapter->m_dhcpv6_prefixlen; i < 128; ++i)
        {
          // Zero all host bits in prefix as required
          pkt->radv.pi_prefix[i/8] &= ~(0x80 >> (i%8));
        }

      // Calculate the ICMPv6 checksum
      checksum = ipv6_checksum ((UCHAR *) &(pkt->radv),
                                sizeof (ICMP6NDRA),
                                &pkt->ip6);
      pkt->radv.checksum = htons (checksum);

      InjectPacketDeferred (p_Adapter,
                            (UCHAR *) pkt,
                            sizeof (NDRAMsg));

      MemFree (pkt, sizeof (NDRAMsg));
      return TRUE;
    }

  return FALSE;
}

//===================================================================
// Handle a DHCPv6 packet produced by the local system to
// resolve the address/netmask of this adapter.
// If we are in TAP_IOCTL_CONFIG_DHCPV6_MASQ mode, reply
// to the message.  Return TRUE if we processed the passed
// message, so that downstream stages can ignore it.
//===================================================================

BOOLEAN
ProcessDHCPv6 (TapAdapterPointer p_Adapter,
	       const ETH_HEADER *eth,
	       const IP6HDR *ip6,
	       const UDPHDR *udp,
	       const DHCP6 *dhcp6,
	       int optlen)
{
  return FALSE;
}
