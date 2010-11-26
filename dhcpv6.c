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


//===========================
// Code to set DHCPv6 options
//===========================

VOID
SetDHCP6Opt (DHCP6Msg *m, void *data, unsigned int len)
{
  if (!m->overflow)
    {
      if (m->optlen + len <= DHCPV6_OPTIONS_BUFFER_SIZE)
        {
	  if (len)
	    {
	      NdisMoveMemory (m->msg.options + m->optlen, data, len);
	      m->optlen += len;
	    }
	}
      else
        {
	  m->overflow = TRUE;
	}
    }
}

VOID
SetDHCP6OptServerID (DHCP6Msg *msg,
		     MACADDR addr)
{
  DHCP6OptServerID opt;
  opt.code = htons (2);   // Server identifier
  opt.len = htons (10);   // Content length 10
  opt.type = htons (3);   // Type DUID-LL (link-layer)
  opt.hwtype = htons (1); // Hardware type: Ethernet
  COPY_MAC (opt.macaddr, addr);
  SetDHCP6Opt (msg, &opt, sizeof (opt));
}

VOID
SetDHCP6OptIANA (DHCP6Msg *msg,
		 ULONG iaid,
		 IP6ADDR ip6addr,
		 ULONG lifetime)
{
  DHCP6OptIANA opt;
  opt.code = htons (3);    // Identity Association for Non-temporary Address
  opt.len = htons (40);    // Content length 40
  opt.iaid = htonl (iaid); // Identity Association ID
  opt.t1 = htonl (0);      // T1 unspecified (up to client)
  opt.t2 = htonl (0);      // T2 unspecified (up to client);
  opt.ia_code = htons (5); // Option code: IA Address
  opt.ia_len = htons (24); // Option length: 24 (16+4+4)
  COPY_IP6ADDR (opt.ia_addr, ip6addr);
  opt.ia_preferred_lifetime = htonl (lifetime);
  opt.ia_valid_lifetime = htonl (lifetime);
  SetDHCP6Opt (msg, &opt, sizeof (opt));
}

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
RouterSolicitationOurs (const TapAdapterPointer p_Adapter,
			const ETH_HEADER *eth,
			const IP6HDR *ip6,
			const ICMP6 *icmp6)
{
  MACADDR mac_all_routers = { 0x33,0x33,0x00,0x00,0x00,0x02 };
  IP6ADDR ip6_all_routers = { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2 };

  // Must be ICMPv6 protocol
  if (!(eth->proto == htons (ETH_P_IPV6) && ip6->next_header == IPPROTO_ICMPV6))
    return FALSE;

  // Source MAC must be our adapter
  if (!MAC_EQUAL (eth->src, p_Adapter->m_MAC))
    return FALSE;

  // Dest MAC must be all routers multicast or our virtual server
  if (!(MAC_EQUAL (eth->dest, mac_all_routers)
	|| MAC_EQUAL (eth->dest, p_Adapter->m_dhcpv6_server_mac)))
    return FALSE;

  // Dest IPv6 address must be all routers or our virtual server
  if (!(IP6ADDR_EQUAL (ip6->daddr, ip6_all_routers)
	|| IP6ADDR_EQUAL (ip6->daddr, p_Adapter->m_dhcpv6_server_ip)))
    return FALSE;

  return TRUE;
}

BOOLEAN
DHCPv6MessageOurs (const TapAdapterPointer p_Adapter,
		   const ETH_HEADER *eth,
		   const IP6HDR *ip6,
		   const UDPHDR *udp,
		   const DHCP6 *dhcp6)
{
  MACADDR mac_all_dhcp_servers = { 0x33,0x33,0x00,0x01,0x00,0x02 };
  IP6ADDR ip6_all_dhcp_servers = { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,1,0,2 };

  // Must be UDPv6 protocol
  if (!(eth->proto == htons (ETH_P_IPV6) && ip6->next_header == IPPROTO_UDP))
    return FALSE;

  // Source MAC must be our adapter
  if (!MAC_EQUAL (eth->src, p_Adapter->m_MAC))
    return FALSE;

  // Dest MAC must be All_DHCP_Relay_Agents_and_Servers
  if (!MAC_EQUAL (eth->dest, mac_all_dhcp_servers))
    return FALSE;

  // Dest IPv6 address must be All_DHCP_Relay_Agents_and_Servers
  if (!IP6ADDR_EQUAL (ip6->daddr, ip6_all_dhcp_servers))
    return FALSE;

  // Port numbers must be correct
  if (!(udp->dest == htons (DHCPV6_SERVER_PORT)
	&& udp->source == htons (DHCPV6_CLIENT_PORT)))
    return FALSE;

  return TRUE;
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

  // Sanity check IP header
  if (!(ntohs (ip6->payload_len) == sizeof (ICMP6) + optlen))
    return TRUE;

  // Check packet according to RFC4861 6.1.1.
  if (ip6->hop_limit != 255
	|| ip6->payload_len < sizeof (ICMP6)
	|| icmp6->code != 0
	|| (IP6ADDR_EQUAL(ip6->saddr, unspecified) && optlen != 0))
    return TRUE;

  // Does this message belong to us?
  if (!RouterSolicitationOurs (p_Adapter, eth, ip6, icmp6))
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
    }

  return FALSE;
}

VOID
BuildDHCP6Pre (const TapAdapterPointer a,
	       DHCP6Pre *p,
	       const ETH_HEADER *eth,
	       const IP6HDR *ip6,
	       const UDPHDR *udp,
	       const DHCP6 *dhcp6,
	       const int optlen,
	       const UCHAR type)
{
  // Build ethernet header

  COPY_MAC (p->eth.src, a->m_dhcp_server_mac);
  COPY_MAC (p->eth.dest, eth->src);
  p->eth.proto = htons (ETH_P_IPV6);

  // Build IPv6 header

  p->ip6.version_traffic = (6 << 4);
  p->ip6.payload_len = htons (sizeof (UDPHDR) + sizeof (DHCP6) + optlen);
  p->ip6.next_header = IPPROTO_UDP;
  p->ip6.hop_limit = 255;
  COPY_IP6ADDR (p->ip6.saddr, a->m_dhcpv6_server_ip);
  COPY_IP6ADDR (p->ip6.daddr, ip6->saddr);

  // Build UDP header

  p->udp.source = htons (DHCPV6_SERVER_PORT);
  p->udp.dest = htons (DHCPV6_CLIENT_PORT);
  p->udp.len = htons (sizeof (UDPHDR) + sizeof (DHCP6) + optlen);
  p->udp.check = 0;

  // Build DHCPv6 response

  p->dhcp6.type = type;
  p->dhcp6.hid = dhcp6->hid;
  p->dhcp6.lid = dhcp6->lid;
}

BOOLEAN
SendDHCPv6Msg (TapAdapterPointer p_Adapter,
	       const UCHAR type,
	       const ETH_HEADER *eth,
	       const IP6HDR *ip6,
	       const UDPHDR *udp,
	       const DHCP6 *dhcp6,
	       int optlen)
{
  DHCP6Msg *pkt;

  if (!(type == DHCPV6_ADVERTISE
	|| type == DHCPV6_REPLY
	|| type == DHCPV6_DECLINE))
    {
      DEBUGP (("[TAP] SendDHCPv6Msg: Bad DHCPv6 type: %d\n", type));
      return FALSE;
    }

  pkt = (DHCP6Msg *) MemAlloc (sizeof (DHCP6Msg), TRUE);
  
  if (pkt)
    {
      UCHAR *optbuf;
      int optbufidx;

      BOOLEAN has_iaid;
      ULONG iaid = 0;
      UCHAR *clientid = NULL;
      int clientidlen = 0;

      //---------------------
      // Build DHCPv6 options
      //---------------------

      optbuf = (UCHAR *) (dhcp6 + 1);
      optbufidx = 0;
      while (optbufidx+4 < optlen)
        {
	  USHORT optcode = ((USHORT *)(optbuf+optbufidx))[0];
	  USHORT optlen = ((USHORT *)(optbuf+optbufidx))[1];

	  if (optlen > optlen-optbufidx-4)
	    break;

	  if (optcode == ntohs (1))
	    {
	      // Client identifier found
	      clientid = optbuf+optbufidx;
	      clientidlen = 4+optlen;
	    }
	  else if (optcode == ntohs (3))
	    {
	      // Identity Association for Non-temporary Address found
	      DHCP6OptIANA *iana_opt = (DHCP6OptIANA *)(optbuf+optbufidx);
	      iaid = ntohl(iana_opt->iaid);
	      has_iaid = TRUE;
	    }

	  optbufidx += 4+optlen;
	}

      // Invalid options found, return failure
      if (optbufidx != optlen)
        {
	  MemFree (pkt, sizeof (DHCP6Msg));
	  return FALSE;
	}

      // Make sure solicitation has required options
      if (!clientid || !has_iaid)
        {
	  MemFree (pkt, sizeof (DHCP6Msg));
	  return FALSE;
        }

      SetDHCP6Opt (pkt, clientid, clientidlen);
      SetDHCP6OptServerID (pkt, p_Adapter->m_dhcpv6_server_mac);
      SetDHCP6OptIANA (pkt, iaid, p_Adapter->m_dhcpv6_addr,
		       p_Adapter->m_dhcpv6_lease_time);
      SetDHCP6Opt (pkt,
		   p_Adapter->m_dhcpv6_user_supplied_options_buffer,
		   p_Adapter->m_dhcpv6_user_supplied_options_buffer_len);
      
      if (!DHCP6MSG_OVERFLOW (pkt))
        {
	  USHORT checksum;

	  BuildDHCP6Pre (p_Adapter,
			 &pkt->msg.pre,
			 eth,
			 ip6,
			 udp,
			 dhcp6,
			 DHCP6MSG_LEN_OPT (pkt),
			 type);

	  // Calculate the UDP checksum
	  checksum = ipv6_checksum ((UCHAR *) &pkt->msg.pre.udp,
				    sizeof (UDPHDR) + sizeof (DHCP6) + pkt->optlen,
				    &pkt->msg.pre.ip6);
				    pkt->msg.pre.udp.check = htons (checksum);

	  InjectPacketDeferred (p_Adapter,
				DHCPMSG_BUF (pkt),
				DHCPMSG_LEN_FULL (pkt));
	}
      else
	{
	  DEBUGP (("[TAP] SendDHCPv6Msg: DHCP buffer overflow\n"));
	}

      MemFree (pkt, sizeof (DHCP6Msg));
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
  // Sanity check IP header
  if (!(ntohs (ip6->payload_len) == sizeof (UDPHDR) + sizeof (DHCP6) + optlen))
    return TRUE;

  // Does this message belong to us?
  if (!DHCPv6MessageOurs (p_Adapter, eth, ip6, udp, dhcp6))
    return FALSE;

  // Accept only SOLICIT, REQUEST and RENEW
  if (!(dhcp6->type == DHCPV6_SOLICIT
	|| dhcp6->type == DHCPV6_REQUEST
	|| dhcp6->type == DHCPV6_RENEW))
    return FALSE;

  // Attempt to send reply, drop packet if fails (invalid packet)
  if (!SendDHCPv6Msg (p_Adapter, DHCPV6_ADVERTISE, eth, ip6, udp, dhcp6, optlen))
    return TRUE;

  return FALSE;
}
