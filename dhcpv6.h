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

#pragma pack(1)

//================================================
// Maximum number of DHCPv6 options bytes supplied
//================================================

#define DHCPV6_USER_SUPPLIED_OPTIONS_BUFFER_SIZE 512
#define DHCPV6_OPTIONS_BUFFER_SIZE               512

//=====================================
// UDP port numbers of DHCPv6 messages.
//=====================================

#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

//=============================================
// The ICMPv6 ND Router Advertisement structure
//=============================================

typedef struct {
  UCHAR   type;
  UCHAR   code;
  USHORT  checksum;
  UCHAR   cur_hop_limit;
  UCHAR   flags;
  USHORT  router_lifetime;
  ULONG   reachable_time;
  ULONG   retrans_timer;

  // Source link-layer address option
  UCHAR   slla_type;
  UCHAR   slla_len;
  MACADDR slla_value;

  // MTU option
  UCHAR   mtu_type;
  UCHAR   mtu_len;
  USHORT  mtu_reserved;
  ULONG   mtu_value;

  // Prefix information option
  UCHAR   pi_type;
  UCHAR   pi_len;
  UCHAR   pi_prefixlen;
  UCHAR   pi_flags;
  ULONG   pi_valid_lifetime;
  ULONG   pi_preferred_lifetime;
  ULONG   pi_reserved;
  IP6ADDR pi_prefix;
} ICMP6NDRA;

typedef struct {
  ETH_HEADER  eth;
  IP6HDR      ip6;
  ICMP6NDRA   radv;
} NDRAMsg;

//=============================
// The DHCPv6 message structure
//=============================

typedef struct {
#define DHCP6_GET_ID(s) (((s)->hid << 16) | (s)->lid)
  UCHAR  type;
  UCHAR  hid;
  USHORT lid;
} DHCP6;

typedef struct {
  ETH_HEADER  eth;
  IP6HDR      ip6;
  UDPHDR      udp;
  DHCP6       dhcp6;
} DHCP6Pre;

typedef struct {
  USHORT   code;
  USHORT   len;
} DHCP6Opt;

typedef struct {
  USHORT   code;
  USHORT   len;
  USHORT   type;
  USHORT   hwtype;
  MACADDR  macaddr;
} DHCP6OptServerID;

typedef struct {
  USHORT  code;
  USHORT  len;
  ULONG   iaid;
  ULONG   t1;
  ULONG   t2;

  // IA Address option
  USHORT  ia_code;
  USHORT  ia_len;
  IP6ADDR ia_addr;
  ULONG   ia_preferred_lifetime;
  ULONG   ia_valid_lifetime;
} DHCP6OptIANA;

typedef struct {
  DHCP6Pre    pre;
  UCHAR       options[DHCPV6_OPTIONS_BUFFER_SIZE];
} DHCP6Full;

typedef struct {
  unsigned int optlen;
  BOOLEAN overflow;
  DHCP6Full msg;
} DHCP6Msg;

#pragma pack()

//====================
// Macros for DHCP6Msg
//====================

#define DHCP6MSG_LEN_BASE(p) (sizeof (DHCP6Pre))
#define DHCP6MSG_LEN_OPT(p)  ((p)->optlen)
#define DHCP6MSG_LEN_FULL(p) (DHCP6MSG_LEN_BASE(p) + DHCP6MSG_LEN_OPT(p))
#define DHCP6MSG_BUF(p)      ((UCHAR*) &(p)->msg)
#define DHCP6MSG_OVERFLOW(p) ((p)->overflow)

//====================
// DHCPv6 Option types
//====================

#define DHCPV6_SOLICIT      1
#define DHCPV6_ADVERTISE    2
#define DHCPV6_REQUEST      3
#define DHCPV6_CONFIRM      4
#define DHCPV6_RENEW        5
#define DHCPV6_REBIND       6
#define DHCPV6_REPLY        7
#define DHCPV6_RELEASE      8
#define DHCPV6_DECLINE      9
#define DHCPV6_RECONFIGURE  10
#define DHCPV6_INFORMATION_REQUEST 11
#define DHCPV6_RELAY_FORW   12
#define DHCPV6_RELAY_REPL   13

//=====================
// DHCPv6 Message types
//=====================

