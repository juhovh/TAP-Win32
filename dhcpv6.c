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
  return TRUE;
}
