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

#define DHCPV6_USER_SUPPLIED_OPTIONS_BUFFER_SIZE 256
#define DHCPV6_OPTIONS_BUFFER_SIZE               256

//=====================================
// UDP port numbers of DHCPv6 messages.
//=====================================

#define DHCPV6_SERVER_PORT 67
#define DHCPV6_CLIENT_PORT 68

//=============================
// The DHCPv6 message structure
//=============================



#pragma pack()

//====================
// DHCPv6 Option types
//====================



//=====================
// DHCPv6 Message types
//=====================


