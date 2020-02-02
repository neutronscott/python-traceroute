#!/usr/bin/env python3
"""Starwars traceroute using raw ethernet socket in Python3.

This is my first dive into Python and learning the Pythonic ways.
The fib and filter globals need modified for your environment.

created: 2020-02-01
author:  Scott Nicholas <scott@nicholas.one>
"""

import ctypes
import struct
from ctypes import create_string_buffer, addressof
from struct import pack, unpack
import copy
import socket
import array

# Ethernet interface to bind to
INTERFACE = 'ens3'

def ttl2ip(ttl, dest):
  """Define our extra hops here.

  TTL 1 is handled by our real interface, let's leave that alone.
  Therefore it starts with ttl-2 index into this list but you can
  do whatever math or list you want.

  Need to cover all TTL in filter and higher should return dest
  I cover TTL from 2..16 which is 15 hosts, 14 fib numbers and dest itself
  or TTL >16 if ICMP ECHO REQUEST goes back to send_echo_reply

  Returns:
    ip in list format. str should be OK too.
    None if we should ignore this, TTL is too high
  """

  fib = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233]
  hop = ttl - 2
  if hop == len(fib):
    return dest
  if hop > len(fib):
    raise ValueError
  return [44, 38, 10, fib[hop]]

"""The BPF filter code from tcpdump.

get the C-struct from tcpdump using -dd
make sure you reference correct interface
whereas my default interface was ip, i will be
opening my ethernet interface.

# tcpdump -p -i ens3 -dd 'ip[8] > 1 and dst host 44.38.10.234 and (icmp[icmptype]==8 or ip[8] < 17)' | tr {} '()'
"""
filter = [
  ( 0x28, 0, 0, 0x0000000c ),
  ( 0x15, 0, 14, 0x00000800 ),
  ( 0x30, 0, 0, 0x00000016 ),
  ( 0x25, 0, 12, 0x00000001 ),
  ( 0x20, 0, 0, 0x0000001e ),
  ( 0x15, 0, 10, 0x2c260aea ),
  ( 0x30, 0, 0, 0x00000017 ),
  ( 0x15, 0, 5, 0x00000001 ),
  ( 0x28, 0, 0, 0x00000014 ),
  ( 0x45, 3, 0, 0x00001fff ),
  ( 0xb1, 0, 0, 0x0000000e ),
  ( 0x50, 0, 0, 0x0000000e ),
  ( 0x15, 2, 0, 0x00000008 ),
  ( 0x30, 0, 0, 0x00000016 ),
  ( 0x35, 1, 0, 0x00000011 ),
  ( 0x6, 0, 0, 0x00040000 ),
  ( 0x6, 0, 0, 0x00000000 ),
]

class PHdr(ctypes.BigEndianStructure):
  """Base class for protocol headers."""
  def __len__(self):
    return ctypes.sizeof(self)

class ethhdr(PHdr):
  """From include/uapi/linux/if_ether.h."""

  ETH_ALEN = 6

  _fields_ = [
    ("h_dest", ctypes.c_ubyte * ETH_ALEN),
    ("h_source", ctypes.c_ubyte * ETH_ALEN),
    ("h_proto", ctypes.c_uint16)
  ]

class iphdr(PHdr):
  """From incude/linux/ip.h."""

  _fields_ = [
    ("version", ctypes.c_ubyte, 4),
    ("ihl", ctypes.c_ubyte, 4),
    ("tos", ctypes.c_ubyte),
    ("tot_len", ctypes.c_uint16),
    ("id", ctypes.c_uint16),
    ("frag_off", ctypes.c_uint16),
    ("ttl", ctypes.c_ubyte),
    ("protocol", ctypes.c_ubyte),
    ("check", ctypes.c_uint16),
    ("_saddr", ctypes.c_uint32),
    ("_daddr", ctypes.c_uint32)
  ]

  def __get_addr(self, addr):
    return socket.inet_ntoa(struct.pack('>I', addr))

  def __set_addr(self, addr, ip):
    if isinstance(ip, str):
      self._saddr = struct.unpack('>I', socket.inet_aton(ip))[0]
    elif isinstance(ip, list):
      self._saddr = int.from_bytes(ip, 'big')
    else:
      raise TypeError

  @property
  def saddr(self):
    return self.__get_addr(self._saddr)

  @saddr.setter
  def saddr(self, *args, **kwargs):
    return self.__set_addr(self._saddr, *args, **kwargs)

  @property
  def daddr(self):
    return self.__get_addr(self._daddr)

  @daddr.setter
  def daddr(self, *args, **kwargs):
    return self.__set_addr(self._daddr, *args, **kwargs)

class icmphdr(PHdr):
  _fields_ = [
    ("type", ctypes.c_ubyte),
    ("code", ctypes.c_ubyte),
    ("checksum", ctypes.c_uint16),
    ("id", ctypes.c_uint16),
    ("sequence", ctypes.c_uint16)
  ]

def checksum(pkt):
    if len(pkt) % 2 == 1:
        pkt += b'\0'
    s = sum(array.array("H", pkt))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s
    return (((s>>8)&0xff)|s<<8) & 0xffff

def send_ttl_expire(s, in_eth, in_ip, payload):
  """Send ICMP TIME expired from each fake hop."""
  icmp = icmphdr(11, 0, 0, 0, 0)
  try:
    saddr = ttl2ip(in_ip.ttl, in_ip.daddr)
  except ValueError:
    raise ValueError
  ip = copy.copy(in_ip)
  ip.protocol = 1
  ip.tot_len = len(ip) + len(icmp) + len(payload)
  ip.ttl = 63
  ip.saddr = saddr
  ip._daddr = in_ip._saddr
  ip.check = 0
  ip.check = checksum(bytearray(ip))

  eth = ethhdr(in_eth.h_source, in_eth.h_dest, in_eth.h_proto)

  icmp.checksum = checksum(bytearray(icmp) + payload)

  msg = create_string_buffer(len(eth) + len(ip) + len(icmp) + len(payload))
  msg = bytearray(eth) + bytearray(ip) + bytearray(icmp) + payload

  print("  %16s <- %16s ttl:%03d proto:%-3d icmp type:%-3d code:%-3d" % (ip.daddr, ip.saddr, ip.ttl, ip.protocol, icmp.type, icmp.code))
  ret = s.send(msg)

def send_echo_reply(s, in_eth, in_ip, payload):
  """Send normal ICMP ECHO reply."""
  icmp = icmphdr.from_buffer_copy(payload)
  icmp.type = 0
  icmp.code = 0
  payload = payload[len(icmp):]

  ip = copy.copy(in_ip)
  ip.tot_len = len(ip) + len(icmp) + len(payload)
  ip.ttl = 63
  ip._saddr = in_ip._daddr
  ip._daddr = in_ip._saddr
  ip.check = 0
  ip.check = checksum(bytearray(ip))

  eth = ethhdr(in_eth.h_source, in_eth.h_dest, in_eth.h_proto)

  icmp.checksum = 0
  icmp.checksum = checksum(bytearray(icmp) + payload)

  msg = create_string_buffer(len(eth) + len(ip) + len(icmp) + len(payload))
  msg = bytearray(eth) + bytearray(ip) + bytearray(icmp) + payload

  print("  %16s <- %16s ihl:%02d ttl:%03d proto:%-3d icmp type:%-3d code:%-3d" % (ip.daddr, ip.saddr, ip.ihl, ip.ttl, ip.protocol, icmp.type, icmp.code))
  ret = s.send(msg)

def main():
  blob = ctypes.create_string_buffer(b''.join(struct.pack("HBBI", *e) for e in filter))
  bpf = struct.pack('HL', len(filter), addressof(blob))
  
  # As defined in asm/socket.h
  SO_ATTACH_FILTER = 26
  
  # Create listening socket with filters
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
  s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bpf)
  s.bind((INTERFACE, 0x800))
  
  while True:
      data, addr = s.recvfrom(65565)
      eth = ethhdr.from_buffer_copy(data)
      ip = iphdr.from_buffer_copy(data[len(eth):])

      # someone might ends these one day...?
      ipoptslen = (4 * ip.ihl) - len(ip)

      print("%s %16s -> %16s ttl:%03d proto:%-3d" % ("*" if ip.ttl == 2 else " ", ip.saddr, ip.daddr, ip.ttl, ip.protocol))
  
      try:
        p = len(eth)
        # ICMP TIME EXCEED sends back ipheader plus first 64-bits of datagram
        send_ttl_expire(s, eth, ip, data[p:p+20+ipoptslen+8])
      except ValueError:
        """ValueError raised if TTL is too high. Let's actually reply to pings."""
        p = len(eth) + len(ip) + ipoptslen
        if ip.protocol == 1 and data[p] == 0x08 and data[p+1] == 0x00:
          send_echo_reply(s, eth, ip, data[p:])

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print("Ok bye")
