#!/usr/bin/env python3
"""Starwars traceroute using raw ethernet socket in Python3.

This is my first dive into Python and learning the Pythonic ways.
The fib and filter globals need modified for your environment.

created: 2020-02-01
author:  Scott Nicholas <scott@nicholas.one>
"""

import ctypes
import struct
from binascii import hexlify
from ctypes import create_string_buffer, addressof
from struct import pack, unpack
import copy
import socket
import array

fib = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 0, 0, 0, 0]

#/include/uapi/linux/if_ether.h
class PHdr(ctypes.BigEndianStructure):
  def hex(self):
    return hexlify(bytearray(self))

class ethhdr(PHdr):
  ETH_ALEN = 6

  _fields_ = [
    ("h_dest", ctypes.c_ubyte * ETH_ALEN),
    ("h_source", ctypes.c_ubyte * ETH_ALEN),
    ("h_proto", ctypes.c_uint16)
  ]

class iphdr(PHdr):
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
      raise TypeException

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
  icmp = icmphdr(11, 0, 0, 0, 0)

  ip = copy.copy(in_ip)
  ip.check = 0
  ip.tot_len = ctypes.sizeof(ip) + ctypes.sizeof(icmp) + len(payload)
  ip.ttl = 63
  ip.saddr = [44, 38, 10, fib[in_ip.ttl - 2]]
  ip._daddr = in_ip._saddr
  ip.check = checksum(bytearray(ip))

  eth = ethhdr(in_eth.h_source, in_eth.h_dest, in_eth.h_proto)

  icmp.checksum = checksum(bytearray(icmp) + payload)

  msg = create_string_buffer(ctypes.sizeof(eth) + ctypes.sizeof(ip) + ctypes.sizeof(icmp) + len(payload))
  msg = bytearray(eth) + bytearray(ip) + bytearray(icmp) + payload

  print("  %16s <- %16s ttl:%03d proto:%-3d icmp type:%-3d code:%-3d" % (ip.daddr, ip.saddr, ip.ttl, ip.protocol, icmp.type, icmp.code))
#  print("send: ", hexlify(msg))
  ret = s.send(msg)

# get the C-struct from tcpdump using -dd
# make sure you reference correct interface
# paste -d"\n" \
#  <(tcpdump -d $expression | sed -e 's/^/# /') \
#  <(tcpdump -dd $expression | tr -s '{}' '()')

# ttl < 16 and > 1 and dst host 44.38.10.234
filter = [
  ( 0x28, 0, 0, 0x0000000c ),
  ( 0x15, 0, 6, 0x00000800 ),
  ( 0x30, 0, 0, 0x00000016 ),
  ( 0x35, 4, 0, 0x00000010 ),
  ( 0x25, 0, 3, 0x00000001 ),
  ( 0x20, 0, 0, 0x0000001e ),
  ( 0x15, 0, 1, 0x2c260aea ),
  ( 0x6, 0, 0, 0x00040000 ),
  ( 0x6, 0, 0, 0x00000000 ),
]

def main():
  blob = ctypes.create_string_buffer(b''.join(struct.pack("HBBI", *e) for e in filter))
  bpf = struct.pack('HL', len(filter), addressof(blob))
  
  # As defined in asm/socket.h
  SO_ATTACH_FILTER = 26
  
  # Create listening socket with filters
  s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
  s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bpf)
  s.bind(('ens3', 0x800))
  
  while True:
      data, addr = s.recvfrom(65565)
      eth = ethhdr.from_buffer_copy(data)
      ip = iphdr.from_buffer_copy(data[ctypes.sizeof(ethhdr):])
  
  #    print("pkttype = ", addr[2], " ip.saddr = ", socket.inet_ntoa(struct.pack("=I", ip.saddr)),
  #          "ip.daddr = ", socket.inet_ntoa(struct.pack("=I", ip.daddr)),
  #          "ip.ttl = ", ip.ttl, " ip.protocol = ", ip.protocol)
  
      # ICMP TIME EXCEED sends back 20 byte header plus first 64-bits of datagram
      print("%s %16s -> %16s ttl:%03d proto:%-3d" % ("*" if ip.ttl == 2 else " ", ip.saddr, ip.daddr, ip.ttl, ip.protocol))
  #    print("recv: ", hexlify(data))
  
      send_ttl_expire(s, eth, ip, data[14:14+28])

if __name__ == '__main__':
  main()