import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
   parser = argparse.ArgumentParser()
   parser.add_argument('-i','--iface', dest ='interface', help = 'Name of interface to sniff on')
   options=parser.parse_args()
   return options.interface

def sniff(interface):
   scapy.sniff(iface= interface, store = False, prn = process_sniffed_packet, filter='arp')

def get_url(packet):
   return packet[http.HTTPRequest].Host + paket[http.HTTPRequest].Path

def get_info(packet):
   if packet.haslayer(scapy.Raw):
      load = packet[scapy.Raw].load
      # you can go on to analyse 
      #load further here before returning
      return load

def process_sniffed_packet(packet):
   print(packet.summary())
   if packet.haslayer(http.HTTPRequest):
      url = get_url(packet)
      print('[+] HTTP Request >> ' + url)
      info = get_info(packet)
      if info:
         print(f'Got info for {url}')

interface_to_sniff= get_arguments()
while True:
   sniff(interface_to_sniff)