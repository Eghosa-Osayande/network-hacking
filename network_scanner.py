import scapy.all as scapy
import argparse

def scan(ip):
   arp_request = scapy.ARP(pdst=ip)
   broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
   arp_request_broadcast= broadcast/arp_request
   answered_list, unanswered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)

   client_list=[]
   for element in answered_list:
      client_dict= {'ip': element[1].psrc, 'mac': element[1].hwsrc}
      client_list.append(client_dict)
   
   return client_list

def print_result(results_list):
   print(f'IP\t\t\tMAC ADDRESS\n{"-"*10}')
   for client in results_list:
      print(client["ip"] + '\t\t' + client["mac"])

def get_arguments():
   parser = argparse.ArgumentParser()
   parser.add_argument('-t','--target', dest ='target', help = 'Target IP/IP range')
   options=parser.parse_args()
   return options
   
options = get_arguments()
scan_result = scan(options.target)   
print_result(scan_result)
