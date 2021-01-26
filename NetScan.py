import scapy.all as scapy 
from mac_vendor_lookup import MacLookup
from subprocess import call
import sys

save_file = False

# CHECK INPUT
def take():
    select = input('\n > ')
    if select.lower() == 'q':
        call('clear')
        sys.exit()
    else:
        return select  


def main_ui():
    global save_file
    call('clear')
    print('\t### NETSCAN ###')
    print('\n > PRESS [ENTER] TO BEGIN')
    take() 
    call('clear')
    print(' > ENTER IP RANGE TO SCAN: ')
    print(' - (EXAMPLE: 10.0.0.1/24)')  
    input_ip = take()
    call('clear')
    print(' > WOULD YOU LIKE TO SAVE CLIENT LIST?')
    save_select = take()
    if save_select.lower() == 'y':
        save_file = True
    call('clear')
    try:
        scan(input_ip) 
    except:
        print(' > AN ERROR OCCURED.')
        print(' > EXITING NETSCAN...')
        sys.exit()


def scan (ip):
    call('clear')
    if save_file == True:
        print(' > ENTER NAME FOR NEW FILE:')
        file_name = take()
        f = open('data/' + file_name, 'w')
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    # LIST OF ALL CLIENT DICTIONARIES
    all_hosts = []

    for element in answered_list:
        found_ip = element[1].psrc
        found_mac = element[1].hwsrc
        try:
            mac_vendor = MacLookup().lookup(found_mac)
        except KeyError:
            mac_vendor = 'NO RESULT'
        
        new_host = {"ip":found_ip,"mac":found_mac,"vendor":mac_vendor.upper()}
        all_hosts.append(new_host)
    
    print('#####################################################################\n')
    
    for clients in all_hosts:
        
        report = f''' 
    > CLIENT: {str(all_hosts.index(clients) + 1)}
    > VENDOR: {clients['vendor'].upper()}
    > IP:     {clients['ip']}
    > MAC:    {clients['mac']}
         
 ---------------------------------------------------------------------'''
        print(report)
        if save_file:
            f.write(report)
    
    if save_file:
        f.close()
    print('#####################################################################')


if __name__ == '__main__':
    main_ui()