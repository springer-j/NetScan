import scapy.all as scapy 
from mac_vendor_lookup import MacLookup
from subprocess import call
import sys
import platform
import json
from os import system


#########################################################
### JSON SETTINGS FUNCTIONS ###

json_ip_range = None
json_save_settings = None 
json_os_settings = None


def load_settings():
    global json_save_settings, json_ip_range, json_os_settings
    current_os = platform.system()
    with open("settings.json",'r') as f:
        data = json.load(f)
        f.close()
    for option in data["os_settings"]:
        if current_os in option["os"]:
            json_os_settings = option
    json_ip_range = data["ip_range"]
    json_save_settings = data["save_default"]


def alter_settings_ui():
    clear()
    load_settings()
    print('### SETTINGS ###')
    print(f'\n 1. IP RANGE   : {json_ip_range}')
    print(f' 2. AUTOSAVE   : {str(json_save_settings).upper()}')
    print('\n\n > ENTER [B] TO RETURN TO MENU')
    setting_choice = take()
    if setting_choice == '1':
        alter_settings('ip_range','ip scan range')
    elif setting_choice == '2':
        alter_settings('save_default','autosave')
    elif setting_choice.lower() == 'b':
        main_ui()
    else:
        alter_settings_ui()
    

def alter_settings(setting_key,setting_name):
    global json_save_settings, json_ip_range, json_os_settings  
    with open("settings.json","r") as f:
        data = json.load(f)
        f.close

    if setting_name.lower() == 'autosave':
        new_val = not data['save_default']

    else:
        clear()
        print(' [#] ENTER NEW VALUE FOR ' + setting_name.upper())
        new_val = take()

    clear()
    print(f' [#] CHANGE {setting_name.upper()} TO {str(new_val).upper()}?')
    print(' (Y/N)')
    change_confirm = take()
    if change_confirm.lower() == 'y':
        clear()
        print(' [+] SAVING...')
        data[setting_key] = new_val
        updated = open("settings.json",'w')
        json.dump(data, updated)
        updated.close()
        clear()
        print(' [+] FILE SAVED!\n [#] PRESS ENTER TO CONTINUE')
        take()
        alter_settings_ui()
    elif change_confirm.lower() == 'n':
        clear()
        print(' > RETURNING TO SETTINGS SCREEN...')
        alter_settings_ui()
    else:
        clear()
        print(' [!] ERROR!')
        print(' [!] PRESS ENTER TO RETURN TO MENU')
        take()
        alter_settings_ui()
    
#########################################################
### NETWORK FUNCTIONS ###

# PING SWEEP AND SAVE ALL TO LIST
def scan():
    arp_request = scapy.ARP(pdst=json_ip_range)
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
        new_host = {"ip":found_ip,"mac":found_mac,"vendor":mac_vendor}
        all_hosts.append(new_host)
    # ALL_HOSTS RETURNS A LIST OF CLIENT INFO DICTIONARIES
    return all_hosts


# FORMAT ALL CLIENTS INTO A READABLE STRING
def generate_report(client_list):
    report = '######################################'
    if client_list:
        for clients in client_list[0:]:
            format = f''' 
 [#] CLIENT: {str(client_list.index(clients) + 1)}
 [#] VENDOR: {clients['vendor']}
 [#] IP:     {clients['ip']}
 [#] MAC:    {clients['mac']}

-------------------------------------'''
            report += format
    else:
        print(' [!] NO CLIENTS FOUND')
        print(' [!] EXITING APPLICATION')
        sys.exit()
    # RETURNS A STRING OF ALL CLIENTS
    return report


# SAVE TO REPORT TO .TXT FILE
def save_file(client_list):
    clear()
    print(f' [+] FOUND {str(len(client_list))} CLIENTS')
    print(' [+] ENTER NAME FOR NEW FILE')
    new_file_name = take()
    clear()
    print(' [+] SAVING ...')
    # GET DATA FILE OS PATH STRUCTURE FROM JSON DATA
    data_file = json_os_settings["data_path"]
    # SAVE FILE
    report_file = data_file + new_file_name
    with open(report_file,'w') as file:
        file.write(generate_report(client_list))
    file.close()
    clear()
    print(f' [+] FILE SAVED')
    print(f' > {report_file}')
    print(' > PRESS ENTER TO RETURN TO MENU')
    take()
    main_ui()


#########################################################
### UI FUNCTIONS ###


def clear():
    os_clear_command = json_os_settings['clear_call']
    system(os_clear_command)
    print('\n' * 5)


# CHECK INPUT
def take():
    select = input('\n > ')
    if select.lower() == 'q':
        sys.exit()
    else:
        return select  


# MAIN UI AT START
def main_ui():
    clear()
    print('\t~~~ NETSCAN ~~~')
    print('\n [+] SYSTEM CONFIGURATION: ' + json_os_settings["os"][json_os_settings["os"].index(platform.system())].upper())
    print(' [+] IP RANGE: ' + json_ip_range )
    print(' [+] AUTOSAVE REPORT: ' + str(json_save_settings).upper())
    print('\n [#] ENTER [S] TO CHANGE SETTINGS')
    print('\n\n > PRESS ENTER TO START SCAN')
    start = take() 
    if start.lower() == 's':
        alter_settings_ui()
    client_list = scan()
    if json_save_settings:
        save_file(client_list)
    else: 
        clear()
        report = generate_report(client_list)
        print(report)
        print(' > TYPE [SAVE] TO SAVE FILE')
        print(' > PRESS [ENTER] TO RETURN TO HOME')
        cont = take()
        if cont.lower() == 'save':
            save_file(client_list)
        main_ui()
            
    

if __name__ == '__main__':
    load_settings()
    main_ui()
