import scapy.all as scapy
import subprocess,sqlite3
import tkinter as tk
from datetime import datetime
import optparse



def optinal_argumenbts():
    parser = optparse.OptionParser()
    parser.add_option("-d","--delete",dest="delete",help="delete-Exsist mac to choose table use -b for blocked , -t for trusted routers")
    parser.add_option("-a","--add",dest="add",help="add-mac to choose table use -b for blocked , -t for trusted routers")
    parser.add_option("-b","--blocked",action="store_true",dest="blocked",help="Choose table blocked")#
    parser.add_option("-t","--trusted",dest="trusted",action="store_true",help="Choose Table Trusted")#
    options,arguments = parser.parse_args()
    return options


#vars
scanned_mac = "0"



###sqlite3
connection = sqlite3.connect('spoof_macs.db')
cursor = connection.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS spoofed_macs (mac_address TEXT,detection_time TEXT);')
cursor.execute('CREATE TABLE IF NOT EXISTS router_macs (mac_address TEXT,detection_time TEXT);')


def recover_iptables(mac_address):
    try:
        subprocess.run(f'iptables -D INPUT -m mac --mac-source {mac_address} -j DROP', shell=True)
        subprocess.run(f'arptables -D INPUT --source-mac {mac_address} -j DROP', shell=True)
    except:
        pass



def block_iptables(mac_address):
    subprocess.run(f'iptables -A INPUT -m mac --mac-source {mac_address} -j DROP', shell=True)
    subprocess.run(f'arptables -A INPUT --source-mac {mac_address} -j DROP', shell=True)

def block_mac(mac_address):
    block_iptables(mac_address)
    print("[+] mac blocked")
    cursor.execute('INSERT INTO spoofed_macs (mac_address,detection_time) VALUES (?,?);', (mac_address,str(datetime.now()),))
    print("[+] saved in database")
    connection.commit()


def send_notification(title, message,mac):
    root = tk.Tk()
    root.title(title)
    root.geometry("300x200")

    def no_action():
        print(f"[+] Mac : [{mac}] added to Routers macs")
        recover_iptables(mac)
        cursor.execute('INSERT INTO router_macs (mac_address,detection_time) VALUES (?,?);', (mac,str(datetime.now()),))
        connection.commit()
        root.destroy()


    def yes_action():
        print(f"[+] Start blocking mac [ {mac} ]")
        block_mac(mac)
        root.destroy()


    label = tk.Label(root, text=message)
    label.pack()


    yes_button = tk.Button(root, text="Yes",bg="green", command=yes_action,width=5,font=("",20))
    yes_button.pack(side=tk.LEFT, padx=10)

    no_button = tk.Button(root, text="NO",bg="red",cursor="arrow", command=no_action,width=5,font=("",20))
    no_button.pack(side=tk.RIGHT, padx=10)

    root.mainloop()



def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_packet)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast / arp_request
    answered =scapy.srp(arp_request_broadcast, timeout=2,verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc
    else:
        raise ValueError(f"No ARP response received for IP: {ip}")

def process_packet(packet):
    global scanned_mac
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            try:
                cursor.execute("SELECT mac_address FROM router_macs")
                rows = cursor.fetchall()
            except:pass
            for row in rows:
                if response_mac in row:
                    return
            if response_mac == scanned_mac:
                    return
            if response_mac != real_mac:
                block_iptables(response_mac)
                print(f"[+] Arp Attack Detected From Mac :{response_mac}")
                send_notification("Router Mac Changed","Do you want to block this Mac Adress ? ",response_mac)
                scanned_mac = response_mac
    except:
        pass

#options section
options = optinal_argumenbts()
if options.delete:
    if not options.blocked and not options.trusted:
        print("[+] use -t for trusted or -b for blocked u need to choose table ")
    else:
        if options.blocked:
            table = 'spoofed_macs'
        elif options.trusted:
            table = 'router_macs'
        exsit = cursor.execute(f"SELECT * FROM {table} WHERE mac_address = ?", (options.delete,))
        rows = exsit.fetchall()
        if not rows:
            print("[+] This mac adderss is invaild")
            quit()
        cursor.execute(f"DELETE FROM {table} WHERE mac_address = ?", (options.delete,))
        connection.commit()
        if table == "spoofed_macs":
            recover_iptables(options.delete)
        print(f"[+] mac {options.delete} from {table} has deleted.")
        quit()
elif options.add:
    if not options.blocked and not options.trusted:
        print("[+] use -t for trusted or -b for blocked u need to choose table ")
    else:
        if options.blocked:
            table = 'spoofed_macs'
        elif options.trusted:
            table = 'router_macs'
        exsit = cursor.execute(f"SELECT * FROM {table} WHERE mac_address = ?", (options.add,))
        rows = exsit.fetchall()
        if rows:
            print("[+] This mac address alredy here")
            quit()
        cursor.execute(f"INSERT INTO {table} (mac_address, detection_time) VALUES (?, ?)", (options.add, str(datetime.now())))
        connection.commit()
        if table == "spoofed_macs":
            block_iptables(options.add)
        print(f"[+] mac {options.add} from {table} has Added.")
        quit()

if not options.add or not options.delete:
    print("[+] Start Arp Detector...")
    sniff("usb0")