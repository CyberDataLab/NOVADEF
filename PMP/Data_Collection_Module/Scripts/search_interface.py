import os

def get_active_interfaces():
    
    net_path = "/sys/class/net/"
    
    if not os.path.exists(net_path):
        return []

    return [iface for iface in os.listdir(net_path) if iface != "lo"]

def select_best_interface():

    interfaces = get_active_interfaces()

    wired_prefixes = ("eth", "en", "eno", "enp", "ens")
    wireless_prefixes = ("wlan", "wl")

    wired_interfaces = [iface for iface in interfaces if iface.startswith(wired_prefixes)]
    wireless_interfaces = [iface for iface in interfaces if iface.startswith(wireless_prefixes)]
    
    if wired_interfaces or wireless_interfaces:
        return wired_interfaces + wireless_interfaces
    else:
        return None

if __name__ == "__main__":
    interface = select_best_interface()
    print(interface) #print required to use the output in the entrypoint_tshark script