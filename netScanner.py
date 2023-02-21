import scapy.all as scapy
import argparse
import ipaddress

import socket
import time
import threading

from queue import Queue
socket.setdefaulttimeout(0.25)

print_lock = threading.Lock()
parser = argparse.ArgumentParser()

def get_args():

    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Adresses')
    parser.add_argument('-p', '--port', dest='port', help='Target Port/Ports')
    options = parser.parse_args()
    #Check for errors i.e if the user does not specify the target IP Address
    if options.target:
        check_ip(options.target.split("/")[0])
        #Check for errors i.e if the user does not specify the target port
        if options.port:
            check_port(options.port)

    else:
        #Code to handle if interface is not specified
        #Scan inputs
        print("Especify Ip address or Ip Network to be scanned: ")

        try:
            #Assign target
            options.target = input()
        except Exception as e:
            print( "<p>Error: %s</p>" % str(e) )

        check_ip(options.target.split("/")[0])

    return options
  
def ipscan(ip):
    print("Starting ARP Discovery over %s" % str(ip))
    arp_req_frame = scapy.ARP(pdst = ip)

    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
    result = []
    for i in range(0,len(answered_list)):
        client_dict = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}
        result.append(client_dict)

    return result

def portscan(ip_scanner_output):
    print("Do you want to perform a port scan?: (y/n)")
    port_scan_response = input()
    result = []

    if port_scan_response == "y":

        target = input('Enter the host to be scanned: (all/host range (ej: 192.168.1.2-192.168.1.4)/host ip (ej: 192.168.1.2)): ')

        #Full Ip Scan
        if check_target(target) == "all":

            port_target = input('Enter the port to be scanned: (all/wellknown/port range (ej: 20-23)/port number (ej: 22)): ')

            #Perform port scan over all hosts
            for ip_target in ip_scanner_output:
                print(ip_target["ip"])
                t_IP = socket.gethostbyname(ip_target["ip"])

                #Full Port scan
                if check_port(port_target) == "all":

                    print('Starting full scan on host: ', t_IP)

                    open_ports = []
                    for port in range(1, 65536):
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        print("Scanning port " + str(port) + " of the host " + t_IP)
                        try:
                            con = s.connect((t_IP, port))
                            with print_lock:
                                print(port, 'is open')
                                open_ports.append(port)
                            con.close()
                        except Exception as e:
                            print( "<p>Error: %s</p>" % str(e) )
                            pass
                    port_dict = {"ip" : t_IP, "ports" : open_ports}
                    result.append(port_dict)

                #Well Known Port scan
                elif check_port(port_target) == "wellknown":

                    print('Starting full scan on host: ', t_IP)

                    open_ports = []
                    for port in range(1, 1024):
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        print("Scanning port " + str(port) + " of the host " + t_IP)
                        try:
                            con = s.connect((t_IP, port))
                            with print_lock:
                                print(port, 'is open')
                                open_ports.append(port)
                            con.close()
                        except Exception as e:
                            print( "<p>Error: %s</p>" % str(e) )
                            pass
                    port_dict = {"ip" : t_IP, "ports" : open_ports}
                    result.append(port_dict)

                #Single port scan
                elif check_port(port_target).isnumeric():

                    print('Starting scan of port ' + port_target + ' on host: ', t_IP)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    open_ports = []
                    try:
                        con = s.connect((t_IP, port_target))
                        with print_lock:
                            print(port_target, 'is open')
                            open_ports.append(port)
                        con.close()
                    except Exception as e:
                        print( "<p>Error: %s</p>" % str(e) )
                        pass

                    port_dict = {"ip" : t_IP, "ports" : open_ports}
                    result.append(port_dict)

                #Range port scan
                else:

                    print('Starting scan of port ' + port_target + ' on host: ', t_IP)
                    start_port = str(port_target).split("-")[0].replace("(", "")
                    end_port = str(port_target).split("-")[1].replace(")", "")

                    open_ports = []
                    for port in range(start_port, end_port):
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        print("Scanning port " + str(port) + " of the host " + t_IP)
                        try:
                            con = s.connect((t_IP, port))
                            with print_lock:
                                print(port, 'is open')
                                open_ports.append(port)
                            con.close()
                        except Exception as e:
                            print( "<p>Error: %s</p>" % str(e) )
                            pass

                        port_dict = {"ip" : t_IP, "ports" : open_ports}
                        result.append(port_dict)

            return result

        #Range Ip Port Scanner
        elif "-" in target:

            port_target = input('Enter the port to be scanned: (all/port range (ej: 20-23)/port number (ej: 22)): ')


            first_ip = target.split("-")[0]
            last_ip = target.split("-")[1]

            #Check the range
            if first_ip.split(".")[0] == last_ip.split(".")[0]:

                if first_ip.split(".")[1] == last_ip.split(".")[1]:

                    if first_ip.split(".")[2] == last_ip.split(".")[2]:
                        #Third set matches

                        ip_prefix = first_ip[:-(len(first_ip.split(".")[-1])+1)]

                        start_ip = first_ip.split(".")[-1]
                        end_ip = last_ip.split(".")[-1]

                    else:
                        #Second set matches
                        ip_prefix = first_ip[:-(len(first_ip.split(".")[-1])+ len(first_ip.split(".")[-2])+ 2)]

                        start_ip_ = first_ip.split(".")[-2]
                        end_ip_ = last_ip.split(".")[-2]

                else:
                    #First set matches
                    ip_prefix = first_ip[:-(len(first_ip.split(".")[-1])+ len(first_ip.split(".")[-2]) + len(first_ip.split(".")[-3]) + 3)]

                    start_ip_ = first_ip.split(".")[-3]
                    end_ip_ = last_ip.split(".")[-3]

            else:
                ip_prefix = ""

                start_ip_ = first_ip.split(".")[0]
                end_ip_ = last_ip.split(".")[0]


            #Need to be finished
            """

            #Perform port scan over host in
            for ip_target in range(first_ip_device, last_ip_device + 1):
                print(ip_target["ip"])
                t_IP = socket.gethostbyname(ip_target["ip"])

                #full scan
                if check_port(port_target) == "all":

                    print('Starting full scan on host: ', t_IP)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    for port in range(0, 65536):
                        try:
                            con = s.connect((t_IP, port))
                            with print_lock:
                                print(port, 'is open')
                                ip_scanner_output["port"].append(port)
                            con.close()
                        except Exception as e:
                            print( "<p>Error: %s</p>" % str(e) )
                            pass

                    return ip_scanner_output

                #Single port scan
                elif check_port(port_target).isnumeric():

                    print('Starting scan of port' + port_target + ' on host: ', t_IP)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        con = s.connect((t_IP, port_target))
                        with print_lock:
                            print(port_target, 'is open')
                            ip_scanner_output["port"].append(port_target)
                        con.close()
                    except Exception as e:
                        print( "<p>Error: %s</p>" % str(e) )
                        pass

                    return ip_scanner_output

                #Range port scan
                else:

                    print('Starting scan of port' + port_target + ' on host: ', t_IP)
                    start_port = str(port_target).split("-")[0].replace("(", "")
                    end_port = str(port_target).split("-")[1].replace(")", "")

                    for port in range(start_port, end_port):
                        try:
                            con = s.connect((t_IP, port))
                            with print_lock:
                                print(port, 'is open')
                                ip_scanner_output["port"].append(port)
                            con.close()
                        except Exception as e:
                            print( "<p>Error: %s</p>" % str(e) )
                            pass

                        return ip_scanner_output
                        
                """

            return result


        #Single Ip Scan
        else:
            t_IP = socket.gethostbyname(target)

            port_target = input('Enter the port to be scanned: (all/port range (ej: 20-23)/port number (ej: 22)): ')

            #Full Port scan
            if check_port(port_target) == "all":

                print('Starting full scan on host: ', t_IP)

                open_ports = []
                for port in range(1, 65536):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    print("Scanning port " + str(port) + " of the host " + t_IP)
                    try:
                        con = s.connect((t_IP, port))
                        with print_lock:
                            print(port, 'is open')
                            open_ports.append(port)
                        con.close()
                    except Exception as e:
                        print( "<p>Error: %s</p>" % str(e) )
                        pass
                port_dict = {"ip" : t_IP, "ports" : open_ports}
                result.append(port_dict)

            #Well Known Port scan
            if check_port(port_target) == "wellknown":

                print('Starting full scan on host: ', t_IP)

                open_ports = []
                for port in range(1, 1024):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    print("Scanning port " + str(port) + " of the host " + t_IP)
                    try:
                        con = s.connect((t_IP, port))
                        with print_lock:
                            print(port, 'is open')
                            open_ports.append(port)
                        con.close()
                    except Exception as e:
                        print( "<p>Error: %s</p>" % str(e) )
                        pass
                port_dict = {"ip" : t_IP, "ports" : open_ports}
                result.append(port_dict)

            #Single port scan
            elif check_port(port_target).isnumeric():

                print('Starting scan of port ' + port_target + ' on host: ', t_IP)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                open_ports = []
                try:
                    con = s.connect((t_IP, port_target))
                    with print_lock:
                        print(port_target, 'is open')
                        open_ports.append(port)
                    con.close()
                except Exception as e:
                    print( "<p>Error: %s</p>" % str(e) )
                    pass

                port_dict = {"ip" : t_IP, "ports" : open_ports}
                result.append(port_dict)

            #Range port scan
            else:

                print('Starting scan of port ' + port_target + ' on host: ', t_IP)
                start_port = str(port_target).split("-")[0].replace("(", "")
                end_port = str(port_target).split("-")[1].replace(")", "")

                open_ports = []
                for port in range(start_port, end_port):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    print("Scanning port " + str(port) + " of the host " + t_IP)
                    try:
                        con = s.connect((t_IP, port))
                        with print_lock:
                            print(port, 'is open')
                            open_ports.append(port)
                        con.close()
                    except Exception as e:
                        print( "<p>Error: %s</p>" % str(e) )
                        pass

                    port_dict = {"ip" : t_IP, "ports" : open_ports}
                    result.append(port_dict)


            return result

    else:
        print("Wrong argument")



def check_target(target):
    try:
        if target == "all":
            return target
        elif "-" in target:
            check_ip(target.split("-")[0])
            check_ip(target.split("-")[1])
            return target
        else:
            check_ip(target)
            return target
    except ValueError:
        print(target + " is not a valid target")
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")


def check_ip(ip_addr):
    try:
        ip_validation = ipaddress.ip_address(ip_addr)
        return ip_validation
    except ValueError:
        print(ip_addr + " is not a valid target")
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")

def check_port(port):
    try:
        if str(port) == "all":
            return port
        elif str(port) == "wellknown":
            return port
        elif str(port).isnumeric():
            return port
        elif str(port).split("-")[0].replace("(", "").isnumeric() and str(port).split("-")[1].replace(")", "").isnumeric():
            return port
        else:
            raise ValueError("[-] Please specify a valid port, use --help for more info.")

    except ValueError as error:
        print(error)

  
def display_ip_scanner(result):
    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))

    print("------------------------------------------------------------------------------------------------")

def display_ip_port_scanner(result):
    print("-----------------------------------\nIP Address\tOpen Ports\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["ports"]))

    print("------------------------------------------------------------------------------------------------")


def save_ip_scanner(result):
    with open('ip_scan.txt', 'w') as f:
        f.write("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------\n")
        for i in result:
            f.write("{}\t{}".format(i["ip"], i["mac"]))
            f.write("\n")

        f.write("------------------------------------------------------------------------------------------------")


def save_ip_port_scanner(result):
    with open('port_scan.txt', 'w') as f:
        f.write("-----------------------------------\nIP Address\tOpen Ports\n-----------------------------------\n")
        for i in result:
            f.write("{}\t{}".format(i["ip"], i["ports"]))
            f.write("\n")

        f.write("------------------------------------------------------------------------------------------------")




if __name__ == "__main__":
    print(f"""
    
    █▀▀▄ █▀▀ ▀▀█▀▀ █▀▀ █▀▀ █▀▀█ █▀▀▄ █▀▀▄ █▀▀ █▀▀█
    █  █ █▀▀   █   ▀▀█ █   █▄▄█ █  █ █  █ █▀▀ █▄▄▀
    ▀  ▀ ▀▀▀   ▀   ▀▀▀ ▀▀▀ ▀  ▀ ▀  ▀ ▀  ▀ ▀▀▀ ▀ ▀▀
    ----------------------------------------------
    """)
    options = get_args()

    #IP Scanner
    ip_scanner_output = ipscan(options.target)
    display_ip_scanner(ip_scanner_output)
    save_ip_scanner(ip_scanner_output)

    #Port Scanner
    port_scammer_output = portscan(ip_scanner_output)
    display_ip_port_scanner(port_scammer_output)
    save_ip_port_scanner(port_scammer_output)

