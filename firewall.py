import configparser
#assuming that there are only two networks 10.10.10.0 and 10.10.11.0 which communicate with eachother 

def read_datagram(ip_datagram):
    ip_datagram_vals={}
    s_addr_bin=ip_datagram[96:128]
    d_addr_bin=ip_datagram[128:160]
    #header length and data part(TCP/UDP segment) extracted
    header_len=int(ip_datagram[4:8],2)*4*8
    tcp_udp_segment=ip_datagram[header_len:]
    s_addr_parts=[s_addr_bin[0:8],s_addr_bin[8:16],s_addr_bin[16:24],s_addr_bin[24:32]]
    d_addr_parts=[d_addr_bin[0:8],d_addr_bin[8:16],d_addr_bin[16:24],d_addr_bin[24:32]]
    #source address in dotted decimal format
    src_addr=""
    for part in s_addr_parts:
        src_addr=src_addr+str(int(part,2))+"."
    src_addr=src_addr[:-1]
    #destination address in dotted decimal format
    dest_addr=""
    for part in d_addr_parts:
        dest_addr=dest_addr+str(int(part,2))+"."
    dest_addr=dest_addr[:-1]
    #source & destination ports formatted 
    s_port_bin=tcp_udp_segment[:16]
    d_port_bin=tcp_udp_segment[16:32]
    src_port=str(int(s_port_bin,2))
    dest_port=str(int(d_port_bin,2))
    #adding extracted values to a dictionary
    ip_datagram_vals["source_address"]=src_addr
    ip_datagram_vals["destination_address"]=dest_addr
    ip_datagram_vals["source_port"]=src_port
    ip_datagram_vals["destination_port"]=dest_port

    return ip_datagram_vals


def handle_datagram(datagram_vals,interface):
    data_src=datagram_vals.get("source_address").split(".")
    data_dest=datagram_vals.get("destination_address").split(".")
    data_d_port=int(datagram_vals.get("destination_port"))
    
    config_parser = configparser.ConfigParser()
    config_parser.read('config.ini')
    sections = config_parser.sections()
    #going through rules in the config file matching conditions
    for section in sections:
        if(config_parser.get(section, 'interface')==interface):
            if(config_parser.get(section, 'src_addr')!='any'):
                conf_src=config_parser.get(section, 'src_addr').split(".")
                if(conf_src[0]==data_src[0] and conf_src[1]==data_src[1] and conf_src[2]==data_src[2]):
                    if(config_parser.get(section, 'dest_addr')!='any'):
                        conf_dest=config_parser.get(section, 'dest_addr').split(".")
                        if(conf_dest[0]==data_dest[0] and conf_dest[1]==data_dest[1] and conf_dest[2]==data_dest[2]):
                            if(config_parser.get(section, 'dest_port')!='any'):
                                conf_d_port=int(config_parser.get(section, 'dest_port')[1:])
                                if (data_d_port > conf_d_port):
                                    print ("Interface = "+interface)
                                    print (config_parser.get(section, 'action'))
                                    break
                                else:
                                    continue
                            else:
                                print ("Interface = "+interface)
                                print (config_parser.get(section, 'action'))
                                break
                        else:
                            continue
                    else:
                        print ("Interface = "+interface)
                        print (config_parser.get(section, 'action'))
                        break
                else:
                    continue
            else:
                print ("Interface = "+interface)
                print (config_parser.get(section, 'action'))
                break
        else:
            continue

#testing ip datagrams which comes to interface_1
config_parser = configparser.ConfigParser()
config_parser.read('interface_1.ini')
datagrams = config_parser.sections()
for datagram in datagrams:
    datagram = config_parser.get(datagram, 'datagram')
    datagram_vals=read_datagram(datagram)
    print(datagram_vals)
    handle_datagram(datagram_vals,'interface_1')
    print("\n")
#testing ip datagrams which comes to interface_2
config_parser = configparser.ConfigParser()
config_parser.read('interface_2.ini')
datagrams = config_parser.sections()
for datagram in datagrams:
    datagram = config_parser.get(datagram, 'datagram')
    datagram_vals=read_datagram(datagram)
    print(datagram_vals)
    handle_datagram(datagram_vals,'interface_2')
    print("\n")

