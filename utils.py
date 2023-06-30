import os
import sys
import math
import codecs
import ntpath
import random
import socket
import logging
import colorlog
import binascii
import configparser
from scapy.all import IP, ICMP, Raw, send, get_if_addr, sniff,conf


# create a ConfigParser object
config = configparser.ConfigParser()
try:
    # read the configuration file
    config.read('config.ini')
except configparser.Error as e:
    # handle the exception if there is an error reading the file
    print(f"Error reading configuration file: {e}")
    sys.exit(1)

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

################# [ VAR SECTION ] #################
RECIVE_UNKNOWN_SERVER = config['DEFAULT']['RECIVE_UNKNOWN_SERVER']
WtListIp = ['192.168.132.135',]
AllListIp = ['192.168.132.135',]
DevIp = get_if_addr(conf.iface)
TlsRevisionNumber = {
    'Defult' : 0x0001,
}
TrustList = lambda : AllListIp if RECIVE_UNKNOWN_SERVER else WtListIp

# Set up colored output
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s%(levelname)s:%(message)s',
    log_colors={
        'DEBUG': 'green',
        'INFO': 'blue',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    }))
logger.addHandler(handler)
DoAc = lambda x: server_online() if x == 1 else(check_status() if x == 2 else(send_data_func() if x == 3 else print('BadConfig')))
menu_text = \
"""
1) check Alive Servers
2) check TLS
3)Send File
"""

################# [ CLIENT SECTION ] #################
def send_icmp(dst, payText, ImId=None, ImSq=None):
    #Encode the payload to hex format
    if type(payText) != bytes:
        EncodedBytes = payText.encode()
    else:
        EncodedBytes = payText
    HexString = binascii.hexlify(EncodedBytes).decode()
    EscapedString = ''.join(['\\x'+HexString[i:i+2] for i in range(0, len(HexString), 2)])
    # Create a new ICMP Packet with a payload
    PacketResp = IP(dst=dst)/ICMP(length=1054)/b'hello'
    # Modify the payload of the Packet
    PacketResp[Raw].load = bytes(EscapedString.encode('utf-8'))
    if (ImId is None or ImSq is None):
        Response = send(PacketResp, verbose=0)
        logging.info(f"[{dst}] Alive Server Packet sent...")
    else:
        # Replace id and seq for transfer data(we use id for put data and seq for know the number of Packets)
        PacketResp[ICMP].id = ImId
        PacketResp[ICMP].seq = ImSq
        # Send the modified Packet
        send(PacketResp, verbose=0)


def send_UDP(FilePath):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Send the chunk of data
    sock.sendto(data, (host, port))

    # Close the socket
    sock.close()

#Check online servers for sending Data or Receive Publickey
def server_online():
    for ip in WtListIp:
        send_icmp(ip, 'check-online')

#Check the last RevisionNumber of tls from server
def check_status():
    server_online()
    if not WtListIp and RECIVE_UNKNOWN_SERVER:
            logger.warning('[ info ] Reciving PublicKey....')
            send_icmp(random.choice(WtListIp), 'check-status', TlsRevisionNumber['Defult'], 0x1)
    else:
        send_icmp(random.choice(WtListIp), 'check-status', TlsRevisionNumber['Defult'], 0x1)

#----------DATA SECTION------------#
#Sending File with UDP OR ICMP
def split_to_368byte(FilePath, SendStat):
    fileR = open(FilePath, "rb")
    chunk = 0
    byte_ss = fileR.read(338)
    FileName = ntpath.basename(FilePath)
    AmountChunk = math.ceil(os.path.getsize(FilePath) / 338)
    UploadServer = random.choice(WtListIp)
    if SendStat == 'icmp':
        #Send Data Start Segment
        send_icmp(UploadServer, f'sendData-{FileName}', 0xffff, AmountChunk)
        while byte_ss:
                #Start Sending main Data
                RawData_s2 = f'sendData-{FileName}<tagMmd>'.encode()+byte_ss
                send_icmp(UploadServer, RawData_s2, chunk, 0xaaaa)

                # Read next 338 bytes
                byte_ss = fileR.read(338)
                chunk += 1
                print(str((chunk *100) / AmountChunk)+'%')
        send_icmp(UploadServer, f'sendData-{FileName}', 0xeeee, 0xeeee)
        print('finish')
    elif SendStat == 'udp':
        pass
    else:
        logger.error('[Error input]: PLZ just send (udp, icmp)')


def send_data(FilePath):
    SizeOf = os.path.getsize(FilePath)
    if SizeOf > 5000000:
        split_to_368byte(FilePath, 'udp')
    else:
        split_to_368byte(FilePath, 'icmp')


def send_data_func():
    while True:
        PathToFile = input("Send your file Path: ")
        if os.path.isfile(PathToFile):
            send_data(PathToFile)
            break
        else:
            continue




################# [ SERVER SECTION ] #################
data_to_write = {

}

def client_icmp(packet_rec):
    if packet_rec[IP].src in TrustList():
        escaped_string = packet_rec[Raw].load
        plain_bytes = codecs.escape_decode(escaped_string)[0]
        if plain_bytes == b'tls_Pub_ok':
            logger.info('[ info ] You are using the latest PublicKey....')
        elif plain_bytes == b'tls_Pub_exp':
            logger.critical('Your PublicKey is expierd')
            logger.warning('Reciving PublicKey....')
        elif plain_bytes == b'alive':
            logger.info(f'Recived alive Packet[{packet_rec[IP].src}]...')
            WtListIp.append(packet_rec[IP].src)
        elif plain_bytes == 'check-online':
            send_icmp(packet_rec[IP].src, 'alive')
        elif escaped_string.split(b'sendData-')[0] == b'':
            NameOfFile = escaped_string.split(b'sendData-')[1].decode()
            if packet_rec[ICMP].id == 0xfffffffff:
                data_to_write[NameOfFile] = {
                    'len': int(plain_bytes.decode()),
                    'data': {}
                }
            elif packet_rec[ICMP].id == 0xeeeeeeeee:
                if len(data_to_write[NameOfFile]['data']) == data_to_write[NameOfFile]['len']:
                    print('Data recv suc!!')
                else:
                    print('Data didint recv correct')
            else:
                chunk_id = packet_rec[ICMP].id
                data_to_write[NameOfFile]['data'][chunk_id] = plain_bytes