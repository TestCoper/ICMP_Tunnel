<h1 align="center">ICMP Tunnel</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-v3.9-blue">
  <img src="https://img.shields.io/badge/scapy-v2.5.0-blue">
</p>
This repository contains code for a client-server application that uses ICMP and UDP protocols for communication. The client sends data or requests to the server using ICMP or UDP packets, and the server responds accordingly.

## Setup and Configuration Client

1. Install the required dependencies:
    - Python 3.x
    - scapy

2. Clone the repository:
    ```
    git clone https://github.com/TestCoper/ICMP_Tunnel
    cd ICMP_Tunnel
    ```
3. Configure the application by editing the `config.ini` file. Make sure to set the appropriate values for the configuration options.

4. Run the application:
    ```
    python main.py
    ```

## Setup and Configuration Server

1. Install the required dependencies:
    - Python 3.x
    - scapy

2. Clone the repository:
    ```
    git clone https://github.com/TestCoper/ICMP_Tunnel
    cd ICMP_Tunnel
    ```

3. Configure the application by editing the `config.ini` file. Make sure to set the appropriate values for the configuration options.

4. Run the application:
    ```
    python server.py
    ```
5. Make sure Data folder is in write mode or Run this code with ```sudo```
## Usage

The application provides a menu-based command line interface with the following options:

1. Check Alive Servers: Sends an ICMP packet to check the availability of servers.

2. Check TLS: Checks the TLS revision number from the servers.

3. Send File: Sends a file to the server using either UDP or ICMP.

Choose the desired option by entering the corresponding number and follow the prompts.

## Extra Discripttion

<ol>
  <li>Import the required libraries: <code>import os</code>, <code>import sys</code>, <code>import math</code>, <code>import codecs</code>, <code>import ntpath</code>, <code>import random</code>, <code>import logging</code>, <code>import colorlog</code>, <code>import binascii</code>, <code>import configparser</code>, <code>from scapy.all import IP, ICMP, Raw, send, get_if_addr, sniff, conf</code>.</li>
  <li>Set up the necessary configuration and logging.</li>
  <li>Use the provided functions to perform various operations:
    <ul>
      <li><code>send_icmp(dst, payText, ImId=None, ImSq=None)</code>: Send ICMP packets with a payload to the specified destination.</li>
      <li><code>send_UDP(FilePath)</code>: Send data using the UDP protocol.</li>
      <li><code>server_online()</code>: Check online servers for sending data or receiving the public key.</li>
      <li><code>check_status()</code>: Check the last revision number of TLS from the server.</li>
      <li><code>split_to_1024byte(FilePath, SendStat)</code>: Split a file into 1024-byte chunks and send them using UDP or ICMP. If the file size is larger than 5,000,000 bytes, it will be sent using UDP.</li>
      <li><code>send_data(FilePath)</code>: Send a file using UDP or ICMP, based on its size.</li>
    </ul>
  </li>
  <li>Implement the necessary server-side functionality:
    <ul>
      <li><code>client_icmp(packet_rec)</code>: Handle received ICMP packets on the server side.</li>
    </ul>
  </li>
</ol>

## ICMP Communication

The client communicates with the server using ICMP packets. It supports the following ICMP message types:

- **Alive Packet**: Sent by the client to check the availability of servers.

- **Check-Status Packet**: Sent by the client to request the TLS revision number from the servers.

- **Send-Data Packet**: Sent by the client to send a file to the server.

## UDP Communication

The application also supports file transfer using UDP. However, the UDP functionality is not implemented in the current version of the code.

## Configuration

The application uses a configuration file `config.ini` to specify various settings. Ensure that the configuration file is present and correctly formatted.

## Logging

The application logs events and messages using the Python `logging` module. The log level is set to `DEBUG` by default. You can modify the log level in the code if needed.

## Contact

For any questions or issues, please contact [<a href='mailto:lap.mmd@outlook.com'> lap.mmd@outlook.com</a>].
