# Basic Network Sniffer

A Python-based network sniffer developed to capture and analyze live network traffic using Scapy.

## 📌 Project Overview

This project captures live network packets from a network interface and displays important information about the traffic.

The sniffer demonstrates how data flows through a network and provides practical experience with common network protocols.

## 🚀 Features

- Capture live network packets
- Display source IP address
- Display destination IP address
- Identify network protocols
- Display source and destination ports
- Detect ICMP traffic
- Analyze DNS traffic
- Identify HTTPS/TLS traffic on TCP port 443
- Identify QUIC/HTTP3 traffic on UDP port 443
- Display readable payload information when available
- Handle encrypted and binary traffic without displaying unreadable data

## 🛠️ Technologies Used

- Python
- Scapy
- Npcap
- TCP/IP Networking

## ⚙️ How It Works

The program uses Scapy to capture packets from the wireless network interface.

For each IPv4 packet, the program extracts:

1. Source IP address
2. Destination IP address
3. Protocol
4. Source port
5. Destination port
6. Payload information

Common traffic such as DNS, ICMP, HTTPS/TLS, and QUIC/HTTP3 can be identified from the captured packets.

## 📋 Requirements

- Windows
- Python 3.x
- Scapy
- Npcap

## 🔧 Installation

Install Scapy using:

```bash
pip install scapy

## 🖼️ Demo Screenshot

![Network Sniffer Demo](network-sniffer-demo.png)
