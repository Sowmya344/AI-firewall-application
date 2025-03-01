import subprocess
import socket
from scapy.all import sniff, IP, TCP
import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest
import numpy as np
from collections import defaultdict

# Session state for login persistence
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'password' not in st.session_state:
    st.session_state.password = ""

# Sidebar Login
st.sidebar.title("Firewall Login")
username = st.sidebar.text_input("Username", value=st.session_state.username)
password = st.sidebar.text_input("Password", type="password", value=st.session_state.password)

if st.sidebar.button("Login"):
    if username == "admin" and password == "admin":
        st.session_state.authenticated = True
        st.session_state.username = username
        st.session_state.password = password
        st.sidebar.success("Login successful!")
    else:
        st.sidebar.error("Invalid credentials")

if not st.session_state.authenticated:
    st.stop()

# Network interface and initial settings
interface = "Wi-Fi"
packet_count = 10
packet_records = []
blocked_ips = set()
blocked_ports = set()
allowed_ips = set()
allowed_ports = {80, 443, 22}  # Whitelist of commonly allowed ports (HTTP, HTTPS, SSH)

# AI Model for Anomaly Detection
model = IsolationForest(contamination=0.1, random_state=42)

# Generate more realistic training data
def generate_training_data():
    data = []
    for _ in range(1000):
        src_ip = f"192.168.1.{np.random.randint(1, 255)}"
        dst_ip = f"192.168.1.{np.random.randint(1, 255)}"
        src_port = np.random.randint(1024, 65535)
        dst_port = np.random.choice([80, 443, 22, 8080, 3389])  # Common ports
        packet_size = np.random.randint(64, 1500)
        protocol = np.random.choice([0, 1])  # 0 for TCP, 1 for UDP
        data.append([hash(src_ip) % 10000, hash(dst_ip) % 10000, src_port, dst_port, packet_size, protocol])
    return np.array(data)

train_data = generate_training_data()
model.fit(train_data)  # Train the model

# Functions to manage Windows Firewall rules
def block_ip_in_windows(ip):
    rule_name = f"Block_IP_{ip}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" protocol=ANY dir=in action=block remoteip={ip}'
    try:
        subprocess.run(command, shell=True, check=True)
        st.success(f"Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        st.sidebar.error(f"Failed to block IP: {e}")
        if st.sidebar.button("Retry with Password"):
            retry_password = st.sidebar.text_input("Enter Admin Password to Confirm", type="password")
            if retry_password == "admin":
                subprocess.run(command, shell=True, check=True)
                st.success(f"Blocked IP: {ip}")
            else:
                st.sidebar.error("Incorrect password. IP not blocked.")

def unblock_ip_in_windows(ip):
    rule_name = f"Block_IP_{ip}"
    command = f'netsh advfirewall firewall delete rule name="{rule_name}" protocol=ANY remoteip={ip}'
    try:
        subprocess.run(command, shell=True, check=True)
        st.success(f"Unblocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        st.sidebar.error(f"Failed to unblock IP: {e}")
        if st.sidebar.button("Retry with Password"):
            retry_password = st.sidebar.text_input("Enter Admin Password to Confirm", type="password")
            if retry_password == "admin":
                subprocess.run(command, shell=True, check=True)
                st.success(f"Unblocked IP: {ip}")
            else:
                st.sidebar.error("Incorrect password. IP not unblocked.")

def block_port_in_windows(port):
    rule_name = f"Block_Port_{port}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" protocol=TCP dir=in action=block localport={port}'
    try:
        subprocess.run(command, shell=True, check=True)
        st.success(f"Blocked Port: {port}")
    except subprocess.CalledProcessError as e:
        st.sidebar.error(f"Failed to block port: {e}")
        if st.sidebar.button("Retry with Password"):
            retry_password = st.sidebar.text_input("Enter Admin Password to Confirm", type="password")
            if retry_password == "admin":
                subprocess.run(command, shell=True, check=True)
                st.success(f"Blocked Port: {port}")
            else:
                st.sidebar.error("Incorrect password. Port not blocked.")

def unblock_port_in_windows(port):
    rule_name = f"Block_Port_{port}"
    command = f'netsh advfirewall firewall delete rule name="{rule_name}" protocol=TCP localport={port}'
    try:
        subprocess.run(command, shell=True, check=True)
        st.success(f"Unblocked Port: {port}")
    except subprocess.CalledProcessError as e:
        st.sidebar.error(f"Failed to unblock port: {e}")
        if st.sidebar.button("Retry with Password"):
            retry_password = st.sidebar.text_input("Enter Admin Password to Confirm", type="password")
            if retry_password == "admin":
                subprocess.run(command, shell=True, check=True)
                st.success(f"Unblocked Port: {port}")
            else:
                st.sidebar.error("Incorrect password. Port not unblocked.")

# Function to process packets
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if packet.haslayer(TCP) else None
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else None
        packet_size = len(packet)
        protocol = 0 if packet.haslayer(TCP) else 1  # 0 for TCP, 1 for UDP
        
        # Features for AI model
        features = np.array([[hash(src_ip) % 10000, hash(dst_ip) % 10000, src_port if src_port else 0, dst_port if dst_port else 0, packet_size, protocol]])
        
        # Predict anomaly
        prediction = model.predict(features)
        status = "Blocked" if prediction[0] == -1 else "Allowed"
        
        # Allow whitelisted ports regardless of AI prediction
        if dst_port in allowed_ports:
            status = "Allowed"
        
        if status == "Blocked":
            blocked_ips.add(src_ip)
            if dst_port:
                blocked_ports.add(dst_port)
        else:
            allowed_ips.add(src_ip)
            if dst_port:
                allowed_ports.add(dst_port)
        
        packet_records.append({
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Packet Size": packet_size,
            "Protocol": "TCP" if protocol == 0 else "UDP",
            "Status": status
        })

# Sniff packets
packets = sniff(count=packet_count, iface=interface)
for packet in packets:
    process_packet(packet)

# Convert packet records to a DataFrame
packet_df = pd.DataFrame(packet_records)

# Retrieve firewall's IP address
def get_firewall_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

firewall_ip = get_firewall_ip()

# Streamlit app layout
st.title("Firewall Packet Monitoring")

# Dropdown to block an IP (shows only allowed IPs)
if allowed_ips:
    selected_ip_to_block = st.selectbox("Block IP", list(allowed_ips))
    if st.button("Block IP"):
        allowed_ips.discard(selected_ip_to_block)
        blocked_ips.add(selected_ip_to_block)
        block_ip_in_windows(selected_ip_to_block)
else:
    st.warning("No IPs available to block.")

# Dropdown to allow an IP (shows only blocked IPs)
if blocked_ips:
    selected_ip_to_allow = st.selectbox("Allow IP", list(blocked_ips))
    if st.button("Allow IP"):
        blocked_ips.discard(selected_ip_to_allow)
        allowed_ips.add(selected_ip_to_allow)
        unblock_ip_in_windows(selected_ip_to_allow)
else:
    st.warning("No IPs available to allow.")

# Dropdown to block a port (shows only allowed ports)
if allowed_ports:
    selected_port_to_block = st.selectbox("Block Port", list(allowed_ports))
    if st.button("Block Port"):
        allowed_ports.discard(selected_port_to_block)
        blocked_ports.add(selected_port_to_block)
        block_port_in_windows(selected_port_to_block)
else:
    st.warning("No ports available to block.")

# Dropdown to allow a port (shows only blocked ports)
if blocked_ports:
    selected_port_to_allow = st.selectbox("Allow Port", list(blocked_ports))
    if st.button("Allow Port"):
        blocked_ports.discard(selected_port_to_allow)
        allowed_ports.add(selected_port_to_allow)
        unblock_port_in_windows(selected_port_to_allow)
else:
    st.warning("No ports available to allow.")

# Display table with packet details
st.subheader("Packet Table")
st.dataframe(packet_df)

# Display the firewall's IP address
st.subheader("Firewall IP Address")
st.write(f"Firewall IP Address: {firewall_ip}")

# Create a stacked bar chart if packets exist
if not packet_df.empty:
    packet_counts = packet_df.groupby(['Source IP', 'Status']).size().reset_index(name='Count')
    fig = px.bar(packet_counts, x='Source IP', y='Count', color='Status',
                 title='Packet Status by Source IP',
                 labels={'Count': 'Number of Packets', 'Source IP': 'Source IP'},
                 text='Count')
    fig.update_traces(texttemplate='%{text}', textposition='outside')
    fig.update_layout(barmode='stack', xaxis_title='Source IP', yaxis_title='Number of Packets')
    st.plotly_chart(fig)