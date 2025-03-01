import subprocess
import socket
import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import tensorflow as tf
from scapy.all import sniff, IP, TCP
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# Initialize session state
if "packet_data" not in st.session_state:
    st.session_state.packet_data = pd.DataFrame(columns=["Source IP", "Destination IP", "Source Port", "Destination Port", "Packet Size", "Protocol", "Status"])
if "blocked_ports" not in st.session_state:
    st.session_state.blocked_ports = set()

# Sidebar Login
st.sidebar.title("Firewall Login")
username = st.sidebar.text_input("Username")
password = st.sidebar.text_input("Password", type="password")

if st.sidebar.button("Login"):
    if username == "admin" and password == "admin":
        st.session_state.authenticated = True
        st.sidebar.success("Login successful!")
    else:
        st.sidebar.error("Invalid credentials")

if not st.session_state.get("authenticated", False):
    st.stop()

# Train TensorFlow model (placeholder)
def train_tensorflow_model():
    train_data = np.random.rand(1000, 6)
    X_train, X_test, _, _ = train_test_split(train_data, np.random.randint(0, 2, size=1000), test_size=0.2)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(6,)),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(X_train, np.random.randint(0, 2, size=len(X_train)), epochs=5, batch_size=32)

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    tflite_model = converter.convert()
    
    with open('anomaly_model.tflite', 'wb') as f:
        f.write(tflite_model)

    return scaler

scaler = train_tensorflow_model()
interpreter = tf.lite.Interpreter(model_path='anomaly_model.tflite')
interpreter.allocate_tensors()

input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()

# TFLite prediction
def tflite_predict(features):
    features = scaler.transform(features.reshape(1, -1)).astype(np.float32)
    interpreter.set_tensor(input_details[0]['index'], features)
    interpreter.invoke()
    return interpreter.get_tensor(output_details[0]['index'])[0][0]

# Firewall function
def block_port(port):
    try:
        command = f'netsh advfirewall firewall add rule name="AutoBlock_{port}" protocol=TCP dir=in action=block localport={port}'
        subprocess.run(command, shell=True, check=True)
        st.session_state.blocked_ports.add(port)
    except Exception as e:
        st.sidebar.error(f"Error blocking port {port}: {e}")

# Process packets
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if packet.haslayer(TCP) else 0
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else 0
        packet_size = len(packet)
        protocol = "TCP" if packet.haslayer(TCP) else "UDP"

        features = np.array([hash(src_ip) % 10000, hash(dst_ip) % 10000, src_port, dst_port, packet_size, 0 if protocol == "TCP" else 1])
        prediction = tflite_predict(features)

        if prediction > 0.3:
            status = "Blocked"
            if dst_port not in st.session_state.blocked_ports:
                block_port(dst_port)  # Auto-block suspicious ports
        else:
            status = "Allowed"

        new_data = pd.DataFrame({
            "Source IP": [src_ip], "Destination IP": [dst_ip],
            "Source Port": [src_port], "Destination Port": [dst_port],
            "Packet Size": [packet_size], "Protocol": [protocol],
            "Status": [status]
        })

        st.session_state.packet_data = pd.concat([st.session_state.packet_data, new_data], ignore_index=True)

# Start sniffing packets
def start_sniffing():
    sniff(count=10, prn=process_packet)

st.sidebar.button("Start Sniffing", on_click=start_sniffing)

# Display Packet Data
st.title("Live Packet Sniffing Table")
if not st.session_state.packet_data.empty:
    st.dataframe(st.session_state.packet_data)
else:
    st.write("No packets captured yet.")

# Status Bar Chart
if not st.session_state.packet_data.empty:
    status_counts = st.session_state.packet_data["Status"].value_counts()
    color_map = {"Allowed": "green", "Blocked": "orangered"}
    fig = px.bar(
        x=status_counts.index, 
        y=status_counts.values, 
        color=status_counts.index, 
        color_discrete_map=color_map,
        labels={"x": "Status", "y": "Count"}, 
        title="Packet Status Analysis"
    )
    st.plotly_chart(fig)

# Show Blocked Ports
st.sidebar.title("Blocked Ports")
st.sidebar.write(list(st.session_state.blocked_ports))
