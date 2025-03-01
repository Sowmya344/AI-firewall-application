# AI-firewall-application



![GitHub](https://img.shields.io/badge/Python-3.8%2B-green)  
![GitHub](https://img.shields.io/badge/Framework-Streamlit-red)  
![GitHub](https://img.shields.io/badge/ML-TensorFlow%20Lite-orange)  

---

## **Overview**  
This project, **"Scaling Trust: AI-Powered Detection of Online Harms,"** is a real-time network monitoring and threat detection system designed to identify and mitigate online harms such as malicious traffic, unauthorized access attempts, and suspicious activities. Leveraging AI and machine learning, the system analyzes live network packets, classifies them as either safe or harmful, and automatically blocks suspicious ports or IPs. The solution is built with a user-friendly interface powered by **Streamlit**, enabling administrators to monitor network traffic, view blocked ports, and download packet data for further analysis.  

---

## **Key Features**  
- **Live Packet Sniffing:** Captures and analyzes network packets in real-time.  
- **AI-Based Threat Detection:** Uses TensorFlow Lite for real-time classification of packets as "Allowed" or "Blocked."  
- **Automated Port Blocking:** Blocks suspicious ports automatically using system firewall rules.  
- **Interactive Dashboard:** Provides a visual representation of packet statuses and blocked ports.  
- **Data Export:** Allows users to download the live packet sniffing table as a CSV file for further analysis.  
- **User Authentication:** Secure login system for administrators to access the dashboard.  
- **Visual Analytics:** Includes a bar chart to visualize the distribution of allowed and blocked packets.  

---

## **Technologies Used**  
- **Streamlit:** For building the interactive web-based dashboard.  
- **TensorFlow Lite:** For lightweight and efficient AI-based anomaly detection.  
- **Scapy:** For live packet sniffing and network traffic analysis.  
- **Pandas:** For data manipulation and storage of packet information.  
- **Plotly:** For creating interactive visualizations of packet statuses.  
- **Numpy:** For numerical computations and feature preprocessing.  
- **Subprocess:** For executing system commands to block ports dynamically.  
- **Socket:** For network-related operations.  

---

## **How It Works**  
1. **Packet Capture:** The system uses **Scapy** to sniff live network packets.  
2. **Feature Extraction:** Key features such as source IP, destination IP, source port, destination port, packet size, and protocol are extracted from each packet.  
3. **AI-Based Classification:** The extracted features are passed through a **TensorFlow Lite** model to classify the packet as "Allowed" or "Blocked."  
4. **Automated Response:** If a packet is classified as suspicious, the system automatically blocks the destination port using system firewall rules.  
5. **Dashboard Visualization:** The results are displayed in an interactive **Streamlit** dashboard, where administrators can monitor traffic, view blocked ports, and download packet data.  

---

## **Installation**  
### Prerequisites  
- Python 3.8+  
- Pip (Python package manager)  

### Steps  
1) Download the whole code in a zip file 
2) download the packages mentioned in the requirments.txt
3) I dont know for mac or linux, since I use windows, I do this before i run the command in the 4th step:
   cd c:/path/to/your/folder/where the csv file is/dont add the file name in this command
4) Then run with this command:
    streamlit run google_hackathon_firewall.py
---

## **Usage**  
1. **Login:** Use the default credentials (`username: admin`, `password: admin`) to log in.  
2. **Start Sniffing:** Click the "Start Sniffing" button to begin capturing and analyzing network packets.  
3. **Monitor Traffic:** View the live packet sniffing table and the status of each packet (Allowed/Blocked).  
4. **Visual Analytics:** Check the bar chart for a visual representation of packet statuses.  
5. **Blocked Ports:** View the list of blocked ports in the sidebar.  
6. **Export Data:** Download the packet data as a CSV file for further analysis.  

---

## **Screenshots**  
![image](https://github.com/user-attachments/assets/3e8c14a5-cf9e-49a8-ac57-6caa3ce8b87e)

![image](https://github.com/user-attachments/assets/c4253645-1225-4f8e-b6d2-8d3c7da86cf9)
 

---

## **Contributing**  
We welcome contributions! If you'd like to contribute, please follow these steps:  
1. Fork the repository.  
2. Create a new branch (`git checkout -b feature/YourFeatureName`).  
3. Commit your changes (`git commit -m 'Add some feature'`).  
4. Push to the branch (`git push origin feature/YourFeatureName`).  
5. Open a pull request.  

---





## **Contact**  
For any questions or feedback, feel free to reach out:  
- **Email:** rameshsowmya365@gmail.com(personal email)
             sr1961@srmist.edu.in(SRM college email) 
- **GitHub:** Sowmya344([https://github.com/your-username](https://github.com/Sowmya344))  

---

**Thank you for checking out our project!** 🚀
