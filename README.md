🔐 WiFi Guard Pro

WiFi Guard Pro is a security-focused Wi-Fi monitoring and analysis tool designed to inspect nearby wireless networks, identify potential security risks, and provide actionable insights.
It helps users understand network configurations, encryption standards, traffic behavior, and possible vulnerabilities in real time.

🚀 Features

📡 Wi-Fi Network Scanning

Detects nearby Wi-Fi networks

Displays SSID, BSSID, signal strength, channel, and frequency band

🔑 Encryption & Security Analysis

Identifies security protocols (Open, WEP, WPA, WPA2, WPA3)

Highlights insecure or weakly protected networks

📊 Traffic & Packet Inspection

Captures and analyzes network packets

Classifies TCP/UDP traffic

Helps identify suspicious or abnormal behavior

⚠️ Threat Awareness

Detects patterns that may indicate attacks such as:

Deauthentication attacks

Packet sniffing risks on open networks

Weak encryption exploitation

📈 Network Performance Insights

Speed testing (download/upload)

Channel congestion awareness

🖥️ User Interface

Desktop-based interface built using PyQt

Clean visualization for logs, packets, and results

🛠️ Tech Stack

Programming Language: Python

Frameworks & Libraries:

Flask (backend / API)

PyWiFi (Wi-Fi scanning)

Scapy (packet capture & analysis)

PyQt5 (GUI)

Matplotlib (graphs & visualization)

YARA (pattern-based threat detection)

Platform: Linux (recommended for full Wi-Fi monitor support)

🧠 How It Works

Scans available Wi-Fi interfaces

Collects network metadata (SSID, channel, encryption, signal strength)

Captures packets using monitor mode

Analyzes traffic at OSI Layer 2–4

Applies rule-based detection to identify weak or risky configurations

Displays results in a structured GUI

🔍 Security Insights Provided

Risks of open and WEP networks

Channel congestion and interference issues

Encryption downgrade awareness

Packet-level visibility for forensic analysis

📂 Project Structure (Simplified)
wifi-guard-pro/
│
├── app.py                # Flask backend
├── scanner.py            # Wi-Fi scanning logic
├── packet_sniffer.py     # Packet capture & analysis
├── ui/                   # PyQt GUI components
├── rules/                # YARA rules
├── static/               # Graphs & assets
└── requirements.txt

⚙️ Installation & Usage
# Clone the repository
git clone https://github.com/your-username/wifi-guard-pro.git

# Navigate to the project
cd wifi-guard-pro

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py


⚠️ Note: Monitor mode and packet capture require administrative privileges and compatible Wi-Fi hardware.

🎯 Use Cases

Cybersecurity learning & research

Wi-Fi security audits

Network troubleshooting

Academic and demo purposes

Resume & interview showcase project

🧩 Future Enhancements

WPA handshake capture analysis

MITM attack detection

AI-based anomaly detection

Web dashboard version

Cross-platform support

⚠️ Disclaimer

This project is developed strictly for educational and ethical security testing purposes.
Do not use this tool on networks without proper authorization.

👤 Author

Tej
Cybersecurity Enthusiast | Network Security Learner
📌 Project: WiFi Guard Pro
