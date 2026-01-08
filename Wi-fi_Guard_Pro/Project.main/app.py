from flask import Flask, render_template, jsonify
import pywifi
from pywifi import const
import time
import subprocess
import platform
from flask_cors import CORS
import speedtest
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QListWidget, QTextEdit,
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
    QFileDialog, QLabel, QMessageBox, QSplitter, QInputDialog
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QSize
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from scapy.all import AsyncSniffer, rdpcap, wrpcap, get_if_list, TCP, UDP, Raw
import yara
import sys
import warnings

app = Flask(__name__)
CORS(app)

# Function to perform a speed test
def perform_speed_test():
    st = speedtest.Speedtest()
    st.get_best_server()
    download_speed = st.download() / 1_000_000  # Convert to Mbps
    upload_speed = st.upload() / 1_000_000      # Convert to Mbps
    ping = st.results.ping
    return {
        'download': round(download_speed, 2),
        'upload': round(upload_speed, 2),
        'latency': round(ping, 2)
    }

# Route to perform the speed test and return JSON data
@app.route('/speedtest1')
def speed_test():
    results = perform_speed_test()
    return jsonify(results)

# Route to display the main page
@app.route('/speed')
def speed():
    return render_template('index.html')
# Function to scan for Wi-Fi networks
def scan_networks():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]  # Access the first wireless interface
    iface.scan()  # Start the scanning process
    time.sleep(5)  # Allow time for the scan to complete

    scan_results = iface.scan_results()  # Get the scan results
    networks = []
    for network in scan_results:
        networks.append({
            "ssid": network.ssid if network.ssid else "Hidden Network",
            "signal_strength": network.signal,
            "channel": network.freq,
            "mac_address": network.bssid,
            "encryption": network.akm
        })
    return networks

# Route to display the main page
@app.route('/')
def index():
    return render_template('first.html')

# Route to perform the scan and return the scan result page
@app.route('/scan')
def scan():
    results = scan_networks()
    print("Scan Results:", results)  # Debugging step to see if data is being retrieved
    return render_template('index1.html', networks=results)

def run_command(command):
    """Run a command in subprocess and return the output or error."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"
def run_as_admin(command):
    """Runs a command with administrator privileges using PowerShell."""
    subprocess.run(
        f'powershell -Command "Start-Process cmd -ArgumentList \'/c {command}\' -Verb RunAs"',
        shell=True
    )
@app.route('/wifi/off', methods=['POST'])
def disable_wifi():
    try:
        run_as_admin('netsh interface set interface "Wi-Fi" disabled')
        return jsonify({"status": "Wi-Fi Disabled Successfully"})
    except Exception as e:
        return jsonify({"status": f"Error: {e}"}), 500

@app.route('/wifi/on', methods=['POST'])
def enable_wifi():
    try:
        run_as_admin('netsh interface set interface "Wi-Fi" enabled')
        return jsonify({"status": "Wi-Fi Enabled Successfully"})
    except Exception as e:
        return jsonify({"status": f"Error: {e}"}), 500

def disable_wifi():
    """Disable Wi-Fi on Windows using 'netsh'."""
    interface_name = "Wi-Fi"
    command = ['netsh', 'interface', 'set', 'interface', interface_name, 'disabled']
    return run_command(command)

def enable_wifi():
    """Enable Wi-Fi on Windows using 'netsh'."""
    interface_name = "Wi-Fi"
    command = ['netsh', 'interface', 'set', 'interface', interface_name, 'enabled']
    return run_command(command)

@app.route('/lock')
def lock():
    """Render the main page."""
    return render_template('lock.html')

@app.route('/wifi/off', methods=['POST'])
def wifi_off():
    """Disable Wi-Fi on the computer."""
    message = disable_wifi()
    return jsonify({'status': message})

@app.route('/wifi/on', methods=['POST'])
def wifi_on():
    """Enable Wi-Fi on the computer."""
    message = enable_wifi()
    return jsonify({'status': message})

@app.route('/run-python')
def run_python():
    

    warnings.filterwarnings("ignore", message="Blowfish has been deprecated", category=DeprecationWarning)
    warnings.filterwarnings("ignore", message="CAST5 has been deprecated", category=DeprecationWarning)

    class NetworkAnalyzerApp(QMainWindow):
        def __init__(self):
            super().__init__()
            self.initUI()
            self.packets = []
            self.capture_thread = None
            self.yara_rules = []
            self.plot_open = False

        def initUI(self):
            self.setWindowTitle("WIFI GUARD PRO")
            self.setGeometry(200, 200, 900, 700)

            # Set white background for the main widget
            main_widget = QWidget()
            main_widget.setStyleSheet("background-color: white;")  # White background
            layout = QVBoxLayout(main_widget)

            # Title Label
            title_label = QLabel("WIFI-GUARD")
            title_label.setFont(QFont("Arial", 16, QFont.Bold))  # Reduced font size
            title_label.setAlignment(Qt.AlignCenter)
            title_label.setFixedHeight(40)  # Fixed height for the title label

            # Add title label to the layout
            title_layout = QVBoxLayout()
            title_layout.addWidget(title_label)
            layout.addLayout(title_layout)

            layout.addSpacing(20)  # Add space after the title

            # Create a button layout for Start, Stop Capture, etc.
            buttons_layout = QHBoxLayout()

            # Styling the buttons to have a dark blue (#0000FF) background with white text
            button_style = "background-color: #316FF6; color: white; font-weight: bold; border-radius: 5px; padding: 10px;"

            self.capture_button = QPushButton("Start Live Capture")
            self.capture_button.setStyleSheet(button_style)
            self.capture_button.clicked.connect(self.start_capture)
            buttons_layout.addWidget(self.capture_button)

            self.stop_capture_button = QPushButton("Stop Capture")
            self.stop_capture_button.setStyleSheet(button_style)
            self.stop_capture_button.clicked.connect(self.stop_capture)
            self.stop_capture_button.setEnabled(False)
            buttons_layout.addWidget(self.stop_capture_button)

            self.load_button = QPushButton("Load Packet File")
            self.load_button.setStyleSheet(button_style)
            self.load_button.clicked.connect(self.load_packet_file)
            buttons_layout.addWidget(self.load_button)

            self.save_button = QPushButton("Save Packets")
            self.save_button.setStyleSheet(button_style)
            self.save_button.clicked.connect(self.save_captured_packets)
            buttons_layout.addWidget(self.save_button)

            layout.addLayout(buttons_layout)

            splitter = QSplitter(Qt.Horizontal)

            self.packet_list = QListWidget()
            self.packet_list.itemClicked.connect(self.display_packet_details)
            splitter.addWidget(self.packet_list)

            self.packet_details = QTextEdit()
            self.packet_details.setReadOnly(True)
            splitter.addWidget(self.packet_details)

            layout.addWidget(splitter)

            yara_layout = QHBoxLayout()
            self.load_yara_button = QPushButton("Load YARA Rules")
            self.load_yara_button.setStyleSheet(button_style)
            self.load_yara_button.clicked.connect(self.load_yara_rules)
            yara_layout.addWidget(self.load_yara_button)

            self.malware_button = QPushButton("Find Malware")
            self.malware_button.setStyleSheet(button_style)
            self.malware_button.clicked.connect(self.detect_malware)
            yara_layout.addWidget(self.malware_button)

            layout.addLayout(yara_layout)

            self.plot_button = QPushButton("Open/Close Protocol Plot")
            self.plot_button.setStyleSheet(button_style)
            self.plot_button.clicked.connect(self.toggle_protocol_plot)
            layout.addWidget(self.plot_button)

            self.fig, self.ax = plt.subplots()
            self.canvas = FigureCanvas(self.fig)
            layout.addWidget(self.canvas)
            self.canvas.setVisible(False)

            self.setCentralWidget(main_widget)

        def start_capture(self):
            try:
                self.packets = []
                interfaces = get_if_list()
                interface, ok = QInputDialog.getItem(self, "Select Interface", "Available Interfaces:", interfaces, 0, False)

                if ok and interface:
                    self.capture_thread = AsyncSniffer(prn=self.add_packet, store=False, iface=interface)
                    self.capture_thread.start()
                    self.capture_button.setEnabled(False)
                    self.stop_capture_button.setEnabled(True)
                else:
                    QMessageBox.warning(self, "No Interface Selected", "You must select a network interface.")
            except Exception as e:
                QMessageBox.critical(self, "Capture Error", f"An error occurred: {str(e)}")
                self.capture_button.setEnabled(True)
                self.stop_capture_button.setEnabled(False)

        def stop_capture(self):
            if self.capture_thread:
                self.capture_thread.stop()
                self.capture_thread.join()
                self.capture_thread = None
            self.capture_button.setEnabled(True)
            self.stop_capture_button.setEnabled(False)

        def add_packet(self, packet):
            self.packets.append(packet)
            self.packet_list.addItem(f"Packet {len(self.packets)}: {packet.summary()}")

        def load_packet_file(self):
            pcap_path, _ = QFileDialog.getOpenFileName(self, "Open Packet File", "", "PCAP Files (*.pcap *.pcapng)")
            if pcap_path:
                self.packets = rdpcap(pcap_path)
                self.packet_list.clear()
                for idx, packet in enumerate(self.packets):
                    self.packet_list.addItem(f"Packet {idx + 1}: {packet.summary()}")

        def display_packet_details(self, item):
            packet_index = self.packet_list.row(item)
            packet = self.packets[packet_index]
            packet_summary = str(packet.show(dump=True))
            self.packet_details.setPlainText(packet_summary)

        def load_yara_rules(self):
            yara_path, _ = QFileDialog.getOpenFileName(self, "Open YARA Rule File", "", "YARA Files (*.yar)")
            if yara_path:
                self.yara_rules = [yara.compile(filepath=yara_path)]
                QMessageBox.information(self, "YARA Rules Loaded", "YARA rules have been loaded.")

        def detect_malware(self):
            if not self.yara_rules:
                QMessageBox.warning(self, "YARA Rules Not Loaded", "Please load YARA rules first.")
                return

            potential_malware = []

            for packet in self.packets:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode(errors="ignore")
                    for rule in self.yara_rules:
                        matches = rule.match(data=payload)
                        if matches:
                            potential_malware.append(f"Packet: {packet.summary()}, Match: {matches}")

            if potential_malware:
                self.packet_details.append("\n".join(potential_malware))
            else:
                self.packet_details.append("No malware detected.")

        def toggle_protocol_plot(self):
            if self.plot_open:
                self.canvas.setVisible(False)
                self.plot_open = False
            else:
                self.plot_protocols()
                self.canvas.setVisible(True)
                self.plot_open = True

        def plot_protocols(self):
            protocol_counts = {"TCP": 0, "UDP": 0, "Other": 0}

            for packet in self.packets:
                if packet.haslayer(TCP):
                    protocol_counts["TCP"] += 1
                elif packet.haslayer(UDP):
                    protocol_counts["UDP"] += 1
                else:
                    protocol_counts["Other"] += 1

            protocols = list(protocol_counts.keys())
            counts = list(protocol_counts.values())

            self.ax.clear()
            self.ax.bar(protocols, counts, color=["#007bff", "#28a745", "#ffc107"])
            self.ax.set_xlabel("Protocols")
            self.ax.set_ylabel("Count")
            self.ax.set_title("Protocol Distribution")
            self.canvas.draw()

        def save_captured_packets(self):
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Packets", "", "PCAP Files (*.pcap)")
            if save_path:
                wrpcap(save_path, self.packets)
                QMessageBox.information(self, "Save Successful", "Packets have been saved.")

    def main():
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        window = NetworkAnalyzerApp()
        window.show()
        sys.exit(app.exec_())

    if __name__ == "__main__":
        main()
        
if __name__ == '__main__':
    app.run(debug=True)
