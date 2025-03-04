from flask import Flask, render_template, jsonify, send_file
import pyshark
import threading
import time
import csv
from collections import defaultdict

app = Flask(__name__)

# Configuración
INTERFACE = "enp0s3"
DDOS_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 15
TIME_WINDOW = 60
ALERT_COOLDOWN = {"DDoS": 30, "PortScan": 60, "MITM": 120, "Injection": 60}

# Diccionarios para almacenamiento
traffic_count = defaultdict(int)
port_scan_count = defaultdict(set)
arp_spoofing_detected = {}
attack_logs = []
last_alert_time = defaultdict(lambda: 0)

# Lista de puertos comunes ignorados
COMMON_PORTS = {22, 53, 80, 443, 123, 5000, 8000, 8080}

# Archivo donde se guardarán los reportes
REPORTE_ARCHIVO = "reportes_ataques.csv"

# Función para escribir en el archivo CSV
def guardar_reporte(tipo, mensaje):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(REPORTE_ARCHIVO, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, tipo, mensaje])

def detect_attacks(packet):
    global traffic_count, port_scan_count, arp_spoofing_detected, attack_logs, last_alert_time
    current_time = time.time()

    try:
        if hasattr(packet, "ip"):
            src_ip = packet.ip.src

            # 🚀 Evitar marcar tráfico del propio servidor
            SERVER_IP = "10.0.2.15"
            if src_ip == SERVER_IP:
                return

            # ✅ Detección de DDoS (Solo tráfico SYN)
            if hasattr(packet, "tcp") and packet.tcp.flags == "0x0002":  # 0x0002 = SYN
                traffic_count[src_ip] += 1
                if traffic_count[src_ip] > DDOS_THRESHOLD and (current_time - last_alert_time[(src_ip, "DDoS")] > ALERT_COOLDOWN["DDoS"]):
                    log = f"⚠️ [DDoS] Posible ataque desde {src_ip} ({traffic_count[src_ip]} paquetes)"
                    print(log)
                    attack_logs.append(log)
                    guardar_reporte("DDoS", log)
                    last_alert_time[(src_ip, "DDoS")] = current_time

            # ✅ Detección de escaneo de puertos
            if hasattr(packet, "tcp"):
                dst_port = int(packet.tcp.dstport)
                if dst_port not in COMMON_PORTS:
                    port_scan_count[src_ip].add(dst_port)
                    if len(port_scan_count[src_ip]) > PORT_SCAN_THRESHOLD and (current_time - last_alert_time[(src_ip, "PortScan")] > ALERT_COOLDOWN["PortScan"]):
                        log = f"⚠️ [Escaneo de Puertos] {src_ip} está escaneando {len(port_scan_count[src_ip])} puertos"
                        print(log)
                        attack_logs.append(log)
                        guardar_reporte("Escaneo de Puertos", log)
                        last_alert_time[(src_ip, "PortScan")] = current_time

        # ✅ Detección de MITM (cambio de MAC inesperado)
        if hasattr(packet, "arp") and packet.arp.opcode == "2":  # Solo ARP Reply
            src_ip = packet.arp.src_proto_ipv4
            src_mac = packet.arp.src_hw_mac

            if src_ip in arp_spoofing_detected and arp_spoofing_detected[src_ip] != src_mac:
                if current_time - last_alert_time[(src_ip, "MITM")] > ALERT_COOLDOWN["MITM"]:
                    log = f"⚠️ [MITM] Posible ataque: {src_ip} cambió de MAC {arp_spoofing_detected[src_ip]} → {src_mac}"
                    print(log)
                    attack_logs.append(log)
                    guardar_reporte("MITM", log)
                    last_alert_time[(src_ip, "MITM")] = current_time
            else:
                arp_spoofing_detected[src_ip] = src_mac

    except AttributeError:
        pass

def sniff_packets():
    capture = pyshark.LiveCapture(interface=INTERFACE)
    start_time = time.time()

    for packet in capture.sniff_continuously():
        detect_attacks(packet)
        if time.time() - start_time > TIME_WINDOW:
            traffic_count.clear()
            port_scan_count.clear()
            start_time = time.time()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logs', methods=['GET'])
def get_logs():
    return jsonify(attack_logs)

@app.route('/descargar_reporte')
def descargar_reporte():
    return send_file(REPORTE_ARCHIVO, as_attachment=True)

if __name__ == '__main__':
    sniffing_thread = threading.Thread(target=sniff_packets)
    sniffing_thread.daemon = True
    sniffing_thread.start()
    app.run(debug=True, host='0.0.0.0')
