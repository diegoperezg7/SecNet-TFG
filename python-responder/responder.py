#!/usr/bin/env python3
import json
import os
import time
import sqlite3
import logging
import subprocess
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, request, jsonify
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/responder.log')
    ]
)
logger = logging.getLogger('responder')

# Database setup
DB_PATH = './database/alerts.db'

def init_database():
    """Initialize the SQLite database if it doesn't exist"""
    if not os.path.exists(os.path.dirname(DB_PATH)):
        os.makedirs(os.path.dirname(DB_PATH))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create alerts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        alert_message TEXT,
        severity INTEGER,
        protocol TEXT,
        action_taken TEXT,
        raw_data TEXT
    )
    ''')
    
    # Create blocked_ips table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE,
        timestamp TEXT,
        reason TEXT
    )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

def block_ip(ip_address, reason):
    """Block an IP address using iptables"""
    try:
        # Check if IP is already blocked
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        if cursor.fetchone():
            logger.info(f"IP {ip_address} is already blocked")
            conn.close()
            return False
        
        # Add to blocked_ips table
        timestamp = datetime.now().isoformat()
        cursor.execute(
            "INSERT INTO blocked_ips (ip_address, timestamp, reason) VALUES (?, ?, ?)",
            (ip_address, timestamp, reason)
        )
        conn.commit()
        conn.close()
        
        # Block using iptables
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
            check=True
        )
        logger.info(f"Blocked IP: {ip_address} for reason: {reason}")
        return True
    except Exception as e:
        logger.error(f"Failed to block IP {ip_address}: {e}")
        return False

# --- Custom Alert Classification and Whitelisting ---
LOCAL_IPS = {'127.0.0.1', '10.0.2.15', '::1', 'localhost'}
SAFE_DOMAINS = [
    r'.*\\.codeium\\.com$', r'.*githubusercontent\\.com$', r'.*docker\\.io$',
    r'codeium\\.com$', r'githubusercontent\\.com$', r'docker\\.io$',
    r'example\\.lan$', r'localdomain$', r'local$'
]
SAFE_IPS = {'8.8.8.8', '1.1.1.1'}  # Puedes ampliar esta lista

# Clasificación personalizada
def classify_alert(alert_data):
    src_ip = alert_data.get('src_ip', '')
    dest_ip = alert_data.get('dest_ip', '')
    dns_rrname = ''
    if 'dns' in alert_data and 'rrname' in alert_data['dns']:
        dns_rrname = alert_data['dns']['rrname']
    alert_msg = alert_data.get('alert', {}).get('signature', '')
    severity = int(alert_data.get('alert', {}).get('severity', 1))

    # --- HTTP interno: capturar SIEMPRE como severidad 1 ---
    if 'http' in alert_msg.lower():
        if (src_ip in LOCAL_IPS or src_ip in SAFE_IPS) and (dest_ip in LOCAL_IPS or dest_ip in SAFE_IPS):
            return 'HTTP interno bajo', 1
        for pattern in SAFE_DOMAINS:
            if (dns_rrname and re.search(pattern, dns_rrname)) or re.search(pattern, dest_ip):
                return 'HTTP interno bajo', 1
    # --- FIN HTTP interno ---

    # Tráfico interno seguro (NO HTTP): ignorar
    if (src_ip in LOCAL_IPS or src_ip in SAFE_IPS) and (dest_ip in LOCAL_IPS or dest_ip in SAFE_IPS):
        return 'Tráfico interno seguro', 0
    for pattern in SAFE_DOMAINS:
        if (dns_rrname and re.search(pattern, dns_rrname)) or re.search(pattern, dest_ip):
            return 'Tráfico legítimo externo', 1
    if src_ip in SAFE_IPS:
        return 'Tráfico legítimo externo', 1
    if severity >= 3 and not (src_ip in LOCAL_IPS or src_ip in SAFE_IPS):
        return 'Amenaza confirmada', severity
    if severity >= 2:
        return 'Actividad sospechosa', severity
    return 'Actividad sospechosa', severity


def process_alert(alert_data):
    """Process a Suricata alert and take appropriate action"""
    try:
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        src_ip = alert_data.get('src_ip', 'unknown')
        dest_ip = alert_data.get('dest_ip', 'unknown')
        # Extraer el puerto de destino si está presente
        dest_port = None
        if 'dest_port' in alert_data and alert_data['dest_port']:
            try:
                dest_port = int(alert_data['dest_port'])
            except (ValueError, TypeError):
                dest_port = None
        elif ':' in str(dest_ip):
            # Si el puerto está en dest_ip (ejemplo: 192.168.1.1:80)
            parts = str(dest_ip).split(':')
            if len(parts) > 1:
                dest_ip = parts[0]
                try:
                    dest_port = int(parts[1])
                except (ValueError, IndexError):
                    dest_port = None
        
        alert_message = alert_data.get('alert', {}).get('signature', 'Unknown alert')
        severity = alert_data.get('alert', {}).get('severity', 1)
        protocol = alert_data.get('proto', 'unknown')
        categoria, nueva_severidad = classify_alert(alert_data)
        # HTTP interno bajo: guardar como severidad 1, nunca bloquear
        if categoria == 'HTTP interno bajo':
            severity = 1
            action_taken = "Tráfico HTTP interno registrado"
        elif categoria == 'Tráfico interno seguro':
            logger.info(f"Ignorado: {alert_message} de {src_ip} a {dest_ip} (tráfico interno seguro)")
            return
        elif categoria == 'Tráfico legítimo externo':
            severity = 1
            action_taken = "Tráfico legítimo externo registrado"
        else:
            severity = nueva_severidad
            action_taken = "Logged only"
        if (categoria == 'Amenaza confirmada' or (categoria == 'Actividad sospechosa' and severity >= 2)) and src_ip not in LOCAL_IPS and src_ip not in SAFE_IPS:
            if block_ip(src_ip, f"{alert_message} [{categoria}]"):
                action_taken = f"Blocked source IP: {src_ip}"
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, src_ip, dest_ip, dest_port, alert_message, severity, protocol, action_taken, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, src_ip, dest_ip, dest_port, alert_message, severity, protocol, action_taken, json.dumps(alert_data))
        )
        conn.commit()
        conn.close()
        logger.info(f"Procesada alerta: {alert_message} de {src_ip} - Categoría: {categoria} - Acción: {action_taken}")
    except Exception as e:
        logger.error(f"Error procesando alerta: {e}")

class SuricataLogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_position = {}
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('eve.json'):
            self.process_log_file(event.src_path)
    
    def process_log_file(self, file_path):
        """Process new lines in the Suricata eve.json log file"""
        try:
            # Get current position or start from beginning
            position = self.last_position.get(file_path, 0)
            
            with open(file_path, 'r') as f:
                f.seek(position)
                for line in f:
                    line = line.strip()
                    if line:  # Skip empty lines
                        try:
                            alert_data = json.loads(line)
                            # Only process alert events
                            if alert_data.get('event_type') == 'alert':
                                process_alert(alert_data)
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in log: {line[:100]}...")
                
                # Update position for next time
                self.last_position[file_path] = f.tell()
                
        except Exception as e:
            logger.error(f"Error processing log file {file_path}: {e}")

def main():
    """Main function to start the log monitoring"""
    logger.info("Starting Suricata log monitor")
    
    # Initialize database
    init_database()
    
    # Set up log directory monitoring
    log_dir = '/var/log/suricata'
    event_handler = SuricataLogHandler()
    observer = Observer()
    observer.schedule(event_handler, log_dir, recursive=False)
    observer.start()
    
    try:
        # Check for existing log file and process it
        eve_log_path = os.path.join(log_dir, 'eve.json')
        if os.path.exists(eve_log_path):
            event_handler.process_log_file(eve_log_path)
        
        # Keep the script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Flask app for REST API
app = Flask(__name__)

@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    data = request.get_json()
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'Manual block from web interface')
    if not ip_address or not isinstance(ip_address, str):
        return jsonify({'success': False, 'message': 'No IP address provided'}), 400
    if not validate_ip(ip_address):
        return jsonify({'success': False, 'message': 'Invalid IP address format'}), 400
    result = block_ip(ip_address, reason)
    if result:
        return jsonify({'success': True, 'message': f'IP {ip_address} blocked successfully'})
    else:
        return jsonify({'success': False, 'message': f'Failed to block IP {ip_address}'})

def validate_ip(ip):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "api":
        app.run(host="0.0.0.0", port=5000, debug=False)
    else:
        main()
