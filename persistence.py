# persistence.py
# Modul untuk menyimpan dan memuat state aplikasi ke file.

import os
import json
import logging

# Impor dari modul lain
import config
import state
from response import check_iptables_rule_exists, block_ip_iptables

def save_ip_status():
    """Menyimpan status blocked_ips dan quarantine_ips ke file JSON."""
    try:
        data = {
            "blocked_ips": list(state.blocked_ips),
            "quarantine_ips": state.quarantine_ips
        }
        with open(config.STATUS_FILE, "w") as f:
            json.dump(data, f, indent=4)
        logging.info(f"IP status saved to {config.STATUS_FILE}.")
    except Exception as e:
        logging.error(f"Failed to save IP status to {config.STATUS_FILE}: {e}")

def load_ip_status():
    """Memuat status IP dari file dan menerapkan kembali aturan iptables jika perlu."""
    try:
        if os.path.exists(config.STATUS_FILE):
            with open(config.STATUS_FILE, "r") as f:
                data = json.load(f)
                state.blocked_ips.update(data.get("blocked_ips", []))
                state.quarantine_ips.update(data.get("quarantine_ips", {}))
            logging.info(f"Loaded {len(state.blocked_ips)} blocked IPs and {len(state.quarantine_ips)} quarantined IPs.")

            # Sinkronisasi dengan iptables
            all_ips_to_check = list(state.blocked_ips) + list(state.quarantine_ips.keys())
            for ip in all_ips_to_check:
                if not check_iptables_rule_exists(ip):
                    logging.warning(f"IP {ip} ada di status file tapi tidak ada di iptables. Menambahkan...")
                    block_ip_iptables(ip)
    except Exception as e:
        logging.error(f"Failed to load IP status from {config.STATUS_FILE}: {e}")
