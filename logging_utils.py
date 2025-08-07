# logging_utils.py
# Modul untuk menangani semua operasi logging.

import json
import logging
import time
import config # Impor konfigurasi

def write_log_serangan(event_dict):
    """
    Simpan event serangan ke file serangan_log.jsonl sebagai JSON lines.
    """
    try:
        with open(config.LOG_FILE, "a") as f:
            f.write(json.dumps(event_dict) + "\n")
        logging.info(f"Event logged: {event_dict['type']} from {event_dict['source_ip']}")
    except Exception as e:
        logging.error(f"Gagal menulis log serangan: {e}")

def log_telegram_activity(text, direction="out"):
    """
    Log aktivitas Telegram (pesan terkirim atau perintah diterima) ke file.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    prefix = "SENT" if direction == "out" else "RECEIVED"
    try:
        with open(config.TELEGRAM_LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] [{prefix}] {text}\n")
    except Exception as e:
        logging.error(f"Gagal menulis log Telegram: {e}")
