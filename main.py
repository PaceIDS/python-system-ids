# main.py
# File utama untuk menginisialisasi dan menjalankan seluruh sistem IDS.

import logging
import threading
import time
from scapy.all import sniff, IP, TCP

# Impor dari modul-modul yang telah kita buat
import config
import state
from persistence import load_ip_status, save_ip_status
from honeypot import start_honeypot
from response import enforce_quarantine_expiry
from telegram_bot import start_telegram_bot
from detection import detect_port_scan, detect_syn_flood_cerdas, detect_global_syn_flood


# Konfigurasi logging utama
logging.basicConfig(
    format='[%(asctime)s] %(levelname)s: %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)


# main.py

def _packet_callback(pkt):
    """Fungsi callback yang dipanggil Scapy untuk setiap paket."""
    if IP in pkt:
        ip_src = pkt[IP].src
        
        # Abaikan IP yang dikecualikan dan yang sudah diblokir
        if ip_src in config.EXCLUDED_IPS: return
        if ip_src in state.blocked_ips or ip_src in state.quarantine_ips: return

        # Deteksi Port Scanning tetap di sini
        detect_port_scan(pkt)

        # --- BLOK UTAMA UNTUK SEMUA DETEKSI SYN FLOOD ---
        if TCP in pkt:
            flags = pkt[TCP].flags
            
            # Hanya proses paket SYN murni ('S' tanpa 'A')
            if 'S' in flags and 'A' not in flags:
                timestamp = time.time()
                
                # 1. Menyiapkan data untuk Deteksi GLOBAL
                state.global_syn_packets.append(timestamp)
                state.global_syn_packets = [t for t in state.global_syn_packets if timestamp - t <= config.GLOBAL_SYN_TIME_WINDOW]
                detect_global_syn_flood()

                # 2. Menyiapkan data untuk Deteksi FAST-PATH per-IP
                if ip_src not in state.fast_path_syn_timestamps:
                    state.fast_path_syn_timestamps[ip_src] = []
                state.fast_path_syn_timestamps[ip_src].append(timestamp)
                state.fast_path_syn_timestamps[ip_src] = [
                    t for t in state.fast_path_syn_timestamps[ip_src]
                    if timestamp - t <= config.FAST_PATH_TIME_WINDOW
                ]
                
                # 3. Menyiapkan data untuk Deteksi RASIO per-IP
                if ip_src not in state.syn_count_smart:
                    state.syn_count_smart[ip_src] = 0
                state.syn_count_smart[ip_src] += 1
                
                # Panggil fungsi deteksi utama yang akan mengevaluasi semua data per-IP
                detect_syn_flood_cerdas(ip_src)

            # Menghitung paket FIN atau RST untuk logika Rasio
            elif 'F' in flags or 'R' in flags:
                if ip_src not in state.fin_rst_count_smart:
                    state.fin_rst_count_smart[ip_src] = 0
                state.fin_rst_count_smart[ip_src] += 1



def _start_sniffer():
    """Memulai sniffer paket dalam sebuah thread."""
    logging.info("Starting packet sniffer...")
    sniff(filter="ip", prn=_packet_callback, store=0)

def main():
    """Fungsi utama untuk menjalankan aplikasi."""
    logging.info("Initializing IDS system...")

    # 1. Muat status sebelumnya dari file
    load_ip_status()

    # 2. Mulai semua thread background
    start_telegram_bot()
    threading.Thread(target=enforce_quarantine_expiry, daemon=True).start()
    threading.Thread(target=start_honeypot, daemon=True).start()
    threading.Thread(target=_start_sniffer, daemon=True).start()

    logging.info("IDS system is now running. Press Ctrl+C to shut down.")

    # 3. Loop utama untuk menjaga program tetap berjalan
    try:
        while True:
            time.sleep(3600) # Tidur untuk waktu yang lama, thread lain yang bekerja
    except KeyboardInterrupt:
        logging.info("Shutdown signal received.")
        # 4. Simpan status saat program berhenti
        save_ip_status()
        logging.info("IDS system has been shut down gracefully.")

if __name__ == "__main__":
    main()
