# detection.py
# Modul yang berisi semua fungsi untuk mendeteksi berbagai jenis serangan.

import logging
import time
from scapy.all import IP, TCP, ICMP, UDP

# Impor dari modul lain
import config
import state
from response import block_ip_iptables
from logging_utils import write_log_serangan

# --- FUNGSI BANTUAN BARU ---
def is_in_cooldown(ip):
    """
    Memeriksa apakah IP dalam masa tenang.
    Jika masa tenang sudah lewat, hapus IP dari daftar dan kembalikan False.
    """
    if ip in state.unblock_cooldown:
        if time.time() < state.unblock_cooldown[ip]:
            # Masih dalam masa tenang, abaikan deteksi
            return True
        else:
            # Waktu tenang sudah habis, hapus dari daftar agar deteksi normal kembali
            del state.unblock_cooldown[ip]
            logging.info(f"[GRACE_PERIOD] Masa tenang untuk IP {ip} telah berakhir.")
            return False
    # Tidak ada dalam daftar cooldown
    return False
# --- AKHIR FUNGSI BANTUAN BARU ---


# Ganti fungsi lama dengan yang ini di file detection.py

# Ganti fungsi lama dengan yang ini di file detection.py

def detect_bruteforce(ip):
    """Deteksi brute-force berdasarkan percobaan koneksi ke honeypot."""
    # Pemeriksaan cooldown yang sudah kita tambahkan sebelumnya
    if is_in_cooldown(ip):
        return

    attempts = state.honeypot_auth_attempts.get(ip, 0)
    if attempts >= config.BRUTE_FORCE_THRESHOLD:
        # --- BLOK MODIFIKASI DIMULAI (Logika Blokir Permanen) ---

        alert_msg = (f"<b>[ALERT] Brute Force on Honeypot</b>\n"
                     f"Source IP: <code>{ip}</code>\n"
                     f"Attempts: {attempts}\n"
                     # --- PERUBAHAN: Teks aksi diubah menjadi Blokir Permanen ---
                     f"Action: Pemblokiran Permanen.")
                     
        logging.warning(f"Brute Force on Honeypot from {ip}. Blocking permanently.")
        state.telegram_send_queue.put(alert_msg)

        # Lakukan aksi blokir menggunakan fungsi yang sudah ada
        if block_ip_iptables(ip):
            # --- PERUBAHAN: IP ditambahkan ke state blokir permanen, bukan karantina ---
            state.blocked_ips.add(ip)
        
        # Reset counter setelah dideteksi dan diblokir
        state.honeypot_auth_attempts[ip] = 0
        
        write_log_serangan({
            "type": "bruteforce_honeypot", 
            "source_ip": ip, 
            "attempts": attempts, 
            "time": time.strftime("%Y-%m-%d %H:%M:%S"), 
            "level": "tinggi",
            # --- PERUBAHAN: Log aksi diubah menjadi blokir permanen ---
            "action": "permanent_block"
        })
        # --- BLOK MODIFIKASI SELESAI ---

def detect_port_scan(pkt):
    """Deteksi Port Scanning."""
    if IP in pkt and TCP in pkt and pkt[TCP].flags == 'S':
        src_ip = pkt[IP].src

        # --- MODIFIKASI: Periksa masa tenang di awal ---
        if is_in_cooldown(src_ip):
            return
        # --- AKHIR MODIFIKASI ---

        dst_port = pkt[TCP].dport
        timestamp = time.time()

        if src_ip not in state.connection_attempts:
            state.connection_attempts[src_ip] = []
        
        state.connection_attempts[src_ip].append((dst_port, timestamp))
        state.connection_attempts[src_ip] = [(p, t) for p, t in state.connection_attempts[src_ip] if timestamp - t <= config.SCAN_TIME_WINDOW]
        unique_ports = {p for p, t in state.connection_attempts[src_ip]}

        if len(unique_ports) >= config.PORT_SCAN_THRESHOLD:
            alert_msg = (f"<b>[ALERT] Port Scan detected</b>\n"
                         f"Source IP: <code>{src_ip}</code>\n"
                         f"Ports scanned: {len(unique_ports)} in {config.SCAN_TIME_WINDOW}s\n"
                         f"Action: Karantina 30 menit.")
            logging.warning(alert_msg)
            state.telegram_send_queue.put(alert_msg)

            if block_ip_iptables(src_ip):
                state.quarantine_ips[src_ip] = time.time() + 30 * 60
            
            write_log_serangan({"type": "port_scan", "source_ip": src_ip, "unique_ports": len(unique_ports), "time": time.strftime("%Y-%m-%d %H:%M:%S"), "level": "sedang"})
            state.connection_attempts[src_ip] = [] # Reset


# --- TAMBAHKAN FUNGSI BARU INI ---
def detect_global_syn_flood():
    """Mendeteksi anomali volume paket SYN secara global (untuk IP acak)."""
    if time.time() < state.global_dos_alert_cooldown:
        return

    packet_count = len(state.global_syn_packets)

    if packet_count > config.GLOBAL_SYN_THRESHOLD:
        logging.critical(f"GLOBAL DDOS ALERT! {packet_count} SYN pkts in {config.GLOBAL_SYN_TIME_WINDOW}s.")
        
        alert_msg = (f"<b>[GLOBAL ALERT] Distributed DoS Attack Detected</b>\n"
                     f"Signature: High-Volume SYN Flood\n"
                     f"Packets: {packet_count} in {config.GLOBAL_SYN_TIME_WINDOW}s\n"
                     f"Note: Serangan dari banyak sumber acak. Tidak ada IP spesifik yang diblokir.")
        
        state.telegram_send_queue.put(alert_msg)
        state.global_dos_alert_cooldown = time.time() + config.GLOBAL_COOLDOWN
        state.global_syn_packets.clear()

        write_log_serangan({
            "type": "dos_global_syn_flood", 
            "source_ip": "Multiple/Randomized", 
            "packets_in_window": packet_count,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"), 
            "level": "kritis",
            "action": "global_alert_sent"
        })

# --- GANTI FUNGSI LAMA DENGAN VERSI UPGRADE INI ---
def detect_syn_flood_cerdas(ip):
    """Mendeteksi SYN Flood per-IP dengan metode Fast-Path dan Ratio-Based."""
    # Metode 1: Fast-Path Volume Detection
    fast_path_count = len(state.fast_path_syn_timestamps.get(ip, []))
    if fast_path_count >= config.FAST_PATH_SYN_COUNT:
        last_notify = state.dos_notification_cooldown.get(ip, 0)
        if time.time() - last_notify > config.DOS_COOLDOWN:
            state.dos_notification_cooldown[ip] = time.time()
            alert_msg = (f"<b>[ALERT] High-Volume SYN Flood (Fast-Path)</b>\n"
                         f"Source IP: <code>{ip}</code>\n"
                         f"Signature: {fast_path_count} SYN pkts in {config.FAST_PATH_TIME_WINDOW}s\n"
                         f"Action: Pemblokiran Permanen.")
            logging.critical(f"Fast-Path SYN Flood from {ip}. Blocking permanently.")
            state.telegram_send_queue.put(alert_msg)

            if block_ip_iptables(ip):
                state.blocked_ips.add(ip)

            write_log_serangan({
                "type": "dos_syn_volume_fastpath", "source_ip": ip, "packet_count": fast_path_count,
                "time": time.strftime("%Y-%m-%d %H:%M:%S"), "level": "sangat tinggi", "action": "permanent_block"
            })
            if ip in state.fast_path_syn_timestamps:
                del state.fast_path_syn_timestamps[ip]
            return

    # Metode 2: Ratio-Based Detection
    syn_count = state.syn_count_smart.get(ip, 0)
    if syn_count < config.RATIO_MIN_SYN_COUNT:
        return

    fin_rst_count = state.fin_rst_count_smart.get(ip, 0)
    ratio = syn_count / (fin_rst_count + 1)

    if ratio > config.RATIO_THRESHOLD:
        last_notify = state.dos_notification_cooldown.get(ip, 0)
        if time.time() - last_notify > config.DOS_COOLDOWN:
            state.dos_notification_cooldown[ip] = time.time()
            alert_msg = (f"<b>[ALERT] High-Ratio SYN Flood Detected</b>\n"
                         f"Source IP: <code>{ip}</code>\n"
                         f"Signature: Abnormal SYN/FIN-RST Ratio\n"
                         f"Ratio: {syn_count}/{fin_rst_count+1} (> {config.RATIO_THRESHOLD})\n"
                         f"Action: Pemblokiran Permanen.")
            logging.critical(alert_msg)
            state.telegram_send_queue.put(alert_msg)

            if block_ip_iptables(ip):
                state.blocked_ips.add(ip)
            
            write_log_serangan({
                "type": "dos_syn_ratio_anomaly", "source_ip": ip, "syn_count": syn_count, 
                "fin_rst_count": fin_rst_count, "time": time.strftime("%Y-%m-%d %H:%M:%S"), 
                "level": "sangat tinggi", "action": "permanent_block"
            })
            
            del state.syn_count_smart[ip]
            if ip in state.fin_rst_count_smart:
                del state.fin_rst_count_smart[ip]

                
# # --- TAMBAHKAN FUNGSI BARU INI ---
# def detect_syn_flood_cerdas(ip):
#     """
#     Mendeteksi SYN Flood menggunakan signature rasio SYN terhadap FIN/RST
#     untuk mengurangi false positive dari server sibuk.
#     """
#     syn_count = state.syn_count_smart.get(ip, 0)
    
#     # 1. Pengecekan awal: Hanya proses jika jumlah SYN sudah signifikan
#     if syn_count < config.RATIO_MIN_SYN_COUNT:
#         return

#     fin_rst_count = state.fin_rst_count_smart.get(ip, 0)
    
#     # 2. Hitung rasio
#     # Menambahkan 1 untuk menghindari error pembagian dengan nol jika fin_rst_count = 0
#     ratio = syn_count / (fin_rst_count + 1)

#     # 3. Bandingkan dengan threshold
#     if ratio > config.RATIO_THRESHOLD:
#         last_notify = state.dos_notification_cooldown.get(ip, 0)
#         if time.time() - last_notify > config.DOS_COOLDOWN:
#             state.dos_notification_cooldown[ip] = time.time()
#             alert_msg = (f"<b>[ALERT] High-Ratio SYN Flood Detected</b>\n"
#                          f"Source IP: <code>{ip}</code>\n"
#                          f"Signature: Abnormal SYN/FIN-RST Ratio\n"
#                          f"Ratio: {syn_count}/{fin_rst_count+1} (> {config.RATIO_THRESHOLD})\n"
#                          f"Action: Pemblokiran Permanen.")
#             logging.critical(alert_msg)
#             state.telegram_send_queue.put(alert_msg)

#             if block_ip_iptables(ip):
#                 state.blocked_ips.add(ip)
            
#             write_log_serangan({
#                 "type": "dos_syn_ratio_anomaly", 
#                 "source_ip": ip, 
#                 "syn_count": syn_count, 
#                 "fin_rst_count": fin_rst_count, 
#                 "time": time.strftime("%Y-%m-%d %H:%M:%S"), 
#                 "level": "sangat tinggi"
#             })
            
#             # Reset counter setelah deteksi agar tidak memicu berulang kali
#             del state.syn_count_smart[ip]
#             if ip in state.fin_rst_count_smart:
#                 del state.fin_rst_count_smart[ip]

# def detect_dos(pkt):
#     """Deteksi SYN Flood (DoS)."""
#     if IP in pkt and TCP in pkt and pkt[TCP].flags == 'S':
#         src_ip = pkt[IP].src

#         # --- MODIFIKASI: Periksa masa tenang di awal ---
#         if is_in_cooldown(src_ip):
#             return
#         # --- AKHIR MODIFIKASI ---

#         timestamp = time.time()

#         if src_ip not in state.packet_counts:
#             state.packet_counts[src_ip] = []
        
#         state.packet_counts[src_ip].append(timestamp)
#         state.packet_counts[src_ip] = [t for t in state.packet_counts[src_ip] if timestamp - t <= config.DOS_TIME_WINDOW]
#         count = len(state.packet_counts[src_ip])

#         if count > config.DOS_PACKET_THRESHOLD:
#             last_notify = state.dos_notification_cooldown.get(src_ip, 0)
#             if time.time() - last_notify > config.DOS_COOLDOWN:
#                 state.dos_notification_cooldown[src_ip] = time.time()
#                 alert_msg = (f"<b>[ALERT] SYN Flood (DoS) detected</b>\n"
#                              f"Source IP: <code>{src_ip}</code>\n"
#                              f"SYN Packets: {count} in {config.DOS_TIME_WINDOW}s\n"
#                              f"Action: Pemblokiran Permanen.")
#                 logging.critical(alert_msg)
#                 state.telegram_send_queue.put(alert_msg)

#                 if block_ip_iptables(src_ip):
#                     state.blocked_ips.add(src_ip)
                
#                 write_log_serangan({"type": "dos_syn_flood", "source_ip": src_ip, "packets_in_window": count, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "level": "tinggi"})