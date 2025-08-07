# honeypot.py
# Modul untuk menjalankan honeypot sederhana.

import logging
import socket
import threading
import time

# Impor dari modul lain
import config
import state
from detection import detect_bruteforce

# Ganti dengan versi ini di file honeypot.py
def _honeypot_handler(client_sock, client_addr):
    """Menangani koneksi individu yang masuk ke honeypot."""
    ip = client_addr[0]
    logging.info(f"[HONEYPOT] Connection from {ip} to honeypot port {config.HONEYPOT_PORT}.")

    # --- PERUBAHAN LOGIKA DIMULAI DI SINI ---
    
    # Pastikan IP ada di dalam state
    if ip not in state.honeypot_auth_attempts:
        state.honeypot_auth_attempts[ip] = 0
    
    # 1. Tambah hitungan percobaan SETIAP KALI ada koneksi baru
    state.honeypot_auth_attempts[ip] += 1
    logging.info(f"[HONEYPOT] Attempt count for {ip} is now: {state.honeypot_auth_attempts[ip]}")
    
    # 2. Panggil fungsi deteksi SETIAP KALI ada koneksi baru
    detect_bruteforce(ip)

    # --- AKHIR PERUBAHAN LOGIKA ---

    # --- TAMBAHKAN PRINT UNTUK DEBUGGING ---
    current_attempts = state.honeypot_auth_attempts[ip]
    print(f"[DEBUG] Jumlah percobaan untuk {ip} sekarang adalah: {current_attempts} / {config.BRUTE_FORCE_THRESHOLD}")
    # ------------------------------------

    try:
        # Kirim banner palsu untuk tetap terlihat seperti server SSH
        client_sock.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n")
        client_sock.settimeout(10)

        # Loop ini sekarang hanya untuk menjaga koneksi tetap terbuka sesaat
        # dan merespon jika penyerang mengirim data
        while True:
            data = client_sock.recv(1024)
            if not data:
                break
            # Jika ada data yang dikirim, balas dengan pesan error
            client_sock.sendall(b"Permission denied, please try again.\r\n")
            
    except Exception as ex:
        # Kita bisa abaikan beberapa error umum seperti 'Connection reset by peer'
        if "Connection reset by peer" not in str(ex):
            logging.warning(f"[HONEYPOT] Exception with {ip}: {ex}")
    finally:
        client_sock.close()

        
def start_honeypot():
    """Memulai server honeypot TCP dalam sebuah thread."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', config.HONEYPOT_PORT))
        server.listen(5)
        logging.info(f"Honeypot listening on TCP port {config.HONEYPOT_PORT}")
    except Exception as e:
        logging.critical(f"Gagal memulai honeypot: {e}")
        return

    while True:
        try:
            client_sock, client_addr = server.accept()
            handler_thread = threading.Thread(target=_honeypot_handler, args=(client_sock, client_addr), daemon=True)
            handler_thread.start()
        except Exception as e:
            logging.error(f"[HONEYPOT] Error accepting new connection: {e}")
            time.sleep(1)
