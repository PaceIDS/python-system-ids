# response.py
# Modul untuk menangani semua aksi respon, terutama interaksi dengan iptables.

import logging
import subprocess
import time
# import socket # Tidak diperlukan jika is_valid_ip sudah dipindahkan sepenuhnya

# Impor dari modul lain
import config
import state
# from telegram_bot import send_telegram_message # HAPUS BARIS INI!

# Fungsi is_valid_ip sudah dipindahkan ke utils.py

def check_iptables_rule_exists(ip, action="DROP", chain="INPUT"):
    """Memeriksa apakah aturan iptables untuk IP tertentu sudah ada."""
    cmd = ["sudo", "iptables", "-C", chain, "-s", ip, "-j", action]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.returncode == 0
    except Exception as e:
        logging.error(f"Error checking iptables rule for {ip}: {e}")
        return False

def block_ip_iptables(ip):
    """Menerapkan aturan DROP di iptables untuk sebuah IP."""
    if ip in state.blocked_ips or ip in state.quarantine_ips:
        logging.info(f"[IPTABLES] IP {ip} sudah dalam status blokir/karantina.")
        return True

    cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            logging.info(f"[IPTABLES] IP {ip} berhasil diblokir.")
            # Ganti send_telegram_message dengan menambah ke antrean
            state.telegram_send_queue.put(f"<b>Info</b>: IP <code>{ip}</code> berhasil diblokir.") # Tambahkan notifikasi ke Telegram jika sukses blokir
            return True
        else:
            logging.error(f"[IPTABLES] Gagal memblokir IP {ip}. Error: {result.stderr.strip()}")
            state.telegram_send_queue.put(f"<b>Error</b>: Gagal blokir IP {ip}. Periksa log server.") # Tambah ke antrean
            return False
    except Exception as e:
        logging.error(f"[IPTABLES] Exception saat memblokir IP {ip}: {e}")
        state.telegram_send_queue.put(f"<b>Error</b>: Terjadi kesalahan saat blokir IP {ip}.") # Tambah ke antrean
        return False

def unblock_ip_iptables(ip):
    """Menghapus aturan DROP di iptables untuk sebuah IP."""
    cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        # Loop untuk menghapus semua aturan yang cocok, karena -I bisa membuat duplikat
        while check_iptables_rule_exists(ip):
             subprocess.run(cmd, capture_output=True, text=True, check=False)
        
        logging.info(f"[IPTABLES] Semua aturan blokir untuk IP {ip} berhasil dihapus.")
        
        # --- BLOK TAMBAHAN: Atur Masa Tenang (Grace Period) ---
        # Berikan masa tenang 15 detik untuk mencegah re-blocking instan dari sisa paket.
        cooldown_duration = 60  # detik
        state.unblock_cooldown[ip] = time.time() + cooldown_duration
        logging.info(f"[GRACE_PERIOD] IP {ip} diberi masa tenang selama {cooldown_duration} detik.")
        # --- AKHIR BLOK TAMBAHAN ---

        # Reset state deteksi untuk IP ini
        if ip in state.connection_attempts: del state.connection_attempts[ip]
        if ip in state.packet_counts: del state.packet_counts[ip]
        if ip in state.honeypot_auth_attempts: del state.honeypot_auth_attempts[ip]
        if ip in state.dos_notification_cooldown: del state.dos_notification_cooldown[ip]
        
        # Ganti send_telegram_message dengan menambah ke antrean
        state.telegram_send_queue.put(f"<b>Info</b>: IP <code>{ip}</code> berhasil dibuka blokirnya.")
        return True
    except Exception as e:
        logging.error(f"[IPTABLES] Exception saat membuka blokir IP {ip}: {e}")
        state.telegram_send_queue.put(f"<b>Error</b>: Terjadi kesalahan saat unblock IP {ip}.")
        return False

def enforce_quarantine_expiry():
    """Worker untuk memonitor dan membuka blokir IP yang masa karantinanya habis."""
    while True:
        now = time.time()
        to_unblock = [ip for ip, unblock_stamp in state.quarantine_ips.items() if now >= unblock_stamp]
        
        for ip in to_unblock:
            logging.info(f"[QUARANTINE_EXPIRY] Waktu karantina untuk IP {ip} habis.")
            if unblock_ip_iptables(ip):
                del state.quarantine_ips[ip]
                state.telegram_send_queue.put(f"<b>Info</b>: IP <code>{ip}</code> dibuka karantinanya.") # Tambah ke antrean
            else:
                logging.warning(f"[QUARANTINE_EXPIRY] Gagal membuka blokir IP {ip} secara otomatis.")
        
        time.sleep(5)