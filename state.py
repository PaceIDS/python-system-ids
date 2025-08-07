# state.py
# File ini menampung semua variabel state global yang digunakan oleh berbagai modul.

from queue import Queue

# === State Deteksi ===
# Menyimpan data sementara untuk analisis serangan
connection_attempts = {}    # {IP: [(port, timestamp), ...]} untuk port scan
packet_counts = {}          # {IP: [timestamp, ...]} untuk DoS
honeypot_auth_attempts = {} # {IP: count} untuk brute-force honeypot


# Menggantikan packet_counts yang lama
syn_count_smart = {}       # {IP: count} untuk menghitung paket SYN
fin_rst_count_smart = {}   # {IP: count} untuk menghitung paket FIN/RST

# === State Respon ===
# Menyimpan daftar IP yang sedang dalam status blokir atau karantina
blocked_ips = set()            # IP yang diblokir permanen
quarantine_ips = {}            # {IP: unblock_time_timestamp} untuk karantina sementara
dos_notification_cooldown = {} # {IP: last_notify_time} untuk mencegah spam notifikasi DoS

# --- BARIS TAMBAHAN ---
# Kamus untuk menyimpan IP yang diberi masa tenang (grace period) setelah di-unblock
unblock_cooldown = {}          # Format: {IP: cooldown_end_timestamp}

# === State Komunikasi ===
# Antrean untuk komunikasi antar thread
detected_events_queue = Queue()  # Antrean untuk event serangan yang terdeteksi
telegram_send_queue = Queue()    # Antrean untuk pesan keluar ke Telegram

# Variabel untuk melacak update dari Telegram
telegram_offset = 0

# --- TAMBAHAN: State untuk Deteksi Canggih ---
# Untuk deteksi global
global_syn_packets = []
global_dos_alert_cooldown = 0

# Untuk deteksi jalur cepat per-IP
fast_path_syn_timestamps = {}