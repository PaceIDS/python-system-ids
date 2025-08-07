# config.py
# File ini berisi semua variabel konfigurasi untuk sistem IDS.

# === Konfigurasi Telegram ===
TELEGRAM_BOT_TOKEN = "XXXXXXXXXXXXXXX" # Ganti dengan token bot Anda
TELEGRAM_CHAT_ID = "XXXXXXXXXXXXXXXXX" # Ganti dengan chat ID Anda (admin)

# === Konfigurasi File & Path ===
STATUS_FILE = "ip_status.json" # File untuk menyimpan status IP yang diblokir/karantina
LOG_FILE = "serangan_log.jsonl" # File log untuk semua serangan yang terdeteksi
TELEGRAM_LOG_FILE = "telegram_activity.log" # File log untuk aktivitas bot Telegram

# === Konfigurasi Jaringan ===
# IP yang Dikecualikan dari deteksi (misal: IP server, gateway, DNS)
EXCLUDED_IPS = ["127.0.0.1", "::1", "192.168.100.0/24"] # Ganti dengan IP server IDS Anda

# Port untuk Honeypot
HONEYPOT_PORT = 2222

# === Konfigurasi Thresholds Deteksi ===
# Port Scanning
PORT_SCAN_THRESHOLD = 25  # Jumlah port unik yang di-scan sebelum memicu alarm
SCAN_TIME_WINDOW = 20     # Dalam detik

# DoS (SYN Flood) - Konfigurasi lama, bisa dihapus atau diabaikan
DOS_PACKET_THRESHOLD = 100 
DOS_TIME_WINDOW = 10       



# --- TAMBAHKAN KONFIGURASI BARU UNTUK SIGNATURE CERDAS ---
# Deteksi SYN Flood Cerdas Berbasis Rasio
# Minimal jumlah SYN yang harus terdeteksi sebelum sistem mulai memeriksa rasionya.
# Ini untuk mencegah false positive pada koneksi normal yang pendek.
RATIO_MIN_SYN_COUNT = 100 

# --- TAMBAHAN: Konfigurasi untuk Deteksi Canggih ---
# Deteksi Banjir SYN Global (untuk IP acak)
GLOBAL_SYN_THRESHOLD = 500
GLOBAL_SYN_TIME_WINDOW = 5
GLOBAL_COOLDOWN = 120

# Deteksi Cepat (Fast-Path) untuk IP tunggal (termasuk palsu)
FAST_PATH_SYN_COUNT = 40
FAST_PATH_TIME_WINDOW = 3


# Ambang batas rasio. Contoh: 50.0 berarti serangan terdeteksi jika
# jumlah paket SYN 50x lebih banyak daripada paket FIN/RST.
RATIO_THRESHOLD = 50.0

# Brute Force (pada Honeypot)
BRUTE_FORCE_THRESHOLD = 2 # Jumlah percobaan koneksi gagal ke honeypot

# Cooldown Notifikasi (untuk mencegah spam)
DOS_COOLDOWN = 300 # Waktu tunggu (detik) sebelum mengirim notifikasi DoS lagi dari IP yang sama