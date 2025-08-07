# telegram_bot.py
# Modul untuk semua interaksi dengan Telegram Bot API.

import logging
import time
import requests
import json
import threading

# Impor dari modul lain
import config
import state
from logging_utils import log_telegram_activity, write_log_serangan
from response import block_ip_iptables, unblock_ip_iptables # Menghapus is_valid_ip di sini
from utils import is_valid_ip # Tambahkan baris ini untuk mengimpor dari modul utils yang baru

def send_telegram_message(text):
    """Menambahkan pesan ke antrean untuk dikirim oleh worker Telegram."""
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        logging.warning("[TELEGRAM] Token/Chat ID belum dikonfigurasi. Pesan tidak dikirim.")
        return
    state.telegram_send_queue.put(text)
    logging.info(f"[TELEGRAM_QUEUE] Pesan ditambahkan ke antrean: {text[:50]}...")

def _telegram_sender_worker():
    """Worker yang mengirim pesan dari antrean. JANGAN PANGGIL LANGSUNG."""
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    while True:
        text = state.telegram_send_queue.get()
        if text is None: break
        data = {"chat_id": config.TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
        try:
            r = requests.post(url, data=data, timeout=10)
            if r.status_code == 200:
                log_telegram_activity(text, direction="out")
                logging.info("[TELEGRAM_SENT] Pesan berhasil dikirim.")
            else:
                logging.warning(f"[TELEGRAM_FAIL] Gagal kirim pesan: {r.status_code} {r.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"[TELEGRAM_EXCEPTION] Terjadi exception saat kirim pesan: {e}")
        finally:
            state.telegram_send_queue.task_done()

def _handle_telegram_message(message):
    """Memproses satu pesan yang diterima dari Telegram."""
    chat_id = message["chat"]["id"]
    text = message.get("text", "").strip()
    user = message["from"].get("username", "unknown user")

    log_telegram_activity(f"Dari @{user} (Chat ID: {chat_id}): {text}", direction="in")

    if str(chat_id) != str(config.TELEGRAM_CHAT_ID):
        send_telegram_message(f"Maaf @{user}, Anda tidak memiliki izin.")
        return

    # Logika untuk setiap perintah
    if text.startswith("/block"):
        parts = text.split()
        if len(parts) == 2 and is_valid_ip(parts[1]):
            ip = parts[1]
            if block_ip_iptables(ip):
                state.blocked_ips.add(ip)
                if ip in state.quarantine_ips: del state.quarantine_ips[ip]
                send_telegram_message(f"IP <code>{ip}</code> berhasil diblokir permanen.")
                write_log_serangan({"type": "manual_block", "source_ip": ip, "action_by": user, "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        else:
            send_telegram_message("Format salah. Gunakan: <code>/block &lt;IP&gt;</code>")

    elif text.startswith("/karantina"):
        parts = text.split()
        if len(parts) == 3 and is_valid_ip(parts[1]) and parts[2].isdigit():
            ip, dur_menit = parts[1], int(parts[2])
            if block_ip_iptables(ip):
                state.quarantine_ips[ip] = time.time() + dur_menit * 60
                send_telegram_message(f"IP <code>{ip}</code> dikarantina selama {dur_menit} menit.")
                write_log_serangan({"type": "manual_quarantine", "source_ip": ip, "duration_minutes": dur_menit, "action_by": user, "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        else:
             send_telegram_message("Format salah. Gunakan: <code>/karantina &lt;IP&gt; &lt;durasi_menit&gt;</code>")

    elif text.startswith("/unblock"):
        parts = text.split()
        if len(parts) == 2 and is_valid_ip(parts[1]):
            ip = parts[1]
            if unblock_ip_iptables(ip):
                if ip in state.blocked_ips: state.blocked_ips.remove(ip)
                if ip in state.quarantine_ips: del state.quarantine_ips[ip]
                write_log_serangan({"type": "manual_unblock", "source_ip": ip, "action_by": user, "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        else:
            send_telegram_message("Format salah. Gunakan: <code>/unblock &lt;IP&gt;</code>")

    elif text == "/status":
        msg = "<b>Status IDS:</b>\n"
        msg += f"Blocked IPs ({len(state.blocked_ips)}): {', '.join(state.blocked_ips) or 'None'}\n"
        msg += "Quarantined IPs:\n"
        if state.quarantine_ips:
            for ip, unblock_time in state.quarantine_ips.items():
                remaining = int(unblock_time - time.time())
                msg += f"  - <code>{ip}</code> (sisa: {remaining // 60}m {remaining % 60}s)\n"
        else:
            msg += "  None\n"
        send_telegram_message(msg)

    elif text == "/help" or text == "/start":
        help_msg = ( "<b>Perintah Bot:</b>\n"
            "<code>/block &lt;IP&gt;</code>\n"
            "<code>/karantina &lt;IP&gt; &lt;menit&gt;</code>\n"
            "<code>/unblock &lt;IP&gt;</code>\n"
            "<code>/status</code>")
        send_telegram_message(help_msg)

def _poll_telegram_updates():
    """Worker yang mengambil update dari Telegram. JANGAN PANGGIL LANGSUNG."""
    endpoint = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/getUpdates"
    while True:
        try:
            params = {"timeout": 30, "offset": state.telegram_offset + 1}
            r = requests.get(endpoint, params=params, timeout=35)
            if r.status_code == 200 and r.json().get("ok"):
                for upd in r.json().get("result", []):
                    state.telegram_offset = upd["update_id"]
                    if "message" in upd and "text" in upd["message"]:
                        _handle_telegram_message(upd["message"])
            else:
                logging.warning(f"[TELEGRAM_POLL] Gagal fetch updates (HTTP {r.status_code})")
        except requests.exceptions.RequestException as e:
            logging.error(f"[TELEGRAM_POLL] Exception saat polling updates: {e}")
        time.sleep(1)

def start_telegram_bot():
    """Memulai semua thread yang berhubungan dengan Telegram."""
    threading.Thread(target=_telegram_sender_worker, daemon=True).start()
    threading.Thread(target=_poll_telegram_updates, daemon=True).start()
    logging.info("Telegram bot sender and poller threads started.")