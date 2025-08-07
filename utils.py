# utils.py
# Modul untuk fungsi utilitas umum.

import socket

def is_valid_ip(ip):
    """Memeriksa apakah string adalah alamat IP v4 yang valid."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False