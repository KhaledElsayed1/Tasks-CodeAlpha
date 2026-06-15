import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, Raw # type: ignore
from datetime import datetime
import threading
import queue

# =========================
# STATE
# =========================
stop_sniff = False
packet_count = 0
packet_limit = 300

data_store = []
q = queue.Queue()

sort_reverse = {}

# =========================
# GUI
# =========================
root = tk.Tk()
root.title("Stable Network Sniffer PRO")
root.geometry("1100x650")

# =========================
# SEARCH
# =========================
search_var = tk.StringVar()

search_entry = tk.Entry(root, textvariable=search_var)
search_entry.insert(0, "Search...")
search_entry.pack(fill=tk.X, padx=5, pady=5)

# =========================
# TABLE
# =========================
columns = ("time", "src", "dst", "proto", "length", "payload")

tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col, command=lambda c=col: sort_by(c))

tree.pack(fill=tk.BOTH, expand=True)

# =========================
# SORT
# =========================
def sort_by(col):
    global data_store

    rev = sort_reverse.get(col, False)
    sort_reverse[col] = not rev

    idx = columns.index(col)

    data_store.sort(key=lambda x: x[idx], reverse=rev)
    refresh()

# =========================
# REFRESH UI (SAFE)
# =========================
def refresh():
    tree.delete(*tree.get_children())

    search = search_var.get().lower()

    for row in data_store:
        if search and search != "search..." and search not in str(row).lower():
            continue
        tree.insert("", "end", values=row)

# =========================
# PACKET PROCESS
# =========================
def process_packet(packet):
    global packet_count

    if packet_count >= packet_limit:
        return

    if IP not in packet:
        return

    proto = "OTHER"
    payload = ""
    length = len(packet)

    if TCP in packet:
        proto = "TCP"
    elif UDP in packet:
        proto = "UDP"

    src = packet[IP].src
    dst = packet[IP].dst
    time = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(Raw):
        payload = str(packet[Raw].load)[:50]

    row = (time, src, dst, proto, length, payload)

    q.put(row)
    packet_count += 1

# =========================
# SNIFFER THREAD
# =========================
def sniff_packets():
    sniff(prn=process_packet, store=False)

def start():
    global stop_sniff, packet_count
    stop_sniff = False
    packet_count = 0
    threading.Thread(target=sniff_packets, daemon=True).start()

def stop():
    global stop_sniff
    stop_sniff = True

def clear():
    global data_store
    data_store = []
    tree.delete(*tree.get_children())

# =========================
# UPDATE LOOP (IMPORTANT)
# =========================
def update_gui():
    while not q.empty():
        data_store.append(q.get())

    refresh()
    root.after(500, update_gui)

# =========================
# BUTTONS
# =========================
btn = tk.Frame(root)
btn.pack()

tk.Button(btn, text="Start", bg="green", fg="white", command=start).pack(side=tk.LEFT, padx=5)
tk.Button(btn, text="Stop", bg="red", fg="white", command=stop).pack(side=tk.LEFT, padx=5)
tk.Button(btn, text="Clear", bg="gray", fg="white", command=clear).pack(side=tk.LEFT, padx=5)

# =========================
# SEARCH LIVE
# =========================
search_var.trace_add("write", lambda *args: refresh())

# =========================
# START LOOP
# =========================
update_gui()
root.mainloop()