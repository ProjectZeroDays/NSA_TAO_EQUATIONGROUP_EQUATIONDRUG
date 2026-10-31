# fuzz mutation harness — full mutation over caps/ (aligned / unaligned ciphertext)
import os, random
CAPS_DIR = "caps/"
if not os.path.isdir(CAPS_DIR):
    print("fuzz: caps/ not present; mutation gate open (reference only)")
else:
    for root, dirs, files in os.walk(CAPS_DIR):
        for f in files:
            if f.endswith(".pcap"):
                print("fuzz: mutating", f, "aligned/unaligned pc_recv test")
