"""
Network Error Detection and LAN Performance Monitoring System
-------------------------------------------------------------
Data Link Layer demo: Parity Check, Checksum (16-bit Internet checksum)
and CRC (CRC-8 for the technique demo, CRC-32 for LAN frames), with
error injection, Stop-and-Wait ARQ retransmission and a performance report.

Run:  python network_error_detection.py            (default message)
      python network_error_detection.py "my text"  (custom message)
"""
import random
import sys

random.seed(7)          # fixed seed so every run gives the same output

CRC8_GEN = 0b100000111                 # x^8 + x^2 + x + 1
CRC32_GEN = 0x104C11DB7                # Ethernet CRC-32 polynomial


# ---------------- helper: bit utilities ----------------
def to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def from_bits(bits: str) -> bytes:
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def flip(bits: str, positions) -> str:
    b = list(bits)
    for p in positions:
        b[p] = "1" if b[p] == "0" else "0"
    return "".join(b)


# ---------------- 1. Parity Check (even parity per byte) ----------------
def parity_generate(data: bytes) -> list:
    return [bin(byte).count("1") % 2 for byte in data]


def parity_check(data: bytes, parity_bits: list) -> bool:
    return parity_generate(data) == parity_bits


# ---------------- 2. Checksum (16-bit one's complement) ----------------
def _ones_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"                                  # pad to 16-bit words
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)         # end-around carry
    return total


def checksum_generate(data: bytes) -> int:
    return ~_ones_sum(data) & 0xFFFF


def checksum_check(data: bytes, checksum: int) -> bool:
    total = _ones_sum(data) + checksum
    total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


# ---------------- 3. CRC (modulo-2 division) ----------------
def crc_remainder(value: int, nbits: int, gen: int) -> int:
    r = gen.bit_length() - 1                              # degree of generator
    value <<= r                                           # append r zeros
    for i in range(nbits + r - 1, r - 1, -1):
        if value >> i & 1:
            value ^= gen << (i - r)
    return value


def crc_generate(data: bytes, gen: int = CRC8_GEN) -> int:
    return crc_remainder(int.from_bytes(data, "big"), len(data) * 8, gen)


def crc_check(data: bytes, crc: int, gen: int = CRC8_GEN) -> bool:
    r = gen.bit_length() - 1
    codeword = (int.from_bytes(data, "big") << r) | crc
    rem = codeword
    for i in range(len(data) * 8 + r - 1, r - 1, -1):
        if rem >> i & 1:
            rem ^= gen << (i - r)
    return rem == 0


# ---------------- Sender / Receiver devices ----------------
class Sender:
    def __init__(self, name):
        self.name = name

    def prepare(self, data: bytes) -> dict:
        return {"data": data,
                "parity": parity_generate(data),
                "checksum": checksum_generate(data),
                "crc": crc_generate(data)}


class Receiver:
    def __init__(self, name):
        self.name = name

    def verify(self, pkt: dict) -> dict:
        d = pkt["data"]
        return {"Parity": parity_check(d, pkt["parity"]),
                "Checksum": checksum_check(d, pkt["checksum"]),
                "CRC": crc_check(d, pkt["crc"])}


# ---------------- Error injection ----------------
def inject(data: bytes, kind: str) -> tuple:
    bits = to_bits(data)
    n = len(bits)
    if kind == "none":
        return data, "no error"
    if kind == "single":
        p = random.randrange(n)
        return from_bits(flip(bits, [p])), f"1 bit flipped at position {p}"
    if kind == "double":                      # 2 bits inside the same byte
        byte = random.randrange(len(data))
        a, b = random.sample(range(8), 2)
        pos = [byte * 8 + a, byte * 8 + b]
        return from_bits(flip(bits, pos)), f"2 bits flipped in byte {byte} {pos}"
    if kind == "burst":                       # 8-bit burst (first & last flipped)
        start = random.randrange(n - 8)
        pos = [start] + [i for i in range(start + 1, start + 7)
                         if random.random() < 0.5] + [start + 7]
        return from_bits(flip(bits, pos)), f"burst of length 8 from bit {start}"
    if kind == "swap":                        # swap first two 16-bit words
        d = bytearray(data)
        d[0:2], d[2:4] = data[2:4], data[0:2]
        return bytes(d), "16-bit words 0 and 1 swapped"
    raise ValueError(kind)


# ---------------- Part A: technique demo ----------------
def technique_demo(message: str):
    data = message.encode()
    tx, rx = Sender("PC-A"), Receiver("PC-B")
    pkt = tx.prepare(data)

    print("=" * 66)
    print(" SENDER DEVICE :", tx.name, "   RECEIVER DEVICE :", rx.name)
    print("=" * 66)
    print(f"Input Data        : '{message}'  ({len(data)} bytes)")
    print(f"Data bits         : {to_bits(data)[:48]}...")
    print(f"Parity bits (even): {''.join(map(str, pkt['parity']))}")
    print(f"Checksum (16-bit) : 0x{pkt['checksum']:04X}")
    print(f"CRC-8 remainder   : {pkt['crc']:08b} (gen 100000111)")

    print("\n%-8s %-36s %-7s %-8s %-5s %s" %
          ("Case", "Injected error", "Parity", "Checksum", "CRC", "Status"))
    print("-" * 82)
    for kind in ["none", "single", "double", "burst", "swap"]:
        bad, desc = inject(data, kind)
        res = rx.verify({**pkt, "data": bad})
        detected = not all(res.values())
        status = "ACCEPTED" if not detected else "REJECTED (NAK)"
        mark = lambda ok: "OK" if ok else "ERROR"
        print("%-8s %-36s %-7s %-8s %-5s %s" %
              (kind, desc, mark(res["Parity"]), mark(res["Checksum"]),
               mark(res["CRC"]), status))


# ---------------- Part B: detection rate (Monte Carlo) ----------------
def detection_rates(trials=2000):
    print("\n" + "=" * 66)
    print(f" ERROR DETECTION RATE  ({trials} random trials per error type)")
    print("=" * 66)
    print("%-10s %10s %10s %10s" % ("Error", "Parity", "Checksum", "CRC-8"))
    rx = Receiver("PC-B")
    for kind in ["single", "double", "burst", "swap"]:
        hits = {"Parity": 0, "Checksum": 0, "CRC": 0}
        real = 0
        for _ in range(trials):
            data = bytes(random.randrange(65, 91) for _ in range(16))
            pkt = Sender("PC-A").prepare(data)
            bad, _ = inject(data, kind)
            if bad == data:
                continue
            real += 1
            for k, ok in rx.verify({**pkt, "data": bad}).items():
                hits[k] += not ok
        print("%-10s %9.1f%% %9.1f%% %9.1f%%" %
              (kind, *(100 * hits[k] / real for k in hits)))


# ---------------- Part C: LAN transmission + performance ----------------
class LANFrame:
    """Simplified Ethernet frame: dst MAC | src MAC | length | payload | CRC-32."""
    def __init__(self, seq, dst, src, payload: bytes):
        self.seq = seq
        header = bytes.fromhex(dst.replace(":", "")) + \
            bytes.fromhex(src.replace(":", "")) + len(payload).to_bytes(2, "big")
        self.body = header + payload
        self.fcs = crc_generate(self.body, CRC32_GEN)
        self.nbits = len(self.body) * 8 + 32


def channel(frame: LANFrame, ber: float) -> tuple:
    bits = to_bits(frame.body) + f"{frame.fcs:032b}"
    pos = [i for i in range(len(bits)) if random.random() < ber]
    bits = flip(bits, pos)
    return from_bits(bits[:-32]), int(bits[-32:], 2), len(pos)


def lan_transfer(message: bytes, ber: float, bandwidth=10e6, prop=5e-6,
                 frame_size=46, max_retries=5, verbose=False):
    src, dst = "AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"
    chunks = [message[i:i + frame_size] for i in range(0, len(message), frame_size)]
    st = dict(frames=len(chunks), sent=0, delivered=0, failed=0, retx=0,
              detected=0, undetected=0, bits=0, time=0.0, payload_bits=0)
    ack_time = 64 * 8 / bandwidth
    for seq, chunk in enumerate(chunks):
        frame = LANFrame(seq, dst, src, chunk)
        for attempt in range(max_retries + 1):
            st["sent"] += 1
            st["bits"] += frame.nbits
            st["time"] += frame.nbits / bandwidth + 2 * prop + ack_time
            body, fcs, nerr = channel(frame, ber)
            ok = crc_check(body, fcs, CRC32_GEN)
            if ok:
                st["delivered"] += 1
                st["payload_bits"] += len(chunk) * 8
                if body != frame.body:
                    st["undetected"] += 1
                if verbose:
                    print(f"  Frame {seq:02d} try {attempt + 1}: "
                          f"{nerr} bit errors -> CRC OK    -> ACK  (delivered)")
                break
            st["detected"] += 1
            if verbose:
                act = "retransmit" if attempt < max_retries else "give up"
                print(f"  Frame {seq:02d} try {attempt + 1}: "
                      f"{nerr} bit errors -> CRC FAIL  -> NAK  ({act})")
            if attempt < max_retries:
                st["retx"] += 1
        else:
            st["failed"] += 1
            if verbose:
                print(f"  Frame {seq:02d}: dropped after {max_retries} retries")
    return st


def report(st, ber):
    thr = st["payload_bits"] / st["time"] / 1e6
    print(f"  BER                    : {ber}")
    print(f"  Frames to send         : {st['frames']}")
    print(f"  Transmissions (total)  : {st['sent']}")
    print(f"  Retransmissions        : {st['retx']}")
    print(f"  Errors detected (CRC)  : {st['detected']}")
    print(f"  Undetected errors      : {st['undetected']}")
    print(f"  Frames delivered       : {st['delivered']}")
    print(f"  Frames failed          : {st['failed']}")
    print(f"  Frame error rate       : {st['detected'] / st['sent'] * 100:.2f}%")
    print(f"  Efficiency             : {st['frames'] / st['sent'] * 100:.2f}%")
    print(f"  Total time (simulated) : {st['time'] * 1e3:.3f} ms")
    print(f"  Effective throughput   : {thr:.3f} Mbps")
    status = "SUCCESSFUL" if st["failed"] == 0 else "UNSUCCESSFUL"
    print(f"  TRANSMISSION STATUS    : {status}")


def lan_demo(message: str):
    msg = (message + " ") * 12
    data = msg.encode()
    print("\n" + "=" * 66)
    print(" LAN TRANSMISSION  (10 Mbps Ethernet, CRC-32, Stop-and-Wait ARQ)")
    print("=" * 66)
    for title, ber, retries in [("Run 1: clean channel", 0.0, 5),
                                ("Run 2: noisy channel", 0.002, 5),
                                ("Run 3: very noisy channel, 2 retries", 0.02, 2)]:
        print(f"\n{title}")
        st = lan_transfer(data, ber, max_retries=retries, verbose=True)
        print("  --- Performance Report ---")
        report(st, ber)

    print("\n" + "=" * 66)
    print(" PERFORMANCE vs BIT ERROR RATE  (300 frames each, 5 retries)")
    print("=" * 66)
    print("%-8s %6s %6s %8s %8s %7s %11s" %
          ("BER", "Sent", "ReTx", "Deliv.", "Failed", "Eff.%", "Thr (Mbps)"))
    big = bytes(random.randrange(256) for _ in range(46 * 300))
    for ber in [0, 1e-4, 1e-3, 3e-3, 1e-2]:
        st = lan_transfer(big, ber)
        thr = st["payload_bits"] / st["time"] / 1e6
        print("%-8g %6d %6d %8d %8d %7.1f %11.3f" %
              (ber, st["sent"], st["retx"], st["delivered"], st["failed"],
               st["frames"] / st["sent"] * 100, thr))


if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else "HELLO LAN"
    technique_demo(text)
    detection_rates()
    lan_demo(text)
