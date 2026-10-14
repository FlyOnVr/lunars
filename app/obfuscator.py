from __future__ import annotations

import hashlib
import struct


MASTER_SECRET = b"astre_payload_master_v1_change_me_per_release"
MAGIC = b"AEN1"
LAYERS = 10


def _layer_key(idx: int) -> bytes:
    h = hashlib.sha256()
    h.update(b"AENC_LAYER_")
    h.update(str(idx).encode("ascii"))
    h.update(b"_")
    h.update(MASTER_SECRET)
    return h.digest()


def _rotate_byte(b: int, bits: int) -> int:
    bits = bits & 7
    return ((b >> bits) | (b << (8 - bits))) & 0xFF


def encrypt_payload(data: bytes, layers: int = LAYERS) -> bytes:
    out = bytearray(data)
    n = len(out)
    for i in range(layers):
        k = _layer_key(i)
        klen = len(k)
        for j in range(n):
            out[j] ^= k[j % klen]
        rot = ((i * 3) + 1) % 8
        if rot:
            for j in range(n):
                out[j] = _rotate_byte(out[j], rot)
    header = MAGIC + bytes([layers])
    return header + bytes(out)


def decrypt_payload(blob: bytes) -> bytes:
    if len(blob) < 5 or blob[:4] != MAGIC:
        return blob
    layers = blob[4]
    out = bytearray(blob[5:])
    n = len(out)
    for i in range(layers - 1, -1, -1):
        rot = ((i * 3) + 1) % 8
        if rot:
            inv = (8 - rot) & 7
            for j in range(n):
                out[j] = _rotate_byte(out[j], inv)
        k = _layer_key(i)
        klen = len(k)
        for j in range(n):
            out[j] ^= k[j % klen]
    return bytes(out)


def _read_u16(buf, off): return struct.unpack_from("<H", buf, off)[0]
def _read_u32(buf, off): return struct.unpack_from("<I", buf, off)[0]
def _write_u32(buf, off, v): struct.pack_into("<I", buf, off, v)


def _zero(buf, off, n):
    for i in range(n):
        if 0 <= off + i < len(buf):
            buf[off + i] = 0


def _rva_to_offset(buf, rva, sections):
    for sec in sections:
        va, vs, raw_ptr, raw_sz = sec
        if va <= rva < va + max(vs, raw_sz):
            return raw_ptr + (rva - va)
    return None


def scrub_dotnet_dll(data: bytes) -> bytes:
    if len(data) < 0x200:
        return data
    try:
        buf = bytearray(data)
        if buf[0] != 0x4D or buf[1] != 0x5A:
            return data
        pe_off = _read_u32(buf, 0x3C)
        if pe_off <= 0 or pe_off + 4 > len(buf):
            return data
        if buf[pe_off:pe_off + 4] != b"PE\x00\x00":
            return data

        file_hdr = pe_off + 4
        nsections = _read_u16(buf, file_hdr + 2)
        _write_u32(buf, file_hdr + 4, 0)
        opt_sz = _read_u16(buf, file_hdr + 16)
        opt_hdr = file_hdr + 20
        magic = _read_u16(buf, opt_hdr)
        is64 = (magic == 0x20B)
        data_dir_off = opt_hdr + (112 if is64 else 96)
        num_dirs = _read_u32(buf, opt_hdr + (108 if is64 else 92))

        sec_off = opt_hdr + opt_sz
        sections = []
        for i in range(nsections):
            base = sec_off + i * 40
            if base + 40 > len(buf):
                break
            vs      = _read_u32(buf, base + 8)
            va      = _read_u32(buf, base + 12)
            raw_sz  = _read_u32(buf, base + 16)
            raw_ptr = _read_u32(buf, base + 20)
            sections.append((va, vs, raw_ptr, raw_sz))

        if num_dirs > 6:
            dbg_dir_off = data_dir_off + 6 * 8
            dbg_rva  = _read_u32(buf, dbg_dir_off)
            dbg_size = _read_u32(buf, dbg_dir_off + 4)
            if dbg_rva and dbg_size:
                phys = _rva_to_offset(buf, dbg_rva, sections)
                if phys is not None:
                    for i in range(dbg_size // 28):
                        entry = phys + i * 28
                        data_rva  = _read_u32(buf, entry + 20)
                        data_size = _read_u32(buf, entry + 16)
                        data_phys = _read_u32(buf, entry + 24)
                        if data_phys and data_size:
                            _zero(buf, data_phys, data_size)
                        if data_rva and data_size:
                            p = _rva_to_offset(buf, data_rva, sections)
                            if p is not None:
                                _zero(buf, p, data_size)
                    _zero(buf, phys, dbg_size)
                _write_u32(buf, dbg_dir_off, 0)
                _write_u32(buf, dbg_dir_off + 4, 0)

        return bytes(buf)
    except Exception:
        return data
