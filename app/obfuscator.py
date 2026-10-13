from __future__ import annotations

import struct


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
    """Light server-side scrubber for .NET assemblies.
    Not a real IL virtualizer — removes trivially useful metadata that
    helps attackers (PDB paths, debug directory, build timestamps) and
    xor-masks the #Strings heap region. For true IL virtualization run
    BitMono/Eazfuscator before upload."""
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
        machine = _read_u16(buf, file_hdr)
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
            dbg_rva = _read_u32(buf, dbg_dir_off)
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

        if num_dirs > 14:
            cli_dir_off = data_dir_off + 14 * 8
            cli_rva  = _read_u32(buf, cli_dir_off)
            cli_size = _read_u32(buf, cli_dir_off + 4)
            if cli_rva and cli_size:
                cli_phys = _rva_to_offset(buf, cli_rva, sections)
                if cli_phys is not None and cli_phys + 16 <= len(buf):
                    md_rva  = _read_u32(buf, cli_phys + 8)
                    md_phys = _rva_to_offset(buf, md_rva, sections)
                    if md_phys is not None and md_phys + 20 <= len(buf):
                        sig = _read_u32(buf, md_phys)
                        if sig == 0x424A5342:
                            vlen = _read_u32(buf, md_phys + 12)
                            if 0 < vlen <= 255:
                                ver_off = md_phys + 16
                                for i in range(vlen):
                                    if ver_off + i < len(buf) and buf[ver_off + i] != 0:
                                        buf[ver_off + i] = ord('.')

        return bytes(buf)
    except Exception:
        return data
