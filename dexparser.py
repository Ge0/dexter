import hashlib
import struct
import sys
import zlib

MAGIC_WORD = b"dex\n035\0"


class DexParserError(Exception):
    """Exception base class for every Dex Parser related error."""


class NotADexFile(DexParserError):
    """Thrown when the parsed dex file has not the magic word."""


class ChecksumError(DexParserError):
    """Thrown when the dex file's checksum is invalid."""


class SHA1HashError(DexParserError):
    """Thrown when the dex file's SHA1 hash is invalid."""


class ULEB128ParseError(DexParserError):
    """Thrown when there is a parser issue of a ULEB128 encoded number."""


def get_uleb128(data):
    value = 0
    for i in range(5):
        tmp = data[i] & 0x7f
        value = tmp << (i * 7) | value

        if (data[i] & 0x80) != 0x80:
            break

    if i == 4 and (tmp & 0xf0) != 0:
        raise ULEB128ParseError()

    return i + 1, value


def fill_string_ids(content, string_ids_off, string_ids_size):
    if not string_ids_size:
        return
    string_ids = list()
    offset, *_ = struct.unpack('<L', content[string_ids_off:string_ids_off+4])
    start = offset
    for i in range(1, string_ids_size):
        offset, *_ = struct.unpack_from(
            'I',
            content,
            string_ids_off + i * 4
        )
        skip, length = get_uleb128(content[start:start + 5])
        string_ids.append(content[start+skip:offset-1])
        start = offset
    for i in range(start, len(content)):
        if content[i] == 0:
            string_ids.append(content[start+1:i])
            break
    return string_ids

def check_dex_file(dex_file):
    content = dex_file.read()
    magic = content[:8]
    if magic != MAGIC_WORD:
        raise NotADexFile()

    checksum = content[8:8+4]
    sha1 = content[12:12+20]

    (
        file_size,
        header_size,
        endian_tag,
        link_size,
        link_off,
        map_off,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        proto_ids_size,
        proto_ids_off,
        field_ids_size,
        field_ids_off,
        method_ids_size,
        method_ids_off,
        class_defs_size,
        class_defs_off,
        data_size,
        data_off,
    ) = struct.unpack(f"<{'L'*20}", content[32:112])

    adler32_checksum = zlib.adler32(sha1 + content[32:])
    if adler32_checksum != struct.unpack("<L", checksum)[0]:
        raise ChecksumError()

    print(f"[+] Adler32 Checksum: {hex(adler32_checksum)}")

    hasher = hashlib.sha1()
    hasher.update(content[32:])

    if hasher.digest() != sha1:
        raise SHA1HashError()

    print(f"[+] SHA1: {sha1.hex()}")
    print(f"[+] File size: {file_size} byte(s)")
    print(f"[+] Header size: {header_size} byte(s)")
    print(f"[+] Endian tag: {hex(endian_tag)}")
    print(f"[+] Link size: {link_size} bytes.")
    print(f"[+] Link offset: {hex(link_off)}")
    print(f"[+] Map offset: {hex(map_off)}")
    print(f"[+] String IDs size: {string_ids_size}")
    print(f"[+] String IDs offset: {hex(string_ids_off)}")
    print(f"[+] Type IDs size: {type_ids_size}")
    print(f"[+] Type IDs offset: {hex(type_ids_off)}")
    print(f"[+] Proto IDs size: {proto_ids_size}")
    print(f"[+] Proto IDs offset: {hex(proto_ids_off)}")
    print(f"[+] Field IDs size: {field_ids_size}")
    print(f"[+] Field IDs offset: {hex(field_ids_off)}")
    print(f"[+] Method IDs size: {method_ids_size}")
    print(f"[+] Method IDs offset: {hex(method_ids_off)}")
    print(f"[+] Class defs size: {class_defs_size}")
    print(f"[+] Class defs offset: {hex(class_defs_off)}")
    print(f"[+] Data size: {data_size}")
    print(f"[+] Data offset: {hex(data_off)}")

    fill_string_ids(content, string_ids_off, string_ids_size)


def main(argv):
    """Parse a .dex file."""
    if len(argv) < 2:
        print(f"Usage: {sys.argv[0]} <dex file>")
        raise SystemExit(-1)

    dex_filename, *_ = argv[1:]
    with open(dex_filename, "rb") as dex_file:
        check_dex_file(dex_file)


if __name__ == "__main__":
    main(sys.argv)
