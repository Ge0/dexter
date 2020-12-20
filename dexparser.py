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


def check_dex_file(dex_file):
    magic = dex_file.read(8)
    if magic != MAGIC_WORD:
        raise NotADexFile()

    checksum = dex_file.read(4)
    sha1 = dex_file.read(20)

    content = dex_file.read()

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
    ) = struct.unpack(f"<{'L'*20}", content[: 4 * 20])

    adler32_checksum = zlib.adler32(sha1 + content)
    if adler32_checksum != struct.unpack("<L", checksum)[0]:
        raise ChecksumError()

    print(f"[+] Adler32 Checksum: {hex(adler32_checksum)}")

    hasher = hashlib.sha1()
    hasher.update(content)

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
