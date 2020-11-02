"""
Pure python git database explorer
Inspired from: https://github.com/benhoyt/pygit/blob/master/pygit.py
"""

from collections import namedtuple
from os import path, makedirs
import hashlib
import re
import zlib

OBECT_TYPES = {"commit": 1, "tree": 2, "blob": 3}

Object = namedtuple("Object", "type data")
Tree = namedtuple("Tree", "type mode path sha1")


class GitException(Exception):
    pass


def get_object_file_path(sha1: str) -> str:
    return path.join(".git", "objects", sha1[:2], sha1[2:])


def read_bytes_from_file(file_path: str) -> bytes:
    """
    Read contents of file at given path as bytes.
    """
    with open(file_path, "rb") as f:
        return f.read()


def write_bytes_to_file(file_path: str, data: bytes):
    """
    Write data bytes to file at given path.
    """
    makedirs(path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(data)


def validate_obj_type(obj_type: str):
    if obj_type not in OBECT_TYPES:
        raise GitException(
            f"validate_obj_type: '{obj_type}' must be one of {OBECT_TYPES.values()}"
        )


def pack_object(obj: Object) -> (str, bytes):
    """
    Return a tuple of (sha1(type + len + data), zlib(type + len + data))
    """
    validate_obj_type(obj.type)
    data_w_header = b"\x00".join([f"{obj.data} {obj.type}", obj.data])
    sha1 = hashlib.sha1(data_w_header).hexdigest()
    gzipped_data = zlib.compress(data_w_header)
    return sha1, gzipped_data


def unpack_object(gzipped_data: bytes) -> Object:
    data_w_header = zlib.decompress(gzipped_data)
    header, data = data_w_header.split(b"\x00", 1)
    obj_type, size_str = header.decode().split(" ")
    size = int(size_str)

    if size != len(data):
        raise GitException(f"read_object: expected size {size}, got {len(data)} bytes")

    return Object(obj_type, data)


def write_object(obj: Object):
    """
    Write Object to .git/objects dir
    """
    sha1, gzipped_data = pack_object(obj)
    file_path = get_object_file_path(sha1)
    if not path.exists(file_path):
        write_bytes_to_file(file_path, gzipped_data)


def read_object(sha1) -> Object:
    """
    Read Object with given sha1
    """
    file_path = get_object_file_path(sha1)
    return unpack_object(read_bytes_from_file(file_path))


def unpack_tree(data: bytes) -> Tree:
    """
    Read Tree object from data
    """
    matches = re.findall(br"(\d{3})(\d{3}) (.+?)\0(.{20})", data, re.MULTILINE)
    print(matches)
    return [Tree(match[0], match[1], match[2], match[3].hex()) for match in matches]


# Test Code #
if __name__ == "__main__":
    obj = read_object("9dff3e45663d61c8b2c0bff7fcfe4b2688649e35")
    print(obj)
    print(unpack_tree(obj.data))
