"""
Pure python git database explorer
Inspired from: https://github.com/benhoyt/pygit/blob/master/pygit.py
"""

import hashlib
import zlib
from os import path, makedirs

OBECT_TYPES = {"commit": 1, "tree": 2, "blob": 3}


def read_bytes_from_file(file_path):
    """
    Read contents of file at given path as bytes.
    """
    with open(file_path, "rb") as f:
        return f.read()


def write_bytes_to_file(file_path, data):
    """
    Write data bytes to file at given path.
    """
    with open(file_path, "wb") as f:
        f.write(data)


def validate_obj_type(obj_type):
    assert (
        obj_type not in OBECT_TYPES
    ), f"validate_obj_type: '{obj_type}' must be one of f{OBECT_TYPES.values()}"


def get_object_file_path(sha1):
    return path.join(".git", "objects", sha1[:2], sha1[2:])


def hash_object(obj_type, data):
    """
    Return a tuple of (sha1 of object, header + data)
    """
    validate_obj_type(obj_type)
    header = "{} {}".format(obj_type, len(data)).encode()
    data_w_header = header + b"\x00" + data
    sha1 = hashlib.sha1(data_w_header).hexdigest()
    return sha1, data_w_header


def write_object(obj_type, data):
    """
    Write object to .git/objects dir
    """
    sha1, data_w_header = hash_object(obj_type, data)
    file_path = get_object_file_path(sha1)
    if not path.exists(file_path):
        makedirs(path.dirname(file_path), exist_ok=True)
        write_bytes_to_file(file_path, zlib.compress(data_w_header))


def read_object(sha1):
    """
    Read object with given SHA-1 prefix and return tuple of
    (object_type, data_bytes), or raise ValueError if not found.
    """
    file_path = get_object_file_path(sha1)
    data_w_header = zlib.decompress(read_bytes_from_file(file_path))
    header, data = data_w_header.split(b"\x00", 1)
    obj_type, size_str = header.decode().split(" ")
    size = int(size_str)

    assert size == len(
        data
    ), f"read_object: expected size {size}, got {len(data)} bytes"
    return (obj_type, data)
