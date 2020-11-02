"""
Pure python git database explorer
Inspired from: https://github.com/benhoyt/pygit/blob/master/pygit.py
"""

from collections import namedtuple
from os import path, makedirs
from pprint import pprint
from typing import List, Dict
import hashlib
import re
import zlib


OBECT_TYPES = {"commit": 1, "tree": 2, "blob": 3}
Object = namedtuple("Object", "type data")
TreeEntry = namedtuple("TreeEntry", "mode path sha1")
Commit = namedtuple(
    "Commit", "tree parent author author_time committer commit_time comment"
)


class GitException(Exception):
    pass


def read_bytes_from_file(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        return f.read()


def write_bytes_to_file(file_path: str, data: bytes):
    makedirs(path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(data)


def validate_obj_type(obj_type: str):
    if obj_type not in OBECT_TYPES:
        raise GitException(f"'{obj_type}' must be one of {OBECT_TYPES.values()}")


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
    validate_obj_type(obj_type)

    if int(size_str) != len(data):
        raise GitException(f"expected size {size_str}, got {len(data)} bytes")

    return Object(obj_type, data)


def get_object_file_path(sha1: str) -> str:
    return path.join(".git", "objects", sha1[:2], sha1[2:])


def write_object(obj: Object):
    sha1, gzipped_data = pack_object(obj)
    file_path = get_object_file_path(sha1)
    if not path.exists(file_path):
        write_bytes_to_file(file_path, gzipped_data)


def read_object(sha1: str) -> Object:
    file_path = get_object_file_path(sha1)
    return unpack_object(read_bytes_from_file(file_path))


def read_ref(ref: str, kind="branch") -> str:
    """
    get sha1 of commit that a ref (branch/tag) is pointing to e.g "master"
    """
    ref_kind = "heads" if kind == "branch" else "tags"
    with open(f".git/refs/{ref_kind}/{ref}") as f:
        return f.read().strip()


def pack_tree(entries: List[TreeEntry]) -> bytes:
    packed_items = [
        b"\x00".join([f"{entry.mode} {entry.path}".encode(), bytes.fromhex(entry.sha1)])
        for entry in entries
    ]
    return b"".join(packed_items)


def unpack_tree(data: bytes) -> List[TreeEntry]:
    matches = re.findall(br"(\d+) (.+?)\0(.{20})", data, re.MULTILINE)
    return [
        TreeEntry(match[0].decode(), match[1].decode(), match[2].hex())
        for match in matches
    ]


def pack_commit(commit: Commit) -> bytes:
    parent = " ".join(commit.parent)
    lines = [
        f"tree {commit.tree}",
        f"parent {parent}" if parent else None,
        f"author {commit.author} {commit.author_time}",
        f"committer {commit.committer} {commit.commit_time}",
        "",
        commit.comment,
    ]
    return "\n".join([line for line in lines if line is not None]).encode()


def unpack_commit(data: bytes) -> Commit:
    meta_str, comment = data.decode().split("\n\n", 1)
    meta = {}

    for line in meta_str.split("\n"):
        key, val = line.split(" ", 1)

        if key == "committer" or key == "author":
            user, time = re.fullmatch(r"(.*) (\d+ [+-]\d{4})", val).groups()
            val = user
            if key == "author":
                meta["author_time"] = time
            else:
                meta["commit_time"] = time

        elif key == "parent":
            # merge commit may have multiple parents
            val = val.split(" ")

        meta[key] = val

    return Commit(
        meta["tree"],
        # root commit doesn't have any parents
        meta.get("parent", []),
        meta["author"],
        meta["author_time"],
        meta["committer"],
        meta["commit_time"],
        comment,
    )


def get_connected_objects(sha1: str, object_graph: Dict = None) -> Dict:
    """
    Starting from a sha1 of an object e.g commit/tree
    Return an object_graph
    where object_graph is a dictionary of {sha1: unpacked_object}
    """

    if object_graph is None:
        object_graph = {}

    obj = read_object(sha1)
    if obj.type == "commit":
        commit = unpack_commit(obj.data)
        object_graph[sha1] = commit
        get_connected_objects(commit.tree, object_graph)

        for parent_sha1 in commit.parent:
            get_connected_objects(parent_sha1, object_graph)

    elif obj.type == "tree":
        tree_entries = unpack_tree(obj.data)
        object_graph[sha1] = tree_entries

        for entry in tree_entries:
            get_connected_objects(entry.sha1, object_graph)

    elif obj.type == "blob":
        object_graph[sha1] = obj

    return object_graph


# Test Code #
if __name__ == "__main__":
    master_sha1 = read_ref("master")
    obj_graph = get_connected_objects(master_sha1)
    pprint(obj_graph)
