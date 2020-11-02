"""
Pure python git database explorer
Inspired from: https://github.com/benhoyt/pygit/blob/master/pygit.py
"""

from collections import namedtuple
from os import path, makedirs
from pprint import pprint
from typing import List, Dict, Union
import hashlib
import re
import zlib


OBECT_TYPES = {"commit": 1, "tree": 2, "blob": 3}
DataObject = namedtuple("DataObject", "type data")
Blob = namedtuple("Blob", "data")
TreeEntry = namedtuple("TreeEntry", "mode path sha1")
Tree = namedtuple("Tree", "entries")
Commit = namedtuple(
    "Commit", "tree parent author author_time committer commit_time comment"
)
GitObject = Union[Blob, Tree, Commit]


class GitException(Exception):
    pass


def write_bytes_to_file(file_path: str, data: bytes):
    makedirs(path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(data)


def read_bytes_from_file(file_path: str) -> bytes:
    with open(file_path, "rb") as f:
        return f.read()


def read_ref(ref: str, kind="branch") -> str:
    """
    get sha1 of commit that a ref (branch/tag) is pointing to e.g "master"
    """
    ref_kind = "heads" if kind == "branch" else "tags"
    with open(f".git/refs/{ref_kind}/{ref}") as f:
        return f.read().strip()


def pack_object_data(obj_type: str, data: bytes) -> (str, bytes):
    """
    Return a tuple of (sha1(type + len + data), gzipped_data)
    """
    data_w_header = b"\x00".join([f"{obj_type} {len(data)}", data])
    sha1 = hashlib.sha1(data_w_header).hexdigest()
    gzipped_data = zlib.compress(data_w_header)
    return sha1, gzipped_data


def unpack_object_data(gzipped_data: bytes) -> DataObject:
    data_w_header = zlib.decompress(gzipped_data)
    header, data = data_w_header.split(b"\x00", 1)
    obj_type, size_str = header.decode().split(" ")

    if int(size_str) != len(data):
        raise GitException(f"expected size {size_str}, got {len(data)} bytes")

    return obj_type, data


def get_object_file_path(sha1: str) -> str:
    return path.join(".git", "objects", sha1[:2], sha1[2:])


def write_object_data(obj_type: str, data: bytes):
    sha1, gzipped_data = pack_object_data(obj_type, data)
    file_path = get_object_file_path(sha1)
    if not path.exists(file_path):
        write_bytes_to_file(file_path, gzipped_data)


def read_object_data(sha1: str) -> DataObject:
    file_path = get_object_file_path(sha1)
    return unpack_object_data(read_bytes_from_file(file_path))


def pack_tree(tree: Tree) -> bytes:
    packed_items = [
        b"\x00".join([f"{entry.mode} {entry.path}", bytes.fromhex(entry.sha1)])
        for entry in tree.entries
    ]
    return b"".join(packed_items)


def unpack_tree(data: bytes) -> Tree:
    matches = re.findall(br"(\d+) (.+?)\0(.{20})", data, re.MULTILINE)
    entries = [
        TreeEntry(match[0].decode(), match[1].decode(), match[2].hex())
        for match in matches
    ]
    return Tree(entries)


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


def write_git_object(obj: GitObject):
    if isinstance(obj, Blob):
        write_object_data("blob", obj.data)
    elif isinstance(obj, Tree):
        write_object_data("tree", pack_tree(obj))
    elif isinstance(obj, Commit):
        write_object_data("commit", pack_commit(obj))
    else:
        raise GitException(f"'{type(obj).__name__}' is not a valid GitObject")


def read_git_object(sha1: str) -> GitObject:
    obj_type, data = read_object_data(sha1)
    obj = None
    if obj_type == "blob":
        obj = Blob(data)
    elif obj_type == "tree":
        obj = unpack_tree(data)
    elif obj_type == "commit":
        obj = unpack_commit(data)
    else:
        raise GitException(f"'{obj_type}' must be one of {OBECT_TYPES.values()}")

    # TODO: validate read
    return obj


def get_connected_objects(sha1: str, object_graph: Dict = None) -> Dict:
    """
    Starting from a sha1 of an object e.g commit/tree
    Return an object_graph
    where object_graph is a dictionary of {sha1: unpacked_object}
    """

    if object_graph is None:
        object_graph = {}

    obj = read_git_object(sha1)
    object_graph[sha1] = obj

    if isinstance(obj, Tree):
        for entry in obj.entries:
            get_connected_objects(entry.sha1, object_graph)

    elif isinstance(obj, Commit):
        get_connected_objects(obj.tree, object_graph)

        for parent in obj.parent:
            get_connected_objects(parent, object_graph)

    return object_graph


# Test Code #
# TODO: validate read_bytes == write_bytes
if __name__ == "__main__":
    master_sha1 = read_ref("master")
    obj_graph = get_connected_objects(master_sha1)
    pprint(obj_graph)
