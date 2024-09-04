# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import copy
import hashlib
import itertools
import math
import os
import time
from typing import TYPE_CHECKING, Any, Optional, Union

from rucio.common.exception import RucioException

if TYPE_CHECKING:
    from _typeshed import FileDescriptorOrPath


def _next_pow2(num: int) -> int:
    if not num:
        return 0
    return math.ceil(math.log2(num))


def _bittorrent_v2_piece_length_pow2(file_size: int) -> int:
    """
    Automatically chooses the `piece size` so that `piece layers`
    is kept small(er) than usually. This is a balancing act:
    having a big piece_length requires more work on bittorrent client
    side to validate hashes, but having it small requires more
    place to store the `piece layers` in the database.

    Returns the result as the exponent 'x' for power of 2.
    To get the actual length in bytes, the caller should compute 2^x.
    """

    # by the bittorrent v2 specification, the piece size is equal to block size = 16KiB
    min_piece_len_pow2 = 14  # 2 ** 14 == 16 KiB
    if not file_size:
        return min_piece_len_pow2
    # Limit the maximum size of pieces_layers hash chain for bittorrent v2,
    # because we'll have to store it in the database
    max_pieces_layers_size_pow2 = 20  # 2 ** 20 == 1 MiB
    # sha256 requires 2 ** 5 == 32 Bytes == 256 bits
    hash_size_pow2 = 5

    # The closest power of two bigger than the file size
    file_size_pow2 = _next_pow2(file_size)

    # Compute the target size for the 'pieces layers' in the torrent
    # (as power of two: the closest power-of-two smaller than the number)
    # Will cap at max_pieces_layers_size for files larger than 1TB.
    target_pieces_layers_size = math.sqrt(file_size)
    target_pieces_layers_size_pow2 = min(math.floor(math.log2(target_pieces_layers_size)), max_pieces_layers_size_pow2)
    target_piece_num_pow2 = max(target_pieces_layers_size_pow2 - hash_size_pow2, 0)

    piece_length_pow2 = max(file_size_pow2 - target_piece_num_pow2, min_piece_len_pow2)
    return piece_length_pow2


def bittorrent_v2_piece_length(file_size: int) -> int:
    return 2 ** _bittorrent_v2_piece_length_pow2(file_size)


def bittorrent_v2_merkle_sha256(file: "FileDescriptorOrPath") -> tuple[bytes, bytes, int]:
    """
    Compute the .torrent v2 hash tree for the given file.
    (http://www.bittorrent.org/beps/bep_0052.html)
    In particular, it will return the root of the merkle hash
    tree of the file, the 'piece layers' as described in the
    previous BEP, and the chosen `piece size`

    This function will read the file in chunks of 16KiB
    (which is the imposed block size by bittorrent v2) and compute
    the sha256 hash of each block. When enough blocks are read
    to form a `piece`, will compute the merkle hash root of the
    piece from the hashes of its blocks. At the end, the hashes
    of pieces are combined to create the global pieces_root.
    """

    # by the bittorrent v2 specification, the block size and the
    # minimum piece size are both fixed to 16KiB
    block_size = 16384
    block_size_pow2 = 14  # 2 ** 14 == 16 KiB
    # sha256 requires 2 ** 5 == 32 Bytes == 256 bits
    hash_size = 32

    def _merkle_root(leafs: list[bytes], nb_levels: int, padding: bytes) -> bytes:
        """
        Build the root of the merkle hash tree from the (possibly incomplete) leafs layer.
        If len(leafs) < 2 ** nb_levels, it will be padded with the padding repeated as many times
        as needed to have 2 ** nb_levels leafs in total.
        """
        nodes = copy.copy(leafs)
        level = nb_levels

        while level > 0:
            for i in range(2 ** (level - 1)):
                node1 = nodes[2 * i] if 2 * i < len(nodes) else padding
                node2 = nodes[2 * i + 1] if 2 * i + 1 < len(nodes) else padding
                h = hashlib.sha256(node1)
                h.update(node2)
                if i < len(nodes):
                    nodes[i] = h.digest()
                else:
                    nodes.append(h.digest())
            level -= 1
        return nodes[0] if nodes else padding

    file_size = os.stat(file).st_size
    piece_length_pow2 = _bittorrent_v2_piece_length_pow2(file_size)

    block_per_piece_pow2 = piece_length_pow2 - block_size_pow2
    piece_length = 2 ** piece_length_pow2
    block_per_piece = 2 ** block_per_piece_pow2
    piece_num = math.ceil(file_size / piece_length)

    remaining = file_size
    remaining_in_block = min(file_size, block_size)
    block_hashes = []
    piece_hashes = []
    current_hash = hashlib.sha256()
    block_padding = bytes(hash_size)
    with open(file, 'rb') as f:
        while True:
            data = f.read(remaining_in_block)
            if not data:
                break

            current_hash.update(data)

            remaining_in_block -= len(data)
            remaining -= len(data)

            if not remaining_in_block:
                block_hashes.append(current_hash.digest())
                if len(block_hashes) == block_per_piece or not remaining:
                    piece_hashes.append(_merkle_root(block_hashes, nb_levels=block_per_piece_pow2, padding=block_padding))
                    block_hashes = []
                current_hash = hashlib.sha256()
                remaining_in_block = min(block_size, remaining)

            if not remaining:
                break

    if remaining or remaining_in_block or len(piece_hashes) != piece_num:
        raise RucioException(f'Error while computing merkle sha256 of {file}')

    piece_padding = _merkle_root([], nb_levels=block_per_piece_pow2, padding=block_padding)
    pieces_root = _merkle_root(piece_hashes, nb_levels=_next_pow2(piece_num), padding=piece_padding)
    pieces_layers = b''.join(piece_hashes) if len(piece_hashes) > 1 else b''

    return pieces_root, pieces_layers, piece_length


def bencode(obj: Union[int, bytes, str, list, dict[bytes, Any]]) -> bytes:
    """
    Copied from the reference implementation of v2 bittorrent:
    http://bittorrent.org/beps/bep_0052_torrent_creator.py
    """

    if isinstance(obj, int):
        return b"i" + str(obj).encode() + b"e"
    elif isinstance(obj, bytes):
        return str(len(obj)).encode() + b":" + obj
    elif isinstance(obj, str):
        return bencode(obj.encode("utf-8"))
    elif isinstance(obj, list):
        return b"l" + b"".join(map(bencode, obj)) + b"e"
    elif isinstance(obj, dict):
        if all(isinstance(i, bytes) for i in obj.keys()):
            items = list(obj.items())
            items.sort()
            return b"d" + b"".join(map(bencode, itertools.chain(*items))) + b"e"
        else:
            raise ValueError("dict keys should be bytes " + str(obj.keys()))
    raise ValueError("Allowed types: int, bytes, str, list, dict; not %s", type(obj))


def construct_torrent(
        scope: str,
        name: str,
        length: int,
        piece_length: int,
        pieces_root: bytes,
        pieces_layers: "Optional[bytes]" = None,
        trackers: "Optional[list[str]]" = None,
) -> "tuple[str, bytes]":

    torrent_dict = {
        b'creation date': int(time.time()),
        b'info': {
            b'meta version': 2,
            b'private': 1,
            b'name': f'{scope}:{name}'.encode(),
            b'piece length': piece_length,
            b'file tree': {
                name.encode(): {
                    b'': {
                        b'length': length,
                        b'pieces root': pieces_root,
                    }
                }
            }
        },
        b'piece layers': {},
    }
    if trackers:
        torrent_dict[b'announce'] = trackers[0].encode()
        if len(trackers) > 1:
            torrent_dict[b'announce-list'] = [t.encode() for t in trackers]
    if pieces_layers:
        torrent_dict[b'piece layers'][pieces_root] = pieces_layers

    torrent_id = hashlib.sha256(bencode(torrent_dict[b'info'])).hexdigest()[:40]
    torrent = bencode(torrent_dict)
    return torrent_id, torrent


def merkle_sha256(file: "FileDescriptorOrPath") -> str:
    """
    The root of the sha256 merkle hash tree with leaf size of 16 KiB.
    """
    pieces_root, _, _ = bittorrent_v2_merkle_sha256(file)
    return pieces_root.hex()
