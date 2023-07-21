# -*- coding: utf-8 -*-
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

import base64
import logging
import os.path
import time
from urllib.parse import urlparse, urlencode, parse_qs

from rucio.common import exception
from rucio.common.utils import construct_torrent, resolve_ip
from rucio.rse.protocols.protocol import RSEProtocol
from rucio.rse import rsemanager

from rucio.common.extra import import_extras

EXTRA_MODULES = import_extras(['libtorrent'])

lt = None
if EXTRA_MODULES['libtorrent']:
    import libtorrent as lt  # pylint: disable=E0401

if getattr(rsemanager, 'CLIENT_MODE', None):
    from rucio.client.didclient import DIDClient

    def _fetch_meta_client(rse_id: str, scope: str, name: str):
        return DIDClient().get_metadata(scope=scope, name=name, plugin='all')

    _fetch_meta = _fetch_meta_client
else:
    from rucio.common.types import InternalScope
    from rucio.core.did import get_metadata
    from rucio.core.rse import get_rse_vo

    def _fetch_meta_server(rse_id: str, scope: str, name: str):
        vo = get_rse_vo(rse_id)
        return get_metadata(scope=InternalScope(scope, vo=vo), name=name, plugin='all')

    _fetch_meta = _fetch_meta_server


class Default(RSEProtocol):

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)
        self.logger = logger

    def lfns2pfns(self, lfns):
        pfns = {}
        prefix = self.attributes['prefix']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        host_port = '%s:%s' % (self.attributes['hostname'], str(self.attributes['port']))

        lfns = [lfns] if isinstance(lfns, dict) else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']

            if 'path' in lfn and lfn['path'] is not None:
                path = lfn['path'] if not lfn['path'].startswith('/') else lfn['path'][1:]
            else:
                path = self._get_path(scope=scope, name=name)

            scope_name = '%s:%s' % (scope, name)

            query = {
                'x.pe': host_port,
                'x.rucio_scope': scope,
                'x.rucio_name': name,
                'x.rucio_path': ''.join((prefix, path))
            }
            pfns[scope_name] = 'magnet:?' + urlencode(query)

        return pfns

    def parse_pfns(self, pfns):
        ret = dict()
        pfns = [pfns] if isinstance(pfns, str) else pfns

        for pfn in pfns:
            parsed = urlparse(pfn)
            scheme = parsed.scheme

            query = parse_qs(parsed.query)
            host_port = next(iter(query.get('x.pe', [])), ':')
            hostname, port = host_port.split(':')
            port = int(port)
            path = next(iter(query.get('x.rucio_path', [])), '')
            scope = next(iter(query.get('x.rucio_scope', [])), '')
            name = next(iter(query.get('x.rucio_name', [])), '')

            # Protect against 'lazy' defined prefixes for RSEs in the repository
            if not self.attributes['prefix'].startswith('/'):
                self.attributes['prefix'] = '/' + self.attributes['prefix']
            if not self.attributes['prefix'].endswith('/'):
                self.attributes['prefix'] += '/'

            if self.attributes['hostname'] != hostname:
                if self.attributes['hostname'] != 'localhost':  # In the database empty hostnames are replaced with localhost but for some URIs (e.g. file) a hostname is not included
                    raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (hostname, self.attributes['hostname']))

            if self.attributes['port'] != port:
                raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (port, self.attributes['port']))

            if not path.startswith(self.attributes['prefix']):
                raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(path.split('/')[0:len(self.attributes['prefix'].split('/')) - 1]),
                                                                                                              self.attributes['prefix']))  # len(...)-1 due to the leading '/

            # Spliting parsed.path into prefix, path, filename
            prefix = self.attributes['prefix']
            path = path.partition(self.attributes['prefix'])[2]
            path = '/'.join(path.split('/')[:-1])
            if not path.startswith('/'):
                path = '/' + path
            if path != '/' and not path.endswith('/'):
                path = path + '/'
            ret[pfn] = {'path': path, 'scope': scope, 'name': name, 'scheme': scheme, 'prefix': prefix, 'port': port, 'hostname': hostname, }

        return ret

    def connect(self):
        pass

    def close(self):
        pass

    def get(self, path, dest, transfer_timeout=None):
        if not lt:
            raise exception.RucioException('The libtorrent python package is required to perform this operation')

        [lfn] = self.parse_pfns([path]).values()
        scope = lfn['scope']
        name = lfn['name']
        hostname = lfn['hostname']
        port = lfn['port']

        meta = _fetch_meta(rse_id=self.rse['id'], scope=scope, name=name)
        pieces_root = base64.b64decode(meta.get('bittorrent_pieces_root', ''))
        if not pieces_root:
            raise exception.RucioException('Torrent metadata missing. Cannot download file.')

        length = meta.get('bytes')
        piece_length = meta.get('bittorrent_piece_length', 0)
        pieces_layers = base64.b64decode(meta.get('bittorrent_pieces_layers', ''))

        _, torrent = construct_torrent(
            scope=scope,
            name=name,
            length=length,
            piece_length=piece_length,
            pieces_root=pieces_root,
            pieces_layers=pieces_layers,
        )

        ses = lt.session()  # type: ignore # noqa
        params = {
            'ti': lt.torrent_info(torrent),  # type: ignore # noqa
            'save_path': os.path.dirname(dest),
            'name': os.path.basename(dest),
            'renamed_files': {0: os.path.basename(dest)},
        }

        handle = ses.add_torrent(params)
        try:
            handle.resume()
            handle.connect_peer((resolve_ip(hostname), port))
            while handle.status().progress != 1.0:
                time.sleep(0.25)
        finally:
            ses.remove_torrent(handle)
