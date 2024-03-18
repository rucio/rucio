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


from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread


class MockServer:
    """
    Start A simple http server in a separate thread to serve as MOCK for testing the client
    """

    class Handler(SimpleHTTPRequestHandler):
        def send_code_and_message(self, code, headers, message):
            """
            Helper which wraps the quite-low-level BaseHTTPRequestHandler primitives and is used to send reponses.
            """
            self.send_response(code)
            self.send_header("Content-type", "text/plain")
            for name, content in headers.items():
                self.send_header(name, content)
            self.end_headers()
            self.wfile.write(message.encode())

    def __init__(self, request_handler_cls):
        self.server = HTTPServer(('localhost', 0), request_handler_cls)
        self.thread = Thread(target=self.server.serve_forever)
        self.thread.daemon = True

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    @property
    def base_url(self):
        name, port = self.server.server_address
        return 'http://{}:{}'.format(name, port)
