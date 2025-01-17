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
def prepare_saml_request(environ, data):
    """
    TODO: Validate for Flask
    Prepare a webpy request for SAML
    :param environ: Flask request.environ object
    :param data: GET or POST data
    """
    if environ.get('mod_wsgi.url_scheme') == 'https':
        ret = {
            'https': 'on' if environ.get('modwsgi.url_scheme') == 'https' else 'off',
            'http_host': environ.get('HTTP_HOST'),
            'server_port': environ.get('SERVER_PORT'),
            'script_name': environ.get('SCRIPT_NAME'),
            # Uncomment if using ADFS as IdP
            # 'lowercase_urlencoding': True,
        }
        if data:
            ret['get_data'] = data
            ret['post_data'] = data
        return ret

    return None
