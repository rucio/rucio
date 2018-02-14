#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

from json import dumps

from rucio.api.scope import list_scopes
from rucio.web.rest.flaskapi.v1.common import before_request, after_request

from flask import Flask, Blueprint
from flask.views import MethodView


class Attributes(MethodView):
    def get(self, account):
        """Return collection of posts.

        .. :quickref: Posts Collection; Get collection of posts.

        **Example request**:

        .. sourcecode:: http

            GET /posts/ HTTP/1.1
            Host: example.com
            Accept: application/json

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/json

            [
              {
                "post_id": 12345,
                "author": "/author/123/",
                "tags": ["sphinx", "rst", "flask"],
                "title": "Documenting API in Sphinx with httpdomain",
                "body": "How to..."
              },
              {
                "post_id": 12346,
                "author": "/author/123/",
                "tags": ["python3", "typehints", "annotations"],
                "title": "To typehint or not to typehint that is the question",
                "body": "Static checking in python..."
              }
            ]

        :query sort: sorting order e.g. sort=author,-pub_date
        :query q: full text search query
        :resheader Content-Type: application/json
        :status 200: posts found
        :returns: :class:`myapp.objects.Post`
        """
        return dumps(list_scopes())

    def post(self, account, key):
        """Add new post.

        .. :quickref: Posts Collection; Add new post to collection.

        :reqheader Accept: application/json
        :<json string title: post title
        :<json string body: post body
        :<json string author: author id
        :<json List[string] tags: tags list
        :>json int: id
        :resheader Content-Type: application/json
        :resheader Location: post url
        :status 201: post created
        :status 400: malformed request
        :status 422: invalid parameters
        """
        pass

    def delete(self, account, key):
        pass


bp = Blueprint('did', __name__)
account_view = Attributes.as_view('account')
bp.add_url_rule('/', view_func=account_view, methods=['GET', ])
bp.add_url_rule('/<account>/<scope>', view_func=account_view, methods=['POST', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/dids')
    return doc_app


if __name__ == "__main__":
    application.run()
