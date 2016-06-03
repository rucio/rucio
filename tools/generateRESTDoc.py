#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#                       http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2015

import sys

CLASS = ''


class Class():
    def __init__(self, name, docstring, methods, urls):
        self.name = name
        self.docstring = docstring
        self.methods = methods


class Method():
    def __init__(self, name, params, docstring, body, urls):
        self.name = name
        self.params = params
        self.docstring = docstring
        self.body = body
        self.url = self.genurls(urls)

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name

    def genurls(self, urls):
        url = CLASS
        for i in urls:
            if i[0].count('(.+)') == len(self.params) - 1:
                url += i[0]
        for i in self.params[1:]:
            url = url.replace('(.+)', '<{0}>'.format(i.replace(' ', '')), 1)
        for i in urls:
            if i[0].count('(.*)') == len(self.params) - 1:
                url += i[0]
        for i in self.params[1:]:
            url = url.replace('(.*)', '<{0}>'.format(i.replace(' ', '')), 1)
        return url

    def geterrors(self):
        errors = filter(lambda x: x.count('generate_http_error(') >= 1, self.body.splitlines())
        docstr = '\n'
        for e in errors:
            a, b, c = e.split('generate_http_error(')[1].split(')')[0].split(', ')
            docstr += ' :statuscode {0}: {1}\n'.format(a, b + ': ' + c)
        return docstr

    def gendoc(self):
        docstr = ''
        docstr += '.. http:'
        docstr += self.name.lower()
        if self.body.count('BadRequest'):
            return ''
        if self.docstring.count('Web service startup'):
            return ''
        docstr += ':: ' + self.url
        try:
            docstr += "\n\n{0}\n\n".format(self.docstring.splitlines()[0] + self.docstring.splitlines()[1])
        except IndexError:
            try:
                docstr += "  \n\n{0}\n\n".format(self.docstring.splitlines()[0])
            except IndexError:
                docstr += "\n\n  No doc string\n\n"
        docstr += " **Example request**:\n\n"
        docstr += " .. sourcecode:: http\n\n"
        docstr += "    {0} {1} HTTP/1.1\n\n".format(self.name, self.url)
        # Accept: ???
        docstr += " **Example response**:\n\n"
        docstr += " .. sourcecode:: http\n\n"
        docstr += "  HTTP/1.1 200 OK\n  Vary: Accept\n  Content-Type:"
        try:
            a, b = self.body.split('header(')[1].split(')')[0].split(', ')
            if b.count('ctx.env'):
                pass
            else:
                docstr += " {0}".format(b)
        except IndexError:
            pass
        docstr += "\n"
        docstr += self.geterrors()
        return docstr


def geturls(s, classname):
    lines = s.split('urls = (')[1].splitlines()
    urls = []
    tuples = []
    for l in lines:
        if l == ')':
            break
        urls.append(l)
    for i in urls[1:]:
        a = i.replace(' ', '')
        a = a.replace('\'', '')
        a = a.split(',')[:-1]
        if classname == a[1]:
            tuples.append(a)
    return tuples


def parsedocstring(s):
    try:
        return s.split('\'\'\'')[1]
    except IndexError:
        try:
            return s.split('\"\"\"')[1]
        except IndexError:
            return ''


def parsebody(s):
    try:
        return s.split('\'\'\'')[2]
    except IndexError:
        try:
            return s.split('\"\"\"')[2]
        except IndexError:
            try:
                return s.split(':')[1]
            except IndexError:
                return ''


def parsemethods(s, urls, classname):
    methods = s.split('    def ')
    met = []
    for m in methods[1:]:
        name = m.split('(')[0]
        params = m.split('(')[1].split(')')[0].split(',')
        docstring = parsedocstring(m)
        body = parsebody(m)
        met.append(Method(name, params, docstring, body, urls))
    return met


def parseclasses(s):
    '''
    s should be a string, probably from open('restfile.py').read()
    '''

    classes = s.split('class ')
    c = []
    for each in classes[1:]:
        name = each.split('(')[0]
        ds = parsedocstring(s)
        urls = geturls(s, name)
        met = parsemethods(each, urls, name)
        c.append(Class(name, ds, met, urls))
    return c


def gendocforclass(c):
    methods = c.methods
    docstr = ''
    for m in methods:
        docstr += m.gendoc() + '\n'
    return docstr


def getbaseurl(filepath, aliases):
    for i in aliases.read().splitlines():
        if filepath.split('/')[-1] in i:
            global CLASS
            CLASS = i.split()[1]


if __name__ == "__main__":
    try:
        fp = open(sys.argv[1])
        aliases = open('etc/web/aliases-py27.conf')
        getbaseurl(sys.argv[1], aliases)
        classes = parseclasses(fp.read())
        for c in classes:
            print gendocforclass(c)
    except IOError:
        print 'Not such file'
