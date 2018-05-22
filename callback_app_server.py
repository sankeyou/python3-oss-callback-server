# -*- coding: utf-8 -*-

import base64
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import request

from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5


def get_local_ip():
    try:
        csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        csock.connect(('8.8.8.8', 80))
        (addr, port) = csock.getsockname()
        csock.close()
        return addr
    except socket.error:
        return ""


class MyHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        # get public key
        pub_key_url = ''
        try:
            pub_key_url = base64.b64decode(bytes(self.headers['x-oss-pub-key-url'], 'utf8')).decode()
            url_reader = request.urlopen(pub_key_url)
            pub_key = url_reader.read()
        except Exception as ex:
            print(ex)
            print('pub_key_url : ' + pub_key_url)
            print('Get pub key failed!')
            self.send_response(400)
            self.end_headers()
            return

        # get authorization
        authorization = base64.b64decode(bytes(self.headers['authorization'], 'utf8'))

        # get callback body
        content_length = self.headers['content-length']
        callback_body = str(self.rfile.read(int(content_length)), 'utf8')

        # compose authorization string
        auth_str = ''
        pos = self.path.find('?')
        if -1 == pos:
            auth_str = self.path + '\n' + callback_body
        else:
            auth_str = request.unquote(self.path[0:pos]) + self.path[pos:] + '\n' + callback_body
        print(auth_str)

        # verify authorization
        try:
            verifier = Signature_pkcs1_v1_5.new(RSA.import_key(pub_key))

            digest = MD5.new(bytes(auth_str, 'utf8'))

            result = verifier.verify(digest, authorization)
        except Exception as e:
            print(e)
            result = False

        if not result:
            print('Authorization verify failed!')
            print('Public key : %s' % (pub_key))
            print('Auth string : %s' % (auth_str))
            self.send_response(400)
            self.end_headers()
            return

        # do something accoding to callback_body

        # response to OSS
        resp_body = '{"Status":"OK"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)


class MyHTTPServer(HTTPServer):
    def __init__(self, host, port):
        HTTPServer.__init__(self, (host, port), MyHTTPRequestHandler)


if '__main__' == __name__:
    server_ip = get_local_ip()
    server_port = 23450

    server = MyHTTPServer(server_ip, server_port)
    server.serve_forever()
