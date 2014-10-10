#!/usr/bin/python
# -*- coding: utf-8 -*-

import os, cgi, json, base64, subprocess, ConfigParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from socket import error as SocketError



def config():
	try:
		config = ConfigParser.RawConfigParser()
		config.read('deploy.cfg')

		port        = config.get('server',      'port')
		username    = config.get('security',    'username')
		password    = config.get('security',    'password')
		branch      = config.get('repository',  'branch')
		repository  = config.get('repository',  'name')

	except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
		print('Error loading configuration')
		os._exit(1)

	if (not port) or (not username) or (not password) or (not branch) or (not repository):
		print('Wrong configuration')
		os._exit(1)

	CFG['key']        = 'Basic ' + base64.b64encode(username + ':' + password)
	CFG['port']       = int(port)
	CFG['branch']     = branch
	CFG['repository'] = repository


def response(self, text=None, code=200):
	self.send_response(code)
	self.send_header('Content-Type', 'text/html')
	self.end_headers()
	self.wfile.write(text)


def auth(self):
	authorization = self.headers.getheader('Authorization')
	if (authorization is not None) and (authorization == CFG['key']):
		return True

	self.send_response(401)
	self.send_header('WWW-Authenticate', 'Basic realm="Classified"')
	self.send_header('Content-Type', 'text/html')
	self.end_headers()
	self.wfile.write('Unauthorized')
	return False



class ResponseError(Exception):
	pass



def request(payload):
	try:
		j = json.loads(payload)
	except ValueError:
		raise ResponseError('Failed to decode JSON')

	if ('repository' not in j) or ('commits' not in j):
		raise ResponseError('Missing fields: "repository" or "commits"')

	r = j.get('repository', {}).get('slug', '')
	if r != CFG['repository']:
		raise ResponseError('Wrong repository: ' + r)

	for commit in j.get('commits', []):
		if 'branch' not in commit:
			raise ResponseError('Missing field: "branch"')

		b = commit.get('branch', '')
		if b == CFG['branch']:
			return True

	raise ResponseError('Wrong branch')



class RequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		if auth(self) is False:
			return

		response(self, 'Error 501', 501)


	def do_POST(self):
		if auth(self) is False:
			return

		if self.path != '/hook':
			response(self, 'Error 404', 404)
			return

		env = {
			'REQUEST_METHOD': 'POST',
			'CONTENT_TYPE': self.headers['Content-Type']
		}
		form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=env)
		payload = form.getfirst('payload', '')

		try:
			request(payload)
			subprocess.Popen(['sh', 'deploy.sh'])
			response(self, 'Ok')

		except Exception as message:
			print(message)
			response(self, 'Error 500', 500)



def main():
	config()

	try:
		server = HTTPServer(('', CFG['port']), RequestHandler)
		server.serve_forever()

	except SocketError as message:
		print(message)

	except KeyboardInterrupt:
		server.socket.close()



CFG = {}

if __name__ == '__main__':
	main()
