from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
import core.server as server

PORT = 8080


class EmotetServer(BaseHTTPRequestHandler):
	def do_POST(self):
		httpReqBody = self.rfile.read(int(self.headers['Content-Length']))
		s = server.server()
		s.loadKey("testData/private.pem")
		respData = s.parse(httpReqBody)
		self.send_response(404)
		self.send_header('Server','nginx')
		self.send_header('Content-Length',len(respData))
		self.end_headers()
		self.wfile.write(respData)


	def handle_error(self, request, client_address):
		pass

def main():
	try:
		server = HTTPServer(("", PORT), EmotetServer)
		print "Listening on port ", PORT
		server.serve_forever()

	except KeyboardInterrupt:
		server.socket.close()

if __name__ == '__main__':
	main()
