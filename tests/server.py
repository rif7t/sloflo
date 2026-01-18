from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import time

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(1)
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("0.0.0.0", 8080), SimpleHandler).serve_forever()
