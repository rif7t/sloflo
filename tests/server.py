import argparse
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

ap = argparse.ArgumentParser()
ap.add_argument("--service", type=float, default=1.0, help="seconds of work per request")
ap.add_argument("--capacity", type=int, default=0,
                help="max requests served at once (0 = unlimited); excess requests queue, so latency grows under overload")
args = ap.parse_args()

slots = threading.Semaphore(args.capacity) if args.capacity else None


class Server(ThreadingHTTPServer):
    request_queue_size = 4096  # default backlog of 5 would drop SYNs in the kernel under load

    def handle_error(self, request, client_address):
        pass  # clients that time out before we reply are expected under load


class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if slots:
            slots.acquire()
        try:
            time.sleep(args.service)
        finally:
            if slots:
                slots.release()
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, *args):
        pass


Server(("0.0.0.0", 8080), SimpleHandler).serve_forever()
