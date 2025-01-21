from http.server import BaseHTTPRequestHandler, HTTPServer


class HelloWorldHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.do_POST()

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sessionid=poodletest;")
        self.end_headers()
        self.wfile.write(b"<h1>POODLE</h1>")


# サーバーのアドレスとポートを設定
host = "localhost"
port = 8050

server = HTTPServer((host, port), HelloWorldHandler)
print(f"Server started at http://{host}:{port}")
try:
    server.serve_forever()  # サーバーを実行
except KeyboardInterrupt:
    print("\nServer stopped.")
    server.server_close()
