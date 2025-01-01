from http.server import BaseHTTPRequestHandler, HTTPServer


class HelloWorldHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # HTTPステータスコード200（成功）を送信
        self.send_response(200)
        # レスポンスヘッダーを設定
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        # レスポンスボディを送信
        self.wfile.write(b"Hello, World!\n")


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
