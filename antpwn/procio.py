"""AntPwn procio: pwntools-style process tube on raw pipes (no dependency)
进程交互: 本地子进程管道 + 远程 TCP socket, 统一 send/recv_until/交互命令接口
"""
import os
import select
import socket
import subprocess
import time


class Tube:
    def __init__(self, path, argv=None, env=None):
        self.proc = subprocess.Popen(
            [path] + (argv or []), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=env or dict(os.environ), bufsize=0)

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def sendline(self, data=b""):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recv(self, timeout=1.0, size=4096):
        r, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if r:
            return os.read(self.proc.stdout.fileno(), size)
        return b""

    def recv_until(self, marker, timeout=3.0):
        if isinstance(marker, str):
            marker = marker.encode()
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([self.proc.stdout], [], [], 0.1)
            if r:
                buf += os.read(self.proc.stdout.fileno(), 4096)
                if marker in buf:
                    return buf
        return buf

    def clean(self, timeout=0.3):
        return self.recv(timeout)

    def drain(self, idle=0.4, max_total=2_000_000):
        """read until the pipe goes quiet (large %Nc padding can exceed the
        64KB pipe buffer and deadlock the child unless we keep reading)"""
        out = b""
        while len(out) < max_total:
            chunk = self.recv(timeout=idle)
            if not chunk:
                break
            out += chunk
        return out

    def alive(self):
        return self.proc.poll() is None

    def interactive_cmds(self, cmds, timeout=1.5):
        """send shell commands and collect output (flag hunting)"""
        out = b""
        for c in cmds:
            self.sendline(c)
            time.sleep(0.2)
            out += self.recv(timeout)
        return out

    def close(self):
        try:
            self.proc.kill()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class RemoteTube:
    """TCP tube: same surface as Tube, so strategies can run against remote.

    远程交互: 直接连 host:port, send/recv_until/drain 与本地 Tube 语义一致,
    因此 pwn --remote 可以复用同一套利用策略。
    """

    def __init__(self, host, port, timeout=10.0):
        self.host, self.port = host, int(port)
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.settimeout(0.2)

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data)

    def sendline(self, data=b""):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recv(self, timeout=1.0, size=4096):
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(size)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def recv_until(self, marker, timeout=3.0):
        if isinstance(marker, str):
            marker = marker.encode()
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if marker in buf:
                return buf
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def clean(self, timeout=0.3):
        return self.recv(timeout)

    def drain(self, idle=0.4, max_total=2_000_000):
        out = b""
        while len(out) < max_total:
            chunk = self.recv(timeout=idle)
            if not chunk:
                break
            out += chunk
        return out

    def alive(self):
        try:
            r, _, _ = select.select([self.sock], [], [], 0)
            if r:
                return bool(self.sock.recv(1, socket.MSG_PEEK))
            return True
        except OSError:
            return False

    def interactive_cmds(self, cmds, timeout=1.5):
        out = b""
        for c in cmds:
            self.sendline(c)
            time.sleep(0.2)
            out += self.recv(timeout)
        return out

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def __repr__(self):
        return f"<RemoteTube {self.host}:{self.port}>"
