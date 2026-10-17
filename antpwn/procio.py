"""AntPwn procio: pwntools-style process tube on raw pipes (no dependency)
进程交互: subprocess 管道封装, 支持 send/recv_until/交互命令与 flag 检测
"""
import os
import select
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
