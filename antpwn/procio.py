"""AntPwn procio: pwntools-style process tube on raw pipes (no dependency)
进程交互: 本地子进程管道 + 远程 TCP socket, 统一 send/recv_until/交互命令接口
"""
import os
import select
import socket
import subprocess
import time


class Tube:
    def __init__(self, path, argv=None, env=None, pty=False):
        self.pty = bool(pty)
        self._fd = None
        if self.pty:
            import pty as _pty
            import tty as _tty
            master, slave = _pty.openpty()
            try:
                _tty.setraw(slave)
            except Exception:
                pass
            try:
                self.proc = subprocess.Popen(
                    [path] + (argv or []), stdin=slave, stdout=slave,
                    stderr=slave, env=env or dict(os.environ),
                    bufsize=0, close_fds=True)
            except Exception:
                os.close(master)
                os.close(slave)
                raise
            os.close(slave)
            self._fd = master
        else:
            self.proc = subprocess.Popen(
                [path] + (argv or []), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=env or dict(os.environ), bufsize=0)

    def _out_fd(self):
        return self._fd if self.pty else self.proc.stdout.fileno()

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        if self.pty:
            os.write(self._fd, data)
        else:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def sendline(self, data=b""):
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recv(self, timeout=1.0, size=4096):
        fd = self._out_fd()
        r, _, _ = select.select([fd], [], [], timeout)
        if r:
            try:
                return os.read(fd, size)
            except OSError:
                return b""
        return b""

    def recv_until(self, marker, timeout=3.0):
        if isinstance(marker, str):
            marker = marker.encode()
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            fd = self._out_fd()
            r, _, _ = select.select([fd], [], [], 0.1)
            if r:
                try:
                    buf += os.read(fd, 4096)
                except OSError:
                    break
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
        try:
            self.proc.wait(timeout=0.5)   # reap the child, no zombies
        except Exception:
            pass
        for f in (getattr(self.proc, "stdin", None), getattr(self.proc, "stdout", None)):
            try:
                if f:
                    f.close()
            except Exception:
                pass
        if self.pty and self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

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
