"""Synthetic local-terminal driver. Secret test input travels only through a PTY."""
import errno
import json
import os
import pty
import select
import signal
import sys
import time


request = json.load(sys.stdin)
pid, fd = pty.fork()
if pid == 0:
    os.execvpe(request['argv'][0], request['argv'], {**os.environ, 'HOME': request['home']})
output = b''
step = 0
deadline = time.monotonic() + 30
status = None
waited = 0
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            output += data
        if step < len(request['inputs']):
            item = request['inputs'][step]
            if item['prompt'].encode() in output:
                os.write(fd, (item['value'] + '\n').encode())
                step += 1
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            break
    else:
        os.kill(pid, signal.SIGKILL)
        raise RuntimeError('Synthetic terminal test timed out')
    if status is None or not waited:
        _, status = os.waitpid(pid, 0)
    text = output.decode(errors='replace')
    secrets = [item['value'] for item in request['inputs']]
    leaked = any(secret and secret in text for secret in secrets)
    print(json.dumps({'status': os.waitstatus_to_exitcode(status), 'stdout': '[withheld]' if leaked else text, 'leaked': leaked}))
finally:
    os.close(fd)
