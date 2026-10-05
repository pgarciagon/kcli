import { RefusalError, requireValue } from './secure-files';

export async function hiddenInput(prompt: string): Promise<string> {
  requireValue(process.stdin.isTTY && process.stdout.isTTY && typeof process.stdin.setRawMode === 'function', 'Secret input requires a local interactive terminal; no arguments, environment or password files are accepted.');
  return new Promise((resolve, reject) => {
    const input = process.stdin; const wasRaw = !!input.isRaw; const bytes: number[] = []; let done = false;
    const finish = (error?: Error) => {
      if (done) return; done = true;
      input.off('data', consume); input.off('end', ended); input.off('error', ended);
      process.off('SIGINT', interrupted); process.off('SIGTERM', interrupted);
      const value = Buffer.from(bytes); bytes.fill(0);
      // Drain both Node's buffered input and new queued bytes while echo is still disabled.
      const discard = (data: Buffer) => { data.fill(0); }; input.on('data', discard);
      while (input.read() !== null) { /* discard buffered input */ }
      setTimeout(() => {
        input.off('data', discard); input.setRawMode(wasRaw); input.pause(); process.stdout.write('\n');
        if (error) { value.fill(0); reject(error); return; }
        const text = value.toString('utf8'); const valid = Buffer.from(text).equals(value); value.fill(0);
        if (!valid) reject(new RefusalError('Invalid terminal encoding.')); else resolve(text);
      }, 50);
    };
    const interrupted = () => finish(new RefusalError('Secret input cancelled.'));
    const ended = () => finish(new RefusalError('Secret input terminal unavailable.'));
    const consume = (data: Buffer) => {
      for (const byte of data) {
        if (byte === 3 || byte === 4 || byte === 27) { data.fill(0); interrupted(); return; }
        if (byte === 10 || byte === 13) { data.fill(0); finish(); return; }
        if (byte === 127 || byte === 8) {
          const last = bytes.pop(); if (last !== undefined && (last & 0xc0) === 0x80) { while (bytes.length && (bytes[bytes.length - 1] & 0xc0) === 0x80) bytes.pop(); bytes.pop(); } continue;
        }
        if (byte < 32 || bytes.length >= 1024) { data.fill(0); finish(new RefusalError('Invalid or oversized terminal input.')); return; }
        bytes.push(byte);
      }
      data.fill(0);
    };
    input.setRawMode(true); input.on('data', consume); input.once('end', ended); input.once('error', ended);
    process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted); input.resume(); process.stdout.write(prompt);
  });
}
