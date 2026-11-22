import net from 'node:net';
import tls from 'node:tls';
import { config } from './config.js';

// A small SMTP client, enough to send plain-text mail through an ordinary provider
// (port 465 with TLS, or port 587 with STARTTLS). No dependencies.

const TIMEOUT_MS = 15_000;
const clean = (s) => String(s).replace(/[\r\n]+/g, ' ').trim(); // no header injection
const addr = (s) => {
  const a = clean(s);
  if (!/^[^\s<>@,;"]+@[^\s<>@,;"]+\.[^\s<>@,;"]+$/.test(a)) throw new Error('bad address');
  return a;
};
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');

class Session {
  constructor(socket) {
    this.buffer = '';
    this.waiters = [];
    this.attach(socket);
  }

  attach(socket) {
    this.socket = socket;
    socket.setEncoding('utf8');
    socket.setTimeout(TIMEOUT_MS, () => this.fail(new Error('SMTP timeout')));
    socket.on('data', (chunk) => {
      this.buffer += chunk;
      this.flush();
    });
    socket.on('error', (err) => this.fail(err));
    socket.on('close', () => this.fail(new Error('SMTP connection closed')));
  }

  fail(err) {
    this.error = this.error || err;
    for (const w of this.waiters.splice(0)) w.reject(this.error);
  }

  // A reply is one or more lines "250-text" ... "250 text".
  flush() {
    for (;;) {
      const lines = this.buffer.split('\r\n');
      const done = lines.findIndex((l) => /^\d{3} /.test(l) || /^\d{3}$/.test(l));
      if (done < 0 || !this.waiters.length) return;
      const take = lines.slice(0, done + 1);
      this.buffer = lines.slice(done + 1).join('\r\n');
      this.waiters.shift().resolve({ code: Number(take[done].slice(0, 3)), lines: take });
    }
  }

  reply() {
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.flush();
    });
  }

  async cmd(line, ok) {
    if (this.error) throw this.error;
    if (line !== null) this.socket.write(`${line}\r\n`);
    const r = await this.reply();
    if (!ok.includes(r.code)) throw new Error(`SMTP ${r.code}: ${r.lines[r.lines.length - 1].slice(4)}`);
    return r;
  }
}

function connect(mail) {
  return new Promise((resolve, reject) => {
    const socket = mail.secure === 'tls'
      ? tls.connect({ host: mail.host, port: mail.port, servername: mail.host }, () => resolve(socket))
      : net.connect({ host: mail.host, port: mail.port }, () => resolve(socket));
    socket.once('error', reject);
  });
}

/**
 * Send one plain-text message. Throws on any failure.
 * @param {{ to: string, subject: string, text: string }} message
 */
export async function sendMail({ to, subject, text }, mail = config.mail) {
  if (!mail.enabled) throw new Error('Mail is not configured.');
  const from = addr(mail.from);
  const rcpt = addr(to);
  const socket = await connect(mail);
  let s = new Session(socket);
  const hello = `flawradar.${(config.baseUrl.match(/\/\/([^/:]+)/) || [])[1] || 'local'}`;
  try {
    await s.cmd(null, [220]);
    let ehlo = await s.cmd(`EHLO ${hello}`, [250]);
    if (mail.secure === 'starttls') {
      await s.cmd('STARTTLS', [220]);
      socket.removeAllListeners('data');
      const upgraded = tls.connect({ socket, servername: mail.host });
      await new Promise((resolve, reject) => {
        upgraded.once('secureConnect', resolve);
        upgraded.once('error', reject);
      });
      s = new Session(upgraded);
      ehlo = await s.cmd(`EHLO ${hello}`, [250]);
    }
    if (mail.user) {
      const mech = ehlo.lines.join(' ');
      if (/AUTH[^\r\n]*PLAIN/i.test(mech)) await s.cmd(`AUTH PLAIN ${b64(`\0${mail.user}\0${mail.pass}`)}`, [235]);
      else {
        await s.cmd('AUTH LOGIN', [334]);
        await s.cmd(b64(mail.user), [334]);
        await s.cmd(b64(mail.pass), [235]);
      }
    }
    await s.cmd(`MAIL FROM:<${from}>`, [250]);
    await s.cmd(`RCPT TO:<${rcpt}>`, [250, 251]);
    await s.cmd('DATA', [354]);
    const body = String(text).replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
    const msg = [
      `From: FlawRadar <${from}>`,
      `To: <${rcpt}>`,
      `Subject: ${clean(subject)}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${Date.now().toString(36)}.${Math.random().toString(36).slice(2)}@${hello}>`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: 8bit',
      'Auto-Submitted: auto-generated',
      '',
      body,
      '.',
    ].join('\r\n');
    await s.cmd(msg, [250]);
    try {
      await s.cmd('QUIT', [221]);
    } catch {
      /* the message was accepted; a bad goodbye does not matter */
    }
  } finally {
    s.socket.destroy();
  }
}
