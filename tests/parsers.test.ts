import { describe, expect, it } from 'vitest';
import { parseLine, parseLogs } from '../src/server/engine/parsers.js';

const opts = { referenceYear: 2026 };

describe('auth log parsing', () => {
  it('parses failed passwords with syslog timestamps', () => {
    const e = parseLine(
      'Nov 18 02:05:13 web-01 sshd[4100]: Failed password for root from 203.0.113.45 port 51000 ssh2',
      1,
      opts,
    );
    expect(e).toMatchObject({
      source: 'auth',
      kind: 'auth_failure',
      user: 'root',
      srcIp: '203.0.113.45',
      host: 'web-01',
    });
    expect(e.timestamp).toBe(Date.UTC(2026, 10, 18, 2, 5, 13));
  });

  it('distinguishes invalid users', () => {
    const e = parseLine(
      'Nov 18 02:05:13 h sshd[1]: Failed password for invalid user oracle from 203.0.113.45 port 1 ssh2',
      1,
      opts,
    );
    expect(e).toMatchObject({ kind: 'invalid_user', user: 'oracle' });
    const e2 = parseLine(
      'Nov 18 02:05:13 h sshd[1]: Invalid user bob from 198.51.100.1 port 22',
      2,
      opts,
    );
    expect(e2).toMatchObject({ kind: 'invalid_user', user: 'bob', srcIp: '198.51.100.1' });
  });

  it('parses accepted logins with ISO-8601 timestamps', () => {
    const e = parseLine(
      '2026-11-18T02:09:05+00:00 web-01 sshd[9]: Accepted publickey for alice from 10.0.0.12 port 5 ssh2',
      1,
      opts,
    );
    expect(e).toMatchObject({ kind: 'auth_success', user: 'alice', srcIp: '10.0.0.12' });
    expect(e.timestamp).toBe(Date.UTC(2026, 10, 18, 2, 9, 5));
  });

  it('parses sudo, useradd and group changes', () => {
    const sudo = parseLine(
      'Nov 18 02:10:02 h sudo:   deploy : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash',
      1,
      opts,
    );
    expect(sudo).toMatchObject({
      kind: 'sudo',
      user: 'deploy',
      targetUser: 'root',
      command: '/bin/bash',
    });
    const add = parseLine(
      'Nov 18 02:10:41 h useradd[4301]: new user: name=sysupdate, UID=1002',
      2,
      opts,
    );
    expect(add).toMatchObject({ kind: 'account_created', user: 'sysupdate' });
    const grp = parseLine(
      "Nov 18 02:11:03 h usermod[4307]: add 'sysupdate' to group 'sudo'",
      3,
      opts,
    );
    expect(grp).toMatchObject({ kind: 'group_change', user: 'sysupdate', group: 'sudo' });
  });

  it('keeps unrecognised syslog lines with their timestamp', () => {
    const e = parseLine('Nov 18 02:01:00 h CRON[1]: (root) CMD (backup)', 1, opts);
    expect(e.source).toBe('unknown');
    expect(e.timestamp).not.toBeNull();
  });
});

describe('web log parsing', () => {
  it('parses combined log format and decodes the path', () => {
    const e = parseLine(
      '198.51.100.23 - - [18/Nov/2026:09:02:00 +0000] "GET /p.php?id=1%27%20OR%201=1 HTTP/1.1" 500 162 "-" "sqlmap/1.8"',
      1,
      opts,
    );
    expect(e).toMatchObject({
      source: 'web',
      kind: 'http_request',
      srcIp: '198.51.100.23',
      method: 'GET',
      status: 500,
      userAgent: 'sqlmap/1.8',
    });
    expect(e.path).toBe("/p.php?id=1' OR 1=1");
    expect(e.timestamp).toBe(Date.UTC(2026, 10, 18, 9, 2, 0));
  });

  it('handles timezone offsets and undecodable paths', () => {
    const e = parseLine(
      '192.0.2.1 - - [18/Nov/2026:14:32:00 +0530] "GET /%E0%A4%A HTTP/1.1" 404 0',
      1,
      opts,
    );
    expect(e.timestamp).toBe(Date.UTC(2026, 10, 18, 9, 2, 0));
    expect(e.path).toBe('/%E0%A4%A');
    expect(e.userAgent).toBeUndefined();
  });
});

describe('firewall log parsing', () => {
  it('parses UFW blocks with destination port', () => {
    const e = parseLine(
      'Nov 18 02:03:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.45 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=3389',
      1,
      opts,
    );
    expect(e).toMatchObject({
      source: 'firewall',
      kind: 'firewall_block',
      srcIp: '203.0.113.45',
      dstPort: 3389,
    });
  });

  it('parses UFW allows', () => {
    const e = parseLine(
      'Nov 18 02:03:00 fw kernel: [UFW ALLOW] IN=eth0 SRC=10.0.0.12 DST=10.0.0.5 PROTO=TCP DPT=22',
      1,
      opts,
    );
    expect(e.kind).toBe('firewall_allow');
  });
});

describe('parseLogs', () => {
  it('counts sources, skips blank lines and keeps 1-based line numbers', () => {
    const text = [
      'Nov 18 02:05:13 h sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2',
      '',
      'garbage line',
      '192.0.2.1 - - [18/Nov/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "ua"',
    ].join('\r\n');
    const parsed = parseLogs(text, opts);
    expect(parsed.linesTotal).toBe(3);
    expect(parsed.linesParsed).toBe(2);
    expect(parsed.bySource).toEqual({ auth: 1, web: 1, firewall: 0, unknown: 1 });
    expect(parsed.events.map((e) => e.line)).toEqual([1, 3, 4]);
  });
});
