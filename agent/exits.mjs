// --- GitHub Tunnel v2: the EXIT BROKER — which country the traffic leaves from ---
//
// Pushed beside gt-agent.mjs (agent/exits.mjs). The user asked for the exit country to be chosen
// ON THE SERVER and never as a tunnel inside a tunnel on their PC: the client keeps its ONE tunnel
// to this runner, and a second hop, when there is one, starts here.
//
//   «حداکثر سرعت» — the runner's own address (the `direct` user). Nothing here is involved.
//   a country     — an EXIT SLOT: x1…x6, each its own VLESS user on the main Xray (so choosing it
//                   is purely the client's choice of user id — no new session, no reconnect of the
//                   tunnel), routed to a local SOCKS port 21101…21106. Behind that port runs a small
//                   Xray of its own, restartable without touching the main one, that sends the
//                   traffic out through the provider:
//      vpngate  — OpenVPN to a volunteer VPN Gate server of that country (measured 2026-09-23 from
//                 a runner: JP 97, KR 72/81 Mbit/s, up in 3 s). Policy-routed: the exit Xray binds
//                 its sockets to the tun DEVICE (SO_BINDTODEVICE — the spike's `curl --interface`),
//                 `ip rule oif <tun>` sends them into it, and nothing else on the runner is touched
//                 (--route-nopull). By device, not by address: two VPN Gate servers can hand out the
//                 same private address. TCP and UDP. Servers differ ~20× in speed (61 vs 3.5 Mbit/s
//                 measured for Japan on one day), so they are searched in parallel batches from both
//                 of VPN Gate's rankings and the fastest kept (see viaVpngate).
//      psiphon  — psiphon-tunnel-core with EgressRegion (dozens of countries). TCP only: its SOCKS
//                 has no UDP, so that slot's UDP leaves from the runner — and the panel says so.
//
// Asked for through the status channel (xray-config.mjs): `GET /x?cc=JP[&provider=psiphon]` starts
// a slot, `GET /x/stop?id=x1` frees one. Progress is published like everything else (a new rev).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const EXIT_SLOTS = 6;
export const EXIT_BASE_PORT = 21100;        // x<N> → 21100+N (the exit Xray's SOCKS)
const PSIPHON_BASE_PORT = 21200;            // x<N> → 21200+N (psiphon's own SOCKS, behind it)
const TABLE_BASE = 100;                     // x<N> → policy routing table 100+N
const PSIPHON = {
    // Psiphon-Labs/psiphon-tunnel-core-binaries @ b4c05f2c (2026-09-18) — pinned by digest.
    url: 'https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/b4c05f2ccbd9681b4e8c1b8e1479189c2583980d/linux/psiphon-tunnel-core-x86_64',
    sha256: '9b3acf07c55cc949c702065c57358323ab75efc5a0c20a460ba9e3a5bc0ecbea',
};
// The public open-source client identity and Psiphon's own server-list locations — the same the
// app's Windows engine uses (psiphon-manager.js).
const PSI_LISTS = {
    rsl: ['https://s3.amazonaws.com/psiphon/web/iohq-waa4-q4dt/server_list_compressed'],
    osl: ['https://s3.amazonaws.com/psiphon/web/iohq-waa4-q4dt/osl'],
    rslKey: 'MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=',
    entryKey: 'sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=',
    exchangeKey: 'DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU=',
};
// Psiphon's regions as the Windows engine has seen them; replaced by the core's own
// AvailableEgressRegions notice once a Psiphon slot has run here.
const PSIPHON_REGIONS_GUESS = ['AT', 'BE', 'BG', 'CA', 'CH', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FI', 'FR', 'GB', 'HU', 'IE', 'IN', 'IT', 'JP', 'LV', 'NL', 'NO', 'PL', 'RO', 'RS', 'SE', 'SG', 'SK', 'US'];
const CC = /^[A-Z]{2}$/;
const TEST_FILE = 'http://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb';

/** The exit slots' public side for the main Xray: one VLESS user and one local SOCKS port each. */
export function exitSlots(uuids) {
    return uuids.map((uuid, i) => ({ id: `x${i + 1}`, uuid, port: EXIT_BASE_PORT + i + 1 }));
}

/** The small Xray behind one slot's port. Pure, so the app's tests can check and `-test` it. */
export function buildExitXrayConfig({ port, provider, dev = '', psiphonPort = 0 }) {
    const outbounds = [];
    const rules = [];
    if (provider === 'vpngate') {
        if (!/^tun\d{1,3}$/.test(dev)) throw new Error('bad tun device');
        // Bound to the tun DEVICE: `ip rule oif <dev>` is what sends it into the tun.
        outbounds.push({ tag: 'out', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' }, streamSettings: { sockopt: { interface: dev } } });
    } else if (provider === 'psiphon') {
        outbounds.push({ tag: 'out', protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: psiphonPort }] } });
        // DNS is answered HERE, over TCP through Psiphon (the first outbound): a lookup asked over
        // UDP would otherwise leave from the runner's own address, and the names would resolve for
        // the runner's country instead of the one the user chose.
        outbounds.push({ tag: 'dns-out', protocol: 'dns' });
        rules.push({ type: 'field', network: 'udp', port: '53', outboundTag: 'dns-out' });
        // Psiphon carries no UDP: the rest of it leaves from the runner itself, and the panel says so.
        outbounds.push({ tag: 'udp-direct', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' } });
        rules.push({ type: 'field', network: 'udp', outboundTag: 'udp-direct' });
    } else {
        throw new Error(`unknown provider ${provider}`);
    }
    return {
        log: { loglevel: 'warning', access: 'none' },
        inbounds: [{ tag: 'in', listen: '127.0.0.1', port, protocol: 'socks', settings: { auth: 'noauth', udp: true, ip: '127.0.0.1' } }],
        outbounds,
        routing: { domainStrategy: 'AsIs', rules },
        ...(provider === 'psiphon' ? { dns: { servers: ['tcp://8.8.8.8:53', 'tcp://1.1.1.1:53'], queryStrategy: 'UseIPv4' } } : {}),
    };
}

/** VPN Gate's public list → { CC: [candidate…] }, best first. Pure (the app's tests feed it). */
export function parseVpngate(csv) {
    const byCc = {};
    for (const line of String(csv || '').split(/\r?\n/)) {
        if (!line || line.startsWith('*') || line.startsWith('#')) continue;
        const f = line.split(',');
        if (f.length < 15) continue;
        const [host, ip, score, ping, speed, , cc] = f;
        const cfg = f[14];
        if (!CC.test(cc) || !cfg || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) continue;
        (byCc[cc] = byCc[cc] || []).push({ host, ip, score: +score || 0, ping: +ping || 0, speed: +speed || 0, cfg });
    }
    // VPN Gate's own quality score first (uptime, load), the self-reported line speed second —
    // measured 2026-09-24: the fastest-LISTED Japanese servers refused a runner outright.
    for (const cc of Object.keys(byCc)) byCc[cc].sort((a, b) => b.score - a.score || b.speed - a.speed);
    return byCc;
}

export function createExitBroker({ work, log, sleep, pexec, xrayBin, fetchPinned, onChange, ownIp = () => '' }) {
    const slots = [];
    const catalog = { vpngate: {}, psiphon: PSIPHON_REGIONS_GUESS.slice(), at: 0, psiphonSeen: false };
    let vpngateList = {};
    let openvpnReady = null;
    let psiphonBin = null;
    const changed = () => { try { onChange && onChange(); } catch (e) {} };

    function init(uuids) {
        for (const s of exitSlots(uuids)) {
            slots.push({ ...s, n: slots.length + 1, state: 'idle', country: '', provider: '', ip: '', city: '', mbps: 0, rttMs: 0, udp: false, error: '', since: 0, busy: false, gen: 0, misses: 0 });
        }
    }

    async function refreshCatalog() {
        try {
            const res = await fetch('http://www.vpngate.net/api/iphone/', { signal: AbortSignal.timeout(20000) });
            vpngateList = parseVpngate(await res.text());
            catalog.vpngate = Object.fromEntries(Object.entries(vpngateList).map(([cc, l]) => [cc, l.length]));
            catalog.at = Date.now();
            log(`exits: VPN Gate lists ${Object.keys(vpngateList).length} countries`);
            changed();
        } catch (e) { log(`exits: VPN Gate list failed: ${e.message}`); }
    }

    // ── plumbing ──
    function ensureOpenvpn() {
        if (!openvpnReady) {
            openvpnReady = (async () => {
                let have = false;
                try { await pexec('which', ['openvpn']); have = true; } catch (e) { /* install */ }
                if (!have) {
                    try { await pexec('sudo', ['apt-get', 'install', '-y', '-qq', 'openvpn'], { timeout: 180000 }); }
                    catch (e) {
                        await pexec('sudo', ['apt-get', 'update', '-qq'], { timeout: 180000 });
                        await pexec('sudo', ['apt-get', 'install', '-y', '-qq', 'openvpn'], { timeout: 180000 });
                    }
                }
                // Binding a socket to a device (SO_BINDTODEVICE) needs CAP_NET_RAW; the exit Xray
                // gets it as a file capability, instead of running as root.
                await pexec('sudo', ['setcap', 'cap_net_raw+ep', xrayBin], { timeout: 30000 });
                return true;
            })().catch((e) => { openvpnReady = null; throw e; });
        }
        return openvpnReady;
    }
    async function ensurePsiphon() {
        if (!psiphonBin) {
            const f = await fetchPinned(PSIPHON);
            fs.chmodSync(f, 0o755);
            psiphonBin = f;
        }
        return psiphonBin;
    }
    const sudo = (args, opts = {}) => pexec('sudo', args, { timeout: 30000, ...opts });
    async function curlJson(port, url) {
        try {
            const { stdout } = await pexec('curl', ['-s', '--max-time', '12', '--socks5-hostname', `127.0.0.1:${port}`, url], { timeout: 15000 });
            return JSON.parse(stdout);
        } catch (e) { return null; }
    }
    /** Mbit/s through the slot's own port, from the first byte, over ~6 s. */
    async function speedOf(port) {
        try {
            const { stdout } = await pexec('curl', ['-s', '-o', '/dev/null', '--max-time', '7', '-r', '0-40000000', '-w', '%{size_download} %{time_starttransfer} %{time_total}',
                '--socks5-hostname', `127.0.0.1:${port}`, TEST_FILE], { timeout: 10000 }).catch((e) => ({ stdout: e.stdout || '' }));
            const [bytes, ttfb, total] = String(stdout).trim().split(/\s+/).map(Number);
            const secs = Math.max(0.5, (total || 0) - (ttfb || 0));
            return bytes > 65536 ? +(bytes * 8 / secs / 1e6).toFixed(1) : 0;
        } catch (e) { return 0; }
    }
    async function rttOf(port) {
        const t = Date.now();
        try {
            await pexec('curl', ['-s', '-o', '/dev/null', '--max-time', '8', '--socks5-hostname', `127.0.0.1:${port}`, 'http://clients3.google.com/generate_204'], { timeout: 10000 });
            return Date.now() - t;
        } catch (e) { return 0; }
    }
    function startExitXray(slot, cfg) {
        const file = path.join(work, `exit-${slot.id}.json`);
        fs.writeFileSync(file, JSON.stringify(cfg));
        const out = fs.openSync(path.join(work, `exit-${slot.id}.log`), 'a');
        const p = spawn(xrayBin, ['run', '-c', file], { stdio: ['ignore', out, out] });
        p.on('exit', (code) => log(`exit ${slot.id} xray exited (${code})`));
        return p;
    }

    async function teardown(slot) {
        const h = slot.h || {};
        slot.h = null;
        for (const p of [h.xray, h.psiphon]) { try { if (p && p.exitCode === null) p.kill('SIGKILL'); } catch (e) {} }
        if (h.pidFile) { try { const pid = (await sudo(['cat', h.pidFile])).stdout.trim(); if (/^\d+$/.test(pid)) await sudo(['kill', pid]); } catch (e) {} }
        if (h.dev) { try { await sudo(['ip', 'rule', 'del', 'oif', h.dev, 'lookup', h.table || String(TABLE_BASE + slot.n)]); } catch (e) {} }
    }

    // ── the providers ──
    /**
     * One VPN Gate server brought up on its own tun device and policy table, and measured through
     * that device from here (address, country, speed, delay). Returns the handle to keep or drop.
     */
    async function tryVpngate(slot, c, lane) {
        const dev = `tun${10 + lane * 10 + slot.n}`;
        const table = String(TABLE_BASE + lane * 10 + slot.n);
        const base = path.join(work, `vg-${slot.id}-${lane}`);
        const h = { dev, table, pidFile: `${base}.pid` };
        fs.writeFileSync(`${base}.ovpn`, Buffer.from(c.cfg, 'base64'));
        // VPN Gate's published login for OpenVPN (some servers answer AUTH_FAILED without it).
        fs.writeFileSync(`${base}.auth`, 'vpn\nvpn\n', { mode: 0o600 });
        try {
            await sudo(['openvpn', '--config', `${base}.ovpn`, '--auth-user-pass', `${base}.auth`, '--auth-nocache', '--route-nopull', '--pull-filter', 'ignore', 'route-ipv6', '--pull-filter', 'ignore', 'ifconfig-ipv6',
                '--dev', dev, '--dev-type', 'tun',
                '--data-ciphers', 'AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC', '--data-ciphers-fallback', 'AES-128-CBC',
                '--connect-retry-max', '1', '--connect-timeout', '10', '--log', `${base}.log`, '--writepid', h.pidFile, '--daemon']);
            // openvpn runs as root and writes its log 0600 — read it with sudo (the spike's lesson).
            let up = false;
            let gaveUp = false;
            for (let i = 0; i < 30 && !up && !gaveUp; i++) {
                await sleep(1000);
                const text = (await sudo(['cat', `${base}.log`]).catch(() => ({ stdout: '' }))).stdout || '';
                up = /Initialization Sequence Completed/.test(text);
                // OpenVPN has already said it is done: no point waiting out the rest of 30 s.
                gaveUp = !up && /Exiting due to fatal error|AUTH_FAILED|process exiting/i.test(text);
            }
            if (!up) {
                // OpenVPN's own last words, not a guess: the reason goes into the slot's error.
                const tail = ((await sudo(['cat', `${base}.log`]).catch(() => ({ stdout: '' }))).stdout || '')
                    .split('\n').map((l) => l.replace(/^\S+ \S+ \S+ \S+ \S+ /, '').trim())
                    .filter((l) => l && !/^(OpenVPN|library versions|WARNING: --|DEPRECATED)/i.test(l)).slice(-2).join(' | ');
                throw new Error(`${gaveUp ? 'refused' : 'did not come up in 30 s'}${tail ? ` (${tail.slice(0, 140)})` : ''}`);
            }
            await sudo(['ip', 'route', 'replace', 'default', 'dev', dev, 'table', table]);
            await sudo(['ip', 'rule', 'add', 'oif', dev, 'lookup', table, 'priority', String(1000 + lane * 10 + slot.n)]);
            const viaDev = ['--interface', dev];
            let geo = null;
            try { geo = JSON.parse((await pexec('curl', ['-s', '--max-time', '12', ...viaDev, 'http://ip-api.com/json/?fields=status,countryCode,city,query'], { timeout: 15000 })).stdout); } catch (e) { geo = null; }
            if (!geo || geo.status !== 'success') throw new Error('no traffic through it');
            const t = Date.now();
            let rttMs = 0;
            try { await pexec('curl', ['-s', '-o', '/dev/null', '--max-time', '8', ...viaDev, 'http://clients3.google.com/generate_204'], { timeout: 10000 }); rttMs = Date.now() - t; } catch (e) { rttMs = 0; }
            let mbps = 0;
            try {
                const out = (await pexec('curl', ['-s', '-o', '/dev/null', '--max-time', '7', '-r', '0-40000000', '-w', '%{size_download} %{time_starttransfer} %{time_total}', ...viaDev, TEST_FILE], { timeout: 10000 }).catch((e) => ({ stdout: e.stdout || '' }))).stdout;
                const [bytes, ttfb, total] = String(out).trim().split(/\s+/).map(Number);
                mbps = bytes > 65536 ? +(bytes * 8 / Math.max(0.5, (total || 0) - (ttfb || 0)) / 1e6).toFixed(1) : 0;
            } catch (e) { mbps = 0; }
            return { h, c, geo, rttMs, mbps };
        } catch (e) {
            await dropVpngate(h);
            throw e;
        }
    }
    async function dropVpngate(h) {
        if (!h) return;
        try { const pid = (await sudo(['cat', h.pidFile])).stdout.trim(); if (/^\d+$/.test(pid)) await sudo(['kill', pid]); } catch (e) {}
        try { await sudo(['ip', 'rule', 'del', 'oif', h.dev, 'lookup', h.table]); } catch (e) {}
    }

    // Good enough to stop looking, and how long a search may take (it runs at boot, before the
    // client asks — measured: one JP server gave 61 Mbit/s, another from the same list 3.5).
    const VPNGATE_GOOD_MBPS = 15;
    const VPNGATE_SEARCH_MS = 90000;

    /**
     * Candidates from BOTH of VPN Gate's rankings, alternating: its quality score (reliable, often
     * crowded) and the listed line speed (fast when it answers, refused more often).
     */
    // VPN Gate servers caught leaking this session (cc → hosts): picked again they leak again — the
    // same fastest server came back after a rebuild and leaked within 13 minutes (2026-09-24).
    const avoided = new Map();
    function avoid(slot) {
        if (slot.provider !== 'vpngate' || !slot.server || !slot.country) return;
        if (!avoided.has(slot.country)) avoided.set(slot.country, new Set());
        avoided.get(slot.country).add(slot.server);
        log(`exit ${slot.id}: VPN Gate ${slot.country} server ${slot.server} is not used again this session`);
    }

    function vpngateCandidates(cc, max = 12) {
        const skip = avoided.get(cc) || new Set();
        const list = (vpngateList[cc] || []).filter((c) => !skip.has(c.host));
        const byScore = list.slice().sort((a, b) => b.score - a.score || b.speed - a.speed);
        const bySpeed = list.slice().sort((a, b) => b.speed - a.speed || b.score - a.score);
        const out = [];
        for (let i = 0; out.length < max && (i < byScore.length || i < bySpeed.length); i++) {
            for (const c of [byScore[i], bySpeed[i]]) if (c && !out.includes(c) && out.length < max) out.push(c);
        }
        return out;
    }

    async function viaVpngate(slot, cc) {
        await ensureOpenvpn();
        const cands = vpngateCandidates(cc);
        if (!cands.length) throw new Error(`VPN Gate has no server in ${cc}`);
        const deadline = Date.now() + VPNGATE_SEARCH_MS;
        let best = null;
        let lastErr = null;
        let next = 0;
        // Batches of up to three in parallel, each on a lane the kept best is not using; the fastest
        // answer so far is kept (speed, then delay) and the search stops once it is good enough.
        while (next < cands.length && Date.now() < deadline && !(best && best.mbps >= VPNGATE_GOOD_MBPS)) {
            const lanes = [0, 1, 2, 3].filter((l) => !best || best.lane !== l).slice(0, 3);
            const batch = cands.slice(next, next + lanes.length);
            const first = next;
            next += batch.length;
            const got = await Promise.all(batch.map((c, i) => tryVpngate(slot, c, lanes[i])
                .then((r) => ({ ...r, lane: lanes[i] }))
                .catch((e) => { lastErr = e; log(`exit ${slot.id}: VPN Gate ${cc} #${first + i + 1} failed: ${String(e.message || e).slice(0, 110)}`); return null; })));
            for (const r of got.filter(Boolean)) {
                const better = !best || r.mbps > best.mbps || (r.mbps === best.mbps && (r.rttMs || 1e9) < (best.rttMs || 1e9));
                if (better) {
                    if (best) { log(`exit ${slot.id}: VPN Gate ${cc}: ${r.mbps} Mbit/s ${r.rttMs} ms beats ${best.mbps} Mbit/s`); await dropVpngate(best.h); }
                    best = r;
                } else {
                    await dropVpngate(r.h);
                }
            }
        }
        if (!best) throw lastErr || new Error('no VPN Gate server answered');
        slot.h = { ...best.h };
        slot.h.xray = startExitXray(slot, buildExitXrayConfig({ port: slot.port, provider: 'vpngate', dev: best.h.dev }));
        await sleep(700);
        const geo = await curlJson(slot.port, 'http://ip-api.com/json/?fields=status,countryCode,city,query');
        if (!geo || geo.status !== 'success') { await teardown(slot); throw new Error('no traffic through the exit'); }
        return { ip: geo.query, country: geo.countryCode, city: geo.city || '', udp: true, server: best.c.host };
    }

    async function viaPsiphon(slot, cc) {
        const bin = await ensurePsiphon();
        const dir = path.join(work, `psi-${slot.id}`);
        fs.mkdirSync(path.join(dir, 'osl'), { recursive: true });
        const b64 = (u) => Buffer.from(u, 'utf8').toString('base64');
        const psPort = PSIPHON_BASE_PORT + slot.n;
        const cfg = {
            PropagationChannelId: 'FFFFFFFFFFFFFFFF', SponsorId: '1111111111111111', ClientVersion: '1',
            EgressRegion: cc, EstablishTunnelTimeoutSeconds: 0, DataRootDirectory: dir,
            LocalSocksProxyPort: psPort, LocalHttpProxyPort: psPort + 50,
            RemoteServerListURLs: PSI_LISTS.rsl.map((u) => ({ URL: b64(u), SkipVerify: false, OnlyAfterAttempts: 0 })),
            RemoteServerListDownloadFilename: path.join(dir, 'remote_server_list'),
            ObfuscatedServerListRootURLs: PSI_LISTS.osl.map((u) => ({ URL: b64(u), SkipVerify: false, OnlyAfterAttempts: 0 })),
            ObfuscatedServerListDownloadDirectory: path.join(dir, 'osl'),
            RemoteServerListSignaturePublicKey: PSI_LISTS.rslKey, ServerEntrySignaturePublicKey: PSI_LISTS.entryKey,
            ExchangeObfuscationKey: PSI_LISTS.exchangeKey,
        };
        const cfgFile = path.join(dir, 'config.json');
        fs.writeFileSync(cfgFile, JSON.stringify(cfg));
        const p = spawn(bin, ['-config', cfgFile], { stdio: ['ignore', 'ignore', 'pipe'] });
        slot.h = { psiphon: p };
        let tunnels = 0;
        let buf = '';
        p.stderr.on('data', (d) => {
            buf += d;
            let i;
            while ((i = buf.indexOf('\n')) >= 0) {
                const line = buf.slice(0, i); buf = buf.slice(i + 1);
                try {
                    const n = JSON.parse(line);
                    if (n.noticeType === 'Tunnels') tunnels = n.data && n.data.count || 0;
                    if (n.noticeType === 'AvailableEgressRegions' && n.data && Array.isArray(n.data.regions) && n.data.regions.length) {
                        catalog.psiphon = n.data.regions.filter((r) => CC.test(r)).sort();
                        catalog.psiphonSeen = true;
                    }
                } catch (e) { /* not a notice */ }
            }
        });
        for (let s = 0; s < 90 && tunnels < 1; s++) {
            if (p.exitCode !== null) throw new Error('psiphon exited');
            await sleep(1000);
        }
        if (tunnels < 1) throw new Error(`Psiphon found no ${cc} server in 90 s`);
        slot.h.xray = startExitXray(slot, buildExitXrayConfig({ port: slot.port, provider: 'psiphon', psiphonPort: psPort }));
        await sleep(700);
        const geo = await curlJson(slot.port, 'http://ip-api.com/json/?fields=status,countryCode,city,query');
        if (!geo || geo.status !== 'success') throw new Error('no traffic through it');
        return { ip: geo.query, country: geo.countryCode, city: geo.city || '', udp: false, server: 'psiphon' };
    }

    async function bring(slot, cc, provider, auto = slot.auto) {
        const gen = ++slot.gen;
        Object.assign(slot, { state: 'starting', country: cc, provider, auto: !!auto, ip: '', city: '', mbps: 0, rttMs: 0, udp: false, error: '', since: Date.now(), busy: true, misses: 0 });
        changed();
        try {
            let r;
            if (provider === 'psiphon') r = await viaPsiphon(slot, cc);
            else {
                try {
                    r = await viaVpngate(slot, cc);
                } catch (e) {
                    // VPN Gate is volunteers: a country's servers can all be down at once (measured:
                    // every JP one at one moment, KR fine). Asked for the COUNTRY without a provider,
                    // the same country through Psiphon is a better answer than none — said in the log
                    // and visible in the slot's provider (TCP only).
                    if (slot.auto && catalog.psiphon.includes(cc) && gen === slot.gen) {
                        log(`exit ${slot.id}: VPN Gate ${cc} failed (${String(e.message || e).slice(0, 100)}); trying Psiphon for ${cc}`);
                        await teardown(slot);
                        slot.provider = 'psiphon';
                        changed();
                        try {
                            r = await viaPsiphon(slot, cc);
                        } catch (e2) {
                            // Both said no: both reasons, so the panel does not blame the wrong one.
                            throw new Error(`VPN Gate: ${String(e.message || e).slice(0, 90)} — Psiphon: ${String(e2.message || e2).slice(0, 70)}`);
                        }
                    } else throw e;
                }
            }
            if (gen !== slot.gen) return;           // stopped or re-asked meanwhile
            const [mbps, rttMs] = [await speedOf(slot.port), await rttOf(slot.port)];
            Object.assign(slot, { state: 'ready', ip: r.ip, city: r.city, udp: r.udp, mbps, rttMs, busy: false,
                // The address's own country, as the far side sees it — not the provider's label.
                seenCountry: r.country || '', server: r.server || '' });
            log(`exit ${slot.id}: ${provider} ${cc} ready — ${mbps} Mbit/s, ${rttMs} ms${r.country && r.country !== cc ? ` (seen as ${r.country})` : ''}`);
        } catch (e) {
            if (gen !== slot.gen) return;
            await teardown(slot);
            Object.assign(slot, { state: 'failed', error: String(e.message || e).slice(0, 160), busy: false });
            log(`exit ${slot.id}: ${provider} ${cc} failed: ${slot.error}`);
        }
        changed();
    }

    /** Start (or reuse) an exit for a country. Returns the slot's public view, or throws. */
    function request(ccRaw, providerRaw = '') {
        const cc = String(ccRaw || '').toUpperCase();
        if (!CC.test(cc)) throw Object.assign(new Error('bad country'), { status: 400 });
        // No provider named: the best this runner has — VPN Gate where it lists the country,
        // Psiphon otherwise — and Psiphon again if VPN Gate's servers all fail (see bring).
        const auto = !(providerRaw === 'psiphon' || providerRaw === 'vpngate');
        const provider = !auto ? providerRaw : (vpngateList[cc] && vpngateList[cc].length ? 'vpngate' : 'psiphon');
        const have = slots.find((s) => s.country === cc && (auto ? s.auto || s.provider === provider : s.provider === provider) && (s.state === 'ready' || s.state === 'starting'));
        if (have) return view(have);
        const free = slots.find((s) => s.state === 'idle' || s.state === 'failed');
        if (!free) throw Object.assign(new Error('every exit slot is in use — free one first'), { status: 409 });
        bring(free, cc, provider, auto).catch(() => {});
        return view(free);
    }

    /** `leak`: the client saw this exit leaving from the runner's own address — its server is avoided. */
    async function stop(id, { leak = false } = {}) {
        const slot = slots.find((s) => s.id === id);
        if (!slot) throw Object.assign(new Error('no such exit'), { status: 404 });
        if (leak) { log(`exit ${slot.id}: the client saw it leave from this runner's own address`); avoid(slot); }
        slot.gen++;
        await teardown(slot);
        Object.assign(slot, { state: 'idle', country: '', provider: '', ip: '', city: '', mbps: 0, rttMs: 0, udp: false, error: '', busy: false, server: '' });
        changed();
        return view(slot);
    }

    /**
     * Where a READY exit really leaves from now — '' when that is where it should, or why not.
     * Carrying data is not the same as carrying it out of the right place: measured 2026-09-24, a
     * VPN Gate JP exit stayed 'ready' for minutes while every byte through it left from this
     * runner's own Azure address, and the plain liveness probe (rttOf) was happy throughout. No
     * answer is not a verdict here — liveness is rttOf's call.
     */
    async function leakOf(slot) {
        const geo = await curlJson(slot.port, 'http://ip-api.com/json/?fields=status,countryCode,query');
        if (!geo || geo.status !== 'success') return '';
        const own = ownIp();
        if (own && geo.query === own) return `leaves from this runner's own address`;
        if (slot.seenCountry && geo.countryCode && geo.countryCode !== slot.seenCountry) return `now leaves from ${geo.countryCode} (${geo.query}), not ${slot.seenCountry}`;
        return '';
    }

    /** The state of a VPN Gate exit's plumbing, one line, for the log when it misbehaves. */
    async function describeTunnel(slot) {
        const h = slot.h || {};
        if (!h.dev) return '';
        const out = [];
        try { out.push((await sudo(['ip', '-o', 'link', 'show', 'dev', h.dev])).stdout.trim().replace(/\s+/g, ' ').slice(0, 120)); } catch (e) { out.push(`${h.dev}: gone`); }
        try { out.push(`table ${h.table}: ${(await sudo(['ip', 'route', 'show', 'table', h.table])).stdout.trim().replace(/\s+/g, ' ') || 'empty'}`); } catch (e) {}
        try { out.push(`rule: ${(await sudo(['ip', 'rule', 'show', 'oif', h.dev])).stdout.trim().replace(/\s+/g, ' ') || 'none'}`); } catch (e) {}
        if (h.pidFile) {
            try {
                const tail = (await sudo(['tail', '-n', '3', h.pidFile.replace(/\.pid$/, '.log')])).stdout.trim().split('\n')
                    .map((l) => l.replace(/^\S+ \S+ \S+ \S+ \S+ /, '').trim()).join(' | ');
                out.push(`openvpn: ${tail.slice(0, 240)}`);
            } catch (e) {}
        }
        return out.join(' ; ');
    }

    /** Every minute: an exit leaving from the wrong place is rebuilt at once; one that stops carrying data, after two misses. */
    async function supervise() {
        for (const slot of slots) {
            if (slot.state !== 'ready' || slot.busy) continue;
            const ok = (await rttOf(slot.port)) > 0;
            const leak = ok ? await leakOf(slot) : '';
            if (ok && !leak) { slot.misses = 0; continue; }
            if (!leak && ++slot.misses < 2) continue;
            log(`exit ${slot.id}: ${leak || 'stopped carrying data'}; bringing ${slot.country} up again`);
            if (leak) {
                // Why, for the next person reading this log — then never that server again.
                const d = await describeTunnel(slot).catch(() => '');
                if (d) log(`exit ${slot.id}: ${d}`);
                avoid(slot);
            }
            await teardown(slot);
            bring(slot, slot.country, slot.provider).catch(() => {});
        }
    }

    function view(s) {
        return { id: s.id, state: s.state, country: s.country, provider: s.provider, ip: s.ip, city: s.city,
            seenCountry: s.seenCountry || '', mbps: s.mbps, rttMs: s.rttMs, udp: s.udp, error: s.error, since: s.since };
    }
    function publicState() {
        return {
            exits: slots.filter((s) => s.state !== 'idle').map(view),
            catalog: { vpngate: catalog.vpngate, psiphon: catalog.psiphon, psiphonSeen: catalog.psiphonSeen, at: catalog.at },
        };
    }
    async function stopAll() { for (const s of slots) { try { await teardown(s); } catch (e) {} } }

    return { init, refreshCatalog, request, stop, supervise, publicState, stopAll, slots, avoidedFor: (cc) => [...(avoided.get(cc) || [])] };
}
