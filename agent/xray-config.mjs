// --- GitHub Tunnel v2: the runner's Xray configuration ---
//
// Pushed to the user's repo beside gt-agent.mjs (agent/xray-config.mjs) and kept apart from the
// agent so the app's tests can build and validate it without running a runner.
//
//   * VLESS over WebSocket on 127.0.0.1 — the quick tunnels are the only way in;
//   * the STATUS CHANNEL: a request for STATUS_HOST from the client is redirected to the agent's
//     own status server on loopback. Any live quick tunnel reaches it, so the client learns about
//     a replaced tunnel or the session's end without asking GitHub — and without DNS, which is
//     exactly what it may not have while the kill switch holds the machine closed;
//   * this runner's own network, the cloud metadata service, BitTorrent and mail ports blocked.

export const WS_PORT = 10001;
export const STATUS_PORT = 18080;
// Not a real name and never resolved: Xray routes on the requested domain before anything
// looks it up. `.internal` is reserved for exactly this kind of private use.
export const STATUS_HOST = 'status.gt.internal';

// `exits` (runner/exits.mjs › exitSlots): one VLESS user per exit slot, each routed to its own local
// SOCKS port — so the exit country is the client's choice of USER, with no new session and no
// second tunnel on the client. A slot with nothing behind its port yet simply refuses.
export function buildXrayConfig({ uuid, wsPath, wsPort = WS_PORT, statusPort = STATUS_PORT, exits = [] }) {
    const exitOutbounds = exits.map((x) => ({ tag: `exit-${x.id}`, protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: x.port }] } }));
    const exitRules = exits.map((x) => ({ type: 'field', user: [`${x.id}@gt`], outboundTag: `exit-${x.id}` }));
    return {
        log: { loglevel: 'warning', access: 'none' },
        inbounds: [{
            tag: 'ws', listen: '127.0.0.1', port: wsPort, protocol: 'vless',
            settings: { clients: [{ id: uuid, email: 'direct@gt' }, ...exits.map((x) => ({ id: x.uuid, email: `${x.id}@gt` }))], decryption: 'none' },
            streamSettings: { network: 'ws', wsSettings: { path: wsPath } },
            sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true },
        }],
        outbounds: [
            { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' } },
            { tag: 'block', protocol: 'blackhole' },
            // The status channel's one exit: whatever port was asked for, it lands on the agent.
            // Xray 26 refuses every private target reached from a VLESS inbound on its own ("blocked
            // target … blackholing connection") — the right default for `direct`, and the reason
            // this exit needs its own rule: allow exactly the agent's port on loopback, nothing else.
            { tag: 'status', protocol: 'freedom', settings: {
                redirect: `127.0.0.1:${statusPort}`,
                finalRules: [{ action: 'allow', network: 'tcp', ip: ['127.0.0.1/32'], port: String(statusPort) }],
            } },
            ...exitOutbounds,
        ],
        routing: { domainStrategy: 'AsIs', rules: [
            // FIRST: the status channel, by name — before the private-address block, which would
            // otherwise be the right answer for anything that ends up on loopback.
            { type: 'field', domain: [`full:${STATUS_HOST}`], outboundTag: 'status' },
            // This runner's own network and the cloud metadata service are nobody's business.
            { type: 'field', ip: ['geoip:private', '169.254.169.254/32'], outboundTag: 'block' },
            // Kept off an account the user depends on: file-sharing and mail are the two uses
            // most likely to get a GitHub account flagged.
            { type: 'field', protocol: ['bittorrent'], outboundTag: 'block' },
            { type: 'field', port: '25,465,587', outboundTag: 'block' },
            // AFTER the blocks: an exit country is a different way out, never a way around them.
            ...exitRules,
        ] },
    };
}
