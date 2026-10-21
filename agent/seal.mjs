// --- GitHub Tunnel runner: seal the session for the one client that dispatched it ---
// The opening half, and why a public key in the dispatch inputs replaces a repo secret, is in
// ../gt-session-crypto.js. Keep INFO and ALG identical to that file.
import crypto from 'node:crypto';

export const INFO = 'mlmvpn-gt-session-v2';
export const ALG = 'x25519-hkdf-sha256-aes256gcm';

const b64u = (buf) => Buffer.from(buf).toString('base64url');

export function seal(clientPubRaw, sessionId, payload) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(String(clientPubRaw || ''))) throw new Error('client_pub is not a raw X25519 key');
    const clientPub = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: clientPubRaw }, format: 'jwk' });
    const eph = crypto.generateKeyPairSync('x25519');
    const epk = eph.publicKey.export({ format: 'jwk' }).x;

    const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: clientPub });
    const salt = Buffer.concat([Buffer.from(epk, 'base64url'), Buffer.from(clientPubRaw, 'base64url')]);
    const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from(INFO), 32));
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(`${INFO}|${sessionId}`));
    const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(payload), 'utf8')), cipher.final(), cipher.getAuthTag()]);
    return { v: 2, alg: ALG, sid: sessionId, epk, iv: b64u(iv), ct: b64u(ct) };
}
