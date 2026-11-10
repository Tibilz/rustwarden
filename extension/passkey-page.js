// Läuft im Kontext der Webseite: fängt WebAuthn-Aufrufe ab und reicht sie an RustWarden weiter.
// Hat RustWarden nichts Passendes (oder ist die Funktion aus), läuft der Aufruf unverändert zu Safari durch.
(() => {
  'use strict';
  const nc = navigator.credentials;
  if (!nc || !window.PublicKeyCredential || window.__rustwardenPasskeys) return;
  Object.defineProperty(window, '__rustwardenPasskeys', { value: true });

  const enc = (b) => {
    const u = b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    let s = '';
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const dec = (s) => {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u.buffer;
  };

  const native = { create: nc.create.bind(nc), get: nc.get.bind(nc) };
  const waiting = new Map();
  let seq = 0;
  addEventListener('message', (e) => {
    if (e.source !== window || !e.data || e.data.rwpk !== 'res') return;
    const done = waiting.get(e.data.n);
    if (done) {
      waiting.delete(e.data.n);
      done(e.data.r);
    }
  });
  const ask = (kind, options) =>
    new Promise((resolve) => {
      const n = ++seq;
      waiting.set(n, resolve);
      postMessage({ rwpk: 'req', n, kind, options }, location.origin);
    });

  const def = (o, k, v) => Object.defineProperty(o, k, { value: v, enumerable: true });
  function build(c) {
    const create = c.type === 'create';
    const proto = create ? window.AuthenticatorAttestationResponse : window.AuthenticatorAssertionResponse;
    const resp = Object.create(proto ? proto.prototype : Object.prototype);
    def(resp, 'clientDataJSON', dec(c.clientDataJSON));
    const json = { clientDataJSON: c.clientDataJSON };
    if (create) {
      def(resp, 'attestationObject', dec(c.attestationObject));
      def(resp, 'getAuthenticatorData', () => dec(c.authenticatorData));
      def(resp, 'getPublicKey', () => dec(c.publicKey));
      def(resp, 'getPublicKeyAlgorithm', () => -7);
      def(resp, 'getTransports', () => ['internal']);
      Object.assign(json, {
        attestationObject: c.attestationObject,
        authenticatorData: c.authenticatorData,
        publicKey: c.publicKey,
        publicKeyAlgorithm: -7,
        transports: ['internal'],
      });
    } else {
      def(resp, 'authenticatorData', dec(c.authenticatorData));
      def(resp, 'signature', dec(c.signature));
      def(resp, 'userHandle', c.userHandle ? dec(c.userHandle) : null);
      Object.assign(json, { authenticatorData: c.authenticatorData, signature: c.signature, userHandle: c.userHandle || undefined });
    }
    const ext = c.credProps ? { credProps: { rk: true } } : {};
    const cred = Object.create(window.PublicKeyCredential.prototype);
    def(cred, 'id', c.id);
    def(cred, 'rawId', dec(c.id));
    def(cred, 'type', 'public-key');
    def(cred, 'authenticatorAttachment', 'platform');
    def(cred, 'response', resp);
    def(cred, 'getClientExtensionResults', () => ext);
    def(cred, 'toJSON', () => ({
      id: c.id,
      rawId: c.id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: ext,
      response: json,
    }));
    return cred;
  }

  async function run(kind, o, options) {
    let r;
    try {
      r = await ask(kind, options);
    } catch {
      r = null;
    }
    if (!r || r.fallback || !r.credential) {
      if (r && r.error) throw new DOMException('Der Vorgang wurde abgebrochen oder ist nicht zulässig.', r.error);
      return native[kind](o);
    }
    return build(r.credential);
  }

  nc.create = function (o) {
    const pk = o && o.publicKey;
    try {
      if (!pk || !pk.user || !pk.challenge) return native.create(o);
      return run('create', o, {
        rp: { id: pk.rp && pk.rp.id, name: pk.rp && pk.rp.name },
        user: { id: enc(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
        challenge: enc(pk.challenge),
        pubKeyCredParams: (pk.pubKeyCredParams || []).map((p) => ({ type: p.type, alg: p.alg })),
        excludeCredentials: (pk.excludeCredentials || []).map((c) => enc(c.id)),
        credProps: !!(pk.extensions && pk.extensions.credProps),
      });
    } catch {
      return native.create(o);
    }
  };

  nc.get = function (o) {
    const pk = o && o.publicKey;
    try {
      // "conditional" (Passkey-Vorschläge im Autofill) bleibt bei Safari.
      if (!pk || !pk.challenge || o.mediation === 'conditional') return native.get(o);
      return run('get', o, {
        rpId: pk.rpId,
        challenge: enc(pk.challenge),
        allowCredentials: (pk.allowCredentials || []).map((c) => enc(c.id)),
      });
    } catch {
      return native.get(o);
    }
  };
})();
