// No packages are needed for the normal checks. To also decode every generated
// image with jsQR, set AWG_TEST_QR_DECODER to an absolute path to its CommonJS build.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { deflateSync, inflateSync } = require('node:zlib');

// Exercise the same ordinary-script form shipped in app.bundle.js, including
// on Node 18 which does not infer ES modules for .js files without package.json.
const source = ['vendor/qrcodegen.js', 'connection-qr.js'].map(file =>
  fs.readFileSync(path.join(__dirname, '../public/assets', file), 'utf8')
    .replace(/^import[^\n]+\n/gm, '')
    .replace(/^export \{[^\n]+\n/gm, '')
    .replace(/^export /gm, '')
    .replace(/[ \t]+$/gm, '')).join('\n');
const { connectionQrSvg, amneziaQrSvg } = new vm.Script(
  "(() => { 'use strict';\n" + source + '\nreturn { connectionQrSvg, amneziaQrSvg };\n})();',
  { filename: 'connection-qr.test.bundle.js' }).runInThisContext();

const config = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.0.2/32, fd00:1234::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111
Jc = 5
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 123456
H2 = 234567
H3 = 345678
H4 = 456789
I1 = <b 0x12345678>
I2 = <r 40>
I3 = <rc 20>
I4 = <t>
I5 = <r 10>

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
Endpoint = [2001:db8::10]:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
const unicodeConfig = '# Рабочий ноутбук — 東京 🔐\r\n' + config.replaceAll('\n', '\r\n');
const fallbackConfig = '# ' + 'x'.repeat(2330); // 2332 UTF-8 bytes exceed version 40 / M.
const maximumConfig = '# ' + 'x'.repeat(2951); // Maximum version 40 / L byte payload.
const fixtures = [
  ['AWG parameters and IPv6', config],
  ['Unicode comments and CRLF', unicodeConfig],
  ['LOW fallback', fallbackConfig],
  ['maximum byte payload', maximumConfig],
];

// Independently frame the official Qt wire format: qCompress bytes, split into
// 850-byte chunks; qint16 magic, quint8 total/index and a QByteArray length prefix.
function amneziaPackets(profile) {
  const json = Buffer.from(JSON.stringify(profile));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(json.length);
  const compressed = Buffer.concat([length, deflateSync(json, { level: 8 })]);
  const total = Math.ceil(compressed.length / 850);
  const packets = [];
  for (let index = 0; index < total; index++) {
    const chunk = compressed.subarray(index * 850, (index + 1) * 850);
    const header = Buffer.alloc(8);
    header.writeInt16BE(1984);
    header.writeUInt8(total, 2);
    header.writeUInt8(index, 3);
    header.writeUInt32BE(chunk.length, 4);
    packets.push(Buffer.concat([header, chunk]).toString('base64url'));
  }
  return packets;
}

const amneziaProfiles = [
  ['single Qt packet', { description: 'Рабочий ноутбук — 東京 🔐', containers: [] }],
  ['multiple Qt packets', {
    description: 'Large profile',
    // Deterministic data with enough entropy to exercise full 850-byte chunks.
    data: Array.from({ length: 100 }, (_, index) => createHash('sha256').update(`test ${index}`).digest('hex')).join(''),
  }],
];
const amneziaFixtures = amneziaProfiles.map(([name, profile]) => [name, profile, amneziaPackets(profile)]);

// Parse only the deliberately small SVG grammar returned by this feature. This
// also verifies that no text, scripts, external references or key metadata leaks.
function imageFromSvg(svg, scale = 4) {
  const match = /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" width="(\d+)" height="\1" viewBox="0 0 (\d+) \2" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"\/><path d="((?:M\d+,\d+h1v1h-1z)*)" fill="#000"\/><\/svg>$/.exec(svg);
  assert.ok(match, 'SVG must contain geometry only on an opaque white background');
  const size = Number(match[2]);
  assert.equal(Number(match[1]), size * 4, 'standalone SVG has an integer square viewport');
  const symbolSize = size - 8;
  assert.ok(symbolSize >= 21 && symbolSize <= 177 && (symbolSize - 21) % 4 === 0);
  const modules = Array.from({ length: size }, () => Array(size).fill(false));
  const rgba = new Uint8ClampedArray(size * size * scale * scale * 4).fill(255);
  const width = size * scale;
  let count = 0;
  for (const cell of match[3].matchAll(/M(\d+),(\d+)h1v1h-1z/g)) {
    const x = Number(cell[1]);
    const y = Number(cell[2]);
    assert.ok(x >= 4 && x < size - 4 && y >= 4 && y < size - 4, 'four white modules around every edge');
    assert.equal(modules[y][x], false, 'no duplicate modules');
    modules[y][x] = true;
    count++;
    for (let dy = 0; dy < scale; dy++) {
      for (let dx = 0; dx < scale; dx++) {
        const offset = ((y * scale + dy) * width + x * scale + dx) * 4;
        rgba[offset] = rgba[offset + 1] = rgba[offset + 2] = 0;
      }
    }
  }
  assert.ok(count > 0);
  // Read the first QR format-information copy, remove its fixed XOR mask,
  // and inspect the two error-correction level bits (ISO/IEC 18004).
  let format = 0;
  for (let bit = 0; bit < 15; bit++) {
    const [x, y] = bit < 6 ? [8, bit] : bit < 8 ? [8, bit + 1] : bit === 8 ? [7, 8] : [14 - bit, 8];
    if (modules[y + 4][x + 4]) format |= 1 << bit;
  }
  return { rgba, width, size, ecc: ((format ^ 0x5412) >>> 13) & 3 };
}

for (const [name, payload] of fixtures) {
  test(`connection QR preserves safe geometry: ${name}`, () => {
    const svg = connectionQrSvg(payload);
    const image = imageFromSvg(svg);
    assert.equal(svg.includes('PrivateKey'), false);
    assert.equal(svg.includes('PresharedKey'), false);
    assert.equal(svg, connectionQrSvg(payload), 'deterministic local encoding');
    if (payload === fallbackConfig || payload === maximumConfig) assert.equal(image.ecc, 1, 'LOW fallback');
    else assert.notEqual(image.ecc, 1, 'at least MEDIUM error correction');
    if (payload === maximumConfig) assert.equal(image.size, 185, 'version 40 with quiet zone');
  });
}

test('byte limit counts UTF-8 bytes and yields an actionable message', () => {
  for (const payload of ['# ' + 'x'.repeat(2952), '# ' + 'я'.repeat(1476), 'x'.repeat(1000000)]) {
    assert.throws(() => connectionQrSvg(payload), error => error instanceof RangeError && /слишком большая/.test(error.message) && /\.conf/.test(error.message));
  }
  assert.doesNotThrow(() => connectionQrSvg('# ' + 'я'.repeat(1475)));
  assert.throws(() => connectionQrSvg(null), TypeError);
});

// Stable fixtures were verified by decoding the rendered SVG with jsQR. Keep a
// fingerprint so the ordinary dependency-free suite protects the exact images.
test('verified AWG and Unicode image fixtures remain unchanged', () => {
  const hashes = [
    '2acaa1d5eff49a72097a6197713d52371050ccb5269ae4cd5cccbd8e907b595d',
    'd58b89ef3588f16b1851e887616298f1b9a9af6f85ed8a83225984e4bdf72797',
  ];
  for (let i = 0; i < 2; i++) {
    assert.equal(createHash('sha256').update(connectionQrSvg(fixtures[i][1])).digest('hex'), hashes[i]);
  }
});

for (const [name, , packets] of amneziaFixtures) {
  test(`AmneziaVPN QR preserves Qt packet and LOW geometry: ${name}`, () => {
    assert.equal(packets.length === 1, name === 'single Qt packet');
    for (const payload of packets) {
      assert.ok(payload.length <= 1144);
      const svg = amneziaQrSvg(payload);
      const image = imageFromSvg(svg);
      assert.equal(image.ecc, 1, 'LOW exactly; automatic ECC boosting is disabled');
      assert.equal(svg, amneziaQrSvg(payload), 'deterministic local encoding');
    }
  });
}

test('AmneziaVPN QR validates bounded base64url input', () => {
  for (const payload of [null, undefined, 10, {}, '', 'vpn://test', 'a+b', 'a/b', 'abc=', 'test\n', '<svg>']) {
    assert.throws(() => amneziaQrSvg(payload), TypeError);
  }
  for (const payload of ['x'.repeat(1145), 'x'.repeat(1000000)]) {
    assert.throws(() => amneziaQrSvg(payload), error => error instanceof RangeError && /\.vpn/.test(error.message));
  }
  assert.doesNotThrow(() => amneziaQrSvg('x'.repeat(1144)));
  assert.equal(imageFromSvg(amneziaQrSvg('AAAA')).ecc, 1, 'even small packets keep LOW');
});

test('independent decoder recovers the entire configuration byte for byte', { skip: !process.env.AWG_TEST_QR_DECODER && 'Set AWG_TEST_QR_DECODER to run optional jsQR round trips' }, () => {
  const jsQR = require(process.env.AWG_TEST_QR_DECODER);
  for (const [name, payload] of fixtures) {
    const image = imageFromSvg(connectionQrSvg(payload));
    const decoded = jsQR(image.rgba, image.width, image.width, { inversionAttempts: 'dontInvert' });
    assert.ok(decoded, `${name} should decode from rendered geometry`);
    assert.equal(decoded.data, payload, name);
    assert.deepEqual(Buffer.from(decoded.binaryData), Buffer.from(payload, 'utf8'), name);
  }
});

test('independent decoder recovers and reassembles single and multipart Qt packets', { skip: !process.env.AWG_TEST_QR_DECODER && 'Set AWG_TEST_QR_DECODER to run optional jsQR round trips' }, () => {
  const jsQR = require(process.env.AWG_TEST_QR_DECODER);
  for (const [name, profile, packets] of amneziaFixtures) {
    const chunks = [];
    for (let index = 0; index < packets.length; index++) {
      const payload = packets[index];
      const image = imageFromSvg(amneziaQrSvg(payload));
      const decoded = jsQR(image.rgba, image.width, image.width, { inversionAttempts: 'dontInvert' });
      assert.ok(decoded, `${name} ${index} should decode from rendered geometry`);
      assert.equal(decoded.data, payload, 'base64url envelope is unchanged');
      assert.deepEqual(Buffer.from(decoded.binaryData), Buffer.from(payload, 'utf8'));
      const packet = Buffer.from(decoded.data, 'base64url');
      assert.equal(packet.readInt16BE(0), 1984);
      assert.equal(packet.readUInt8(2), packets.length);
      assert.equal(packet.readUInt8(3), index);
      const chunk = packet.subarray(8);
      assert.equal(packet.readUInt32BE(4), chunk.length);
      assert.ok(chunk.length <= 850);
      chunks.push(chunk);
    }
    const compressed = Buffer.concat(chunks);
    const json = inflateSync(compressed.subarray(4));
    assert.equal(compressed.readUInt32BE(0), json.length, 'qCompress preserves UTF-8 length');
    assert.deepEqual(JSON.parse(json.toString('utf8')), profile, name);
  }
});
