import { qrcodegen } from './vendor/qrcodegen.js';

const QR_TOO_LARGE = 'Конфигурация слишком большая для QR-кода. Скачайте файл .conf.';

// Encode the exact downloaded configuration locally. The SVG contains geometry
// only; configuration text and private keys must never become SVG attributes.
export function connectionQrSvg(config) {
  if (typeof config !== 'string') throw new TypeError('Конфигурация должна быть строкой.');
  // Even a numeric-only QR cannot hold more than 7089 characters. Bound work
  // before the encoder allocates bit arrays for unexpectedly huge input.
  if (config.length > 7089) throw new RangeError(QR_TOO_LARGE);
  let qr;
  try {
    qr = qrcodegen.QrCode.encodeText(config, qrcodegen.QrCode.Ecc.MEDIUM);
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    try {
      qr = qrcodegen.QrCode.encodeText(config, qrcodegen.QrCode.Ecc.LOW);
    } catch (fallbackError) {
      if (!(fallbackError instanceof RangeError)) throw fallbackError;
      throw new RangeError(QR_TOO_LARGE);
    }
  }
  const border = 4;
  const size = qr.size + border * 2;
  const paths = [];
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.getModule(x, y)) paths.push(`M${x + border},${y + border}h1v1h-1z`);
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size * 4}" height="${size * 4}" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="${paths.join('')}" fill="#000"/></svg>`;
}
