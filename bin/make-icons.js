#!/usr/bin/env node
'use strict';
// 拡張のアイコン（PNG）を作る。
//
//   node bin/make-icons.js
//
// 画像ライブラリを入れられない環境なので、PNG を自前で書き出す。
// zlib は Node 標準に入っているので、あとはチャンクを組み立てるだけ。

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const OUT_DIR = path.resolve(__dirname, '..', 'extension', 'icons');

function crc32(buf) {
  let crc = 0xffffffff;
  for (const byte of buf) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeAndData = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData), 0);
  return Buffer.concat([length, typeAndData, crc]);
}

// pixels は RGBA の Uint8Array（幅 * 高さ * 4）
function encodePng(width, height, pixels) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // ビット深度
  ihdr[9] = 6;  // カラータイプ: RGBA
  ihdr[10] = 0; // 圧縮方式
  ihdr[11] = 0; // フィルタ方式
  ihdr[12] = 0; // インターレースなし

  // 各行の先頭にフィルタ種別（0 = なし）を付ける
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    raw[y * (width * 4 + 1)] = 0;
    pixels.copy
      ? pixels.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4)
      : Buffer.from(pixels).copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0))
  ]);
}

// 南京錠のかたち。角丸の本体に、上へU字のシャックル、中央に鍵穴。
function drawIcon(size) {
  const pixels = Buffer.alloc(size * size * 4, 0);
  const s = (v) => v * size; // 0〜1 の比率を実寸へ

  const body = { x0: s(0.18), x1: s(0.82), y0: s(0.44), y1: s(0.88), r: s(0.10) };
  const shackle = { cx: s(0.5), cy: s(0.42), outer: s(0.22), inner: s(0.13) };
  const hole = { cx: s(0.5), cy: s(0.62), r: s(0.075) };
  const stem = { x0: s(0.465), x1: s(0.535), y0: s(0.62), y1: s(0.78) };

  const BODY = [13, 110, 253, 255];    // Bootstrap の primary に寄せる
  const SHACKLE = [31, 41, 51, 255];   // 画面のヘッダーと同じ濃紺
  const HOLE = [255, 255, 255, 255];

  // 少し重ねてサンプリングして、輪郭のギザギザを抑える
  const SUB = 3;

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let acc = [0, 0, 0, 0];
      let hits = 0;

      for (let sy = 0; sy < SUB; sy += 1) {
        for (let sx = 0; sx < SUB; sx += 1) {
          const px = x + (sx + 0.5) / SUB;
          const py = y + (sy + 0.5) / SUB;
          let color = null;

          // 本体（角丸四角）
          const insideBody = (() => {
            if (px < body.x0 || px > body.x1 || py < body.y0 || py > body.y1) return false;
            const cx = Math.min(Math.max(px, body.x0 + body.r), body.x1 - body.r);
            const cy = Math.min(Math.max(py, body.y0 + body.r), body.y1 - body.r);
            return (px - cx) ** 2 + (py - cy) ** 2 <= body.r ** 2
              || (px >= body.x0 + body.r && px <= body.x1 - body.r)
              || (py >= body.y0 + body.r && py <= body.y1 - body.r);
          })();

          if (insideBody) {
            color = BODY;
            // 鍵穴（丸 + 下に伸びる棒）
            const inHole = (px - hole.cx) ** 2 + (py - hole.cy) ** 2 <= hole.r ** 2;
            const inStem = px >= stem.x0 && px <= stem.x1 && py >= stem.y0 && py <= stem.y1;
            if (inHole || inStem) color = HOLE;
          } else {
            // シャックル（本体より上のU字。下半分は本体に隠れる）
            const d2 = (px - shackle.cx) ** 2 + (py - shackle.cy) ** 2;
            if (py <= body.y0 && d2 <= shackle.outer ** 2 && d2 >= shackle.inner ** 2) {
              color = SHACKLE;
            }
          }

          if (color) {
            acc = [acc[0] + color[0], acc[1] + color[1], acc[2] + color[2], acc[3] + color[3]];
            hits += 1;
          }
        }
      }

      const total = SUB * SUB;
      if (hits > 0) {
        const offset = (y * size + x) * 4;
        pixels[offset] = Math.round(acc[0] / hits);
        pixels[offset + 1] = Math.round(acc[1] / hits);
        pixels[offset + 2] = Math.round(acc[2] / hits);
        pixels[offset + 3] = Math.round((acc[3] / total));
      }
    }
  }

  return pixels;
}

fs.mkdirSync(OUT_DIR, { recursive: true });
for (const size of [16, 48, 128]) {
  const file = path.join(OUT_DIR, `icon${size}.png`);
  fs.writeFileSync(file, encodePng(size, size, drawIcon(size)));
  console.log(`${file} (${size}x${size})`);
}
