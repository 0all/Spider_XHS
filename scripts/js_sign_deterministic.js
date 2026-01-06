const path = require("path");
const crypto = require("crypto");

const [, , randHex, fixedNow, method, api, a1, payloadB64] = process.argv;

if (!randHex || !fixedNow || !method || !api || !a1) {
  console.error("Usage: node js_sign_deterministic.js <randHex> <fixedNowMs> <method> <api> <a1> <payloadB64>");
  process.exit(1);
}

const randBuf = Buffer.from(randHex, "hex");
let offset = 0;
const originalRandomBytes = crypto.randomBytes;
crypto.randomBytes = function (n) {
  const slice = randBuf.slice(offset, offset + n);
  offset += n;
  if (slice.length < n) {
    return Buffer.concat([slice, Buffer.alloc(n - slice.length, 0)]);
  }
  return slice;
};

const realNow = Date.now;
const fixed = Number(fixedNow);
Date.now = () => fixed;
const RealDate = Date;
// Override Date constructor so new Date() uses fixed time
global.Date = class extends RealDate {
  constructor(...args) {
    if (args.length === 0) {
      super(fixed);
    } else {
      super(...args);
    }
  }
  static now() {
    return fixed;
  }
};

const signer = require(path.join(__dirname, "..", "static", "xhs_xs_xsc_56.js"));
const payload = payloadB64 ? JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8")) : {};

const res = signer.get_request_headers_params(api, payload, a1, method);
console.log(JSON.stringify(res));

Date.now = realNow;
crypto.randomBytes = originalRandomBytes;
