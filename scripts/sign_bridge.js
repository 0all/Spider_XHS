const path = require("path");
const { get_request_headers_params } = require(path.join(__dirname, "..", "static", "xhs_xs_xsc_56.js"));

function decodePayload(encoded) {
  if (!encoded) {
    return "";
  }
  try {
    const raw = Buffer.from(encoded, "base64").toString("utf-8");
    if (!raw) {
      return "";
    }
    return JSON.parse(raw);
  } catch (err) {
    console.error(`Failed to decode payload: ${err.message}`);
    return "";
  }
}

function main() {
  const [,, api, method, a1, payloadEncoded] = process.argv;
  if (!api || !a1) {
    console.error("Usage: node sign_bridge.js <api> <method> <a1> [base64_payload]");
    process.exit(1);
  }
  const payload = decodePayload(payloadEncoded);
  const result = get_request_headers_params(api, payload, a1, method || "POST");
  process.stdout.write(JSON.stringify(result));
}

main();
