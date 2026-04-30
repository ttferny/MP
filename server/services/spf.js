const dnsService = require("./dns"); // [1] DNS helper used by [4].

exports.checkSPF = async (parsed) => { // [2] Exported SPF check uses [3]-[6].
  const domain = parsed.from.split("@")[1]; // [3] Extract domain for [4].

  const records = await dnsService.getTXT(domain); // [4] Fetch TXT records via [1] using [3].
  const spfRecord = records.find(r => r.startsWith("v=spf1")); // [5] Find SPF record in [4].

  if (!spfRecord) { // [6] Guard if [5] missing.
    return { status: "fail", reason: "No SPF record found" }; // [6a] Failure response for [6].
  }

  return { // [7] Success response for [2] using [5].
    status: "pass", // [7a] Status field for [7].
    record: spfRecord, // [7b] Record field from [5].
    reason: "SPF record exists (simulation)" // [7c] Reason field for [7].
  };
};