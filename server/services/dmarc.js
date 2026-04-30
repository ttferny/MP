exports.evaluateDMARC = (spf, dkim, parsed) => { // [1] Exported DMARC eval uses [2] and [3].
  let policy = "quarantine"; // [2] Simulated policy used by [6].

  if (spf.status === "pass" || dkim.status === "pass") { // [3] Pass condition based on [1] inputs.
    return { // [4] Pass response for [3].
      status: "pass", // [4a] Status field for [4].
      action: "deliver", // [4b] Action field for [4].
      reason: "SPF or DKIM passed" // [4c] Reason field for [4].
    };
  }

  return { // [6] Fail response when [3] is false, using [2].
    status: "fail", // [6a] Status field for [6].
    action: policy, // [6b] Action field uses [2].
    reason: "Both SPF and DKIM failed" // [6c] Reason field for [6].
  };
};