exports.checkDKIM = async (parsed) => { // [1] Exported DKIM check uses [2].
  if (!parsed.dkimSignature) { // [2] Guard against missing signature in [1].
    return { status: "fail", reason: "No DKIM signature" }; // [2a] Failure response for [2].
  }

  // Simulated validation
  return { // [3] Success response for [1].
    status: "pass", // [3a] Status field for [3].
    reason: "DKIM signature present (simulation)" // [3b] Reason field for [3].
  };
};