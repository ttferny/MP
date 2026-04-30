const express = require("express"); // [1] Import Express; used by [2].
const router = express.Router(); // [2] Create router from [1]; exported by [10].

const parser = require("../services/parser"); // [3] Header parser; used by [7b].
const spf = require("../services/spf"); // [4] SPF service; used by [8a].
const dkim = require("../services/dkim"); // [5] DKIM service; used by [8b].
const dmarc = require("../services/dmarc"); // [6] DMARC service; used by [8c].

router.post("/", async (req, res) => { // [7] Handle POST requests using [2].
  const { header } = req.body; // [7a] Extract header for [7b].

  const parsed = parser.parseHeader(header); // [7b] Parse header via [3] using [7a].

  const spfResult = await spf.checkSPF(parsed); // [8a] SPF check via [4] using [7b].
  const dkimResult = await dkim.checkDKIM(parsed); // [8b] DKIM check via [5] using [7b].
  const dmarcResult = dmarc.evaluateDMARC(spfResult, dkimResult, parsed); // [8c] DMARC eval via [6] using [8a]/[8b]/[7b].

  res.json({ // [9] Respond with outputs from [7b]/[8a]/[8b]/[8c].
    parsed, // [9a] Include [7b].
    spf: spfResult, // [9b] Include [8a].
    dkim: dkimResult, // [9c] Include [8b].
    dmarc: dmarcResult, // [9d] Include [8c].
  });
});

module.exports = router; // [10] Export router created in [2].