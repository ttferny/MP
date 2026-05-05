const express = require('express');
const router  = express.Router();
const { evaluateDMARC } = require('../services/dmarc');

router.post('/evaluate', (req, res) => {
  const { spf, dkim, parsed } = req.body;
  const result = evaluateDMARC(spf, dkim, parsed);
  res.json(result);
});

module.exports = router;