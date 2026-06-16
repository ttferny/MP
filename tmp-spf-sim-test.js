const scenarios = ['ceo-fraud','legit-newsletter','phishing','misconfigured'];
(async () => {
  for (const key of scenarios) {
    try {
      const res = await fetch('http://localhost:3000/api/spf/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: '', attackerIP: '', scenarioKey: key }),
      });
      const data = await res.json();
      console.log('---', key, '---');
      console.log(JSON.stringify(data, null, 2));
    } catch (e) {
      console.error('ERR', key, e.message);
    }
  }
})();