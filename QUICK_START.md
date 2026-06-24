# 🚀 Quick Start: Automated DNS & DKIM Studio

## Installation & Launch

### 1. Ensure Dependencies
```bash
cd MP
npm install
```

### 2. Start the Server
```bash
npm start
# or
node server/app.js
```

Server runs on: `http://localhost:3000`

### 3. Access the DNS Studio
```
http://localhost:3000/dns-studio.html
```

---

## ⚡ 30-Second Usage

1. **Enter a domain** (e.g., `google.com`)
2. **Click "Check DNS"**
3. **See results:**
   - ✅ SPF record found/not found
   - ✅ DMARC policy found/not found
   - ✅ DKIM selectors discovered
   - ✅ Summary statistics

4. **(Optional) Paste email header** to validate DKIM signature
5. **Click "Check DNS"** again for combined results

---

## 📚 Available API Endpoints

```bash
# Check DNS records for a domain
POST /api/dns/check
Body: { "domain": "example.com" }

# Validate DKIM from email header
POST /api/dns/dkim-validate
Body: { "rawHeader": "From: ...\nDKIM-Signature: ..." }

# Complete automated check
POST /api/dns/full-check
Body: { "domain": "example.com", "rawHeader": "..." (optional) }
```

---

## 🧪 Test Cases

### ✅ Test 1: Google (Should Find Everything)
```
Domain: google.com
Expected: SPF ✓ DMARC ✓ DKIM ✓
```

### ✅ Test 2: Example.com (Should Find Nothing)
```
Domain: example.com
Expected: SPF ✗ DMARC ✗ DKIM ✗
```

### ✅ Test 3: GitHub (Should Find Most)
```
Domain: github.com
Expected: SPF ✓ DMARC ✓ DKIM ✓
```

---

## 🔧 Files Modified

| File | Change |
|------|--------|
| `server/services/autoDnsChecker.js` | ✨ NEW - Automation engine |
| `server/routes/dnsRoutes.js` | ✨ NEW - API endpoints |
| `server/app.js` | Modified - Added DNS routes |
| `client/dns-studio.html` | ✨ NEW - UI interface |
| `client/index.html` | Modified - Added nav link |

---

## 🎯 What Gets Checked

### DNS Records
- ✅ SPF (Sender Policy Framework)
- ✅ DMARC (Domain-based Message Authentication)
- ✅ DKIM (DomainKeys Identified Mail)

### Common DKIM Selectors
- default
- mail
- selector1, selector2
- google, amazon, sendgrid
- k1

---

## 💡 Tips

- **Fastest**: Just enter domain, no email needed
- **Thorough**: Add email header for DKIM validation
- **Debug**: Check browser console for detailed logs
- **Retry**: If DNS query times out, try again

---

## 🆘 Troubleshooting

### "Invalid domain"
→ Remove protocol (http://) and path (/)
→ Use: `example.com` not `https://example.com/`

### "Network timeout"
→ Try a different domain or retry
→ Your DNS server might be slow

### No DKIM selectors found
→ Domain might not have DKIM configured
→ Not all domains use DKIM

### Header validation fails
→ Email must contain `DKIM-Signature:` header
→ Use a real email header, not plain text

---

## 📊 Response Example

```json
{
  "success": true,
  "data": {
    "domain": "google.com",
    "dnsCheck": {
      "records": {
        "spf": {
          "status": "found",
          "record": "v=spf1 include:_spf.google.com ~all"
        },
        "dmarc": {
          "status": "found",
          "record": "v=DMARC1; p=quarantine; ..."
        },
        "dkim": [
          {
            "selector": "google",
            "status": "found",
            "record": "v=DKIM1; k=rsa; p=..."
          }
        ]
      },
      "summary": {
        "hasSPF": true,
        "hasDMARC": true,
        "dkimSelectors": ["google"]
      }
    }
  }
}
```

---

## 🎓 Learning Path

1. **Beginner**: Just check domains with one-click
2. **Intermediate**: Add email headers for validation
3. **Advanced**: Check API endpoints directly with curl/Postman
4. **Expert**: Integrate into your own tools

---

## ✨ Features at a Glance

| Feature | Status |
|---------|--------|
| Automated DNS lookup | ✅ |
| SPF detection | ✅ |
| DMARC policy check | ✅ |
| DKIM selector scanning | ✅ |
| Email header validation | ✅ |
| Public key verification | ✅ |
| Error handling | ✅ |
| Responsive UI | ✅ |
| Real-time results | ✅ |

---

## 🚀 Next Steps

1. ✅ Launch the server
2. ✅ Open http://localhost:3000/dns-studio.html
3. ✅ Enter a domain
4. ✅ Check your results
5. ✅ Try with an email header (optional)

**Happy DNS checking!** 🎉
