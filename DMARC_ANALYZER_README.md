# DMARC Report Analyzer Feature

## Overview

The DMARC Report Analyzer is a new tab in the Email Authentication Studio that allows companies to upload and analyze their DMARC XML aggregate reports. It provides actionable insights about email authentication, suspicious activity, and security risks.

## Features

### 📊 Report Summary
- Organization name and report domain
- Total email count during reporting period
- Report time range
- DMARC policy mode (reject/quarantine/none)
- Enforcement percentage

### ✅ Authentication Statistics
- **SPF Results**: Pass/fail counts and pass rate percentage
- **DKIM Results**: Pass/fail/none counts and pass rate percentage
- **Alignment Rate**: Percentage of emails with proper SPF/DKIM alignment

### 🖥️ Mail Servers Analysis
- Complete list of IPs/servers sending on behalf of the domain
- Email count per server
- SPF/DKIM verification status per server
- Multiple sender detection per IP

### 🚨 Suspicious Activity Detection
- Risk score calculation per suspicious IP
- Identification of IPs with authentication failures
- Detection of multiple senders from single IP
- Failure pattern analysis

### ⚠️ Spoofing Detection
- Detection of header/envelope mismatches
- Double authentication failure identification
- Policy rejection tracking
- Confidence score for spoofing indicators

### 📈 Risk Assessment
- Overall risk score (0-100)
- Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)
- Risk factors enumeration
- Visual risk meter

### 💡 Recommendations
- Prioritized recommendations (CRITICAL, HIGH, MEDIUM)
- Category-based grouping (SPF, DKIM, Policy, Security, Authentication)
- Specific actions and impact assessment
- Actionable guidance for domain owners

## Architecture

### Backend Components

#### 1. **dmarcXmlParser.js** (`server/services/dmarcXmlParser.js`)
Parses DMARC XML aggregate reports into structured JSON format.

```javascript
const { parseDMARCReport } = require('../services/dmarcXmlParser');
const parsed = await parseDMARCReport(xmlContent);
```

**Returns:**
```json
{
  "metadata": { "orgName", "email", "reportId", "dateRange" },
  "policy": { "domain", "adkim", "aspf", "p", "sp", "pct", "rua", "ruf" },
  "records": [...],
  "totalRecords": number,
  "dateRange": { "start", "end" }
}
```

#### 2. **dmarcReportAnalyzer.js** (`server/services/dmarcReportAnalyzer.js`)
Analyzes parsed DMARC records and generates comprehensive insights.

```javascript
const { analyzeDMARCReport } = require('../services/dmarcReportAnalyzer');
const analysis = analyzeDMARCReport(dmarcReport);
```

**Returns:**
```json
{
  "summary": {...},
  "mailServers": {...},
  "authenticationStats": {...},
  "suspiciousActivity": {...},
  "spoofingDetection": {...},
  "riskAssessment": {...},
  "recommendations": [...]
}
```

#### 3. **dmarcRoutes.js** Endpoints

**POST /api/dmarc/upload**
- Accepts XML file upload (multipart/form-data)
- Parses and validates the XML
- Returns parsed DMARC report structure

**POST /api/dmarc/analyze**
- Accepts parsed DMARC report (JSON)
- Performs comprehensive analysis
- Returns detailed insights and recommendations

### Frontend Components

#### 1. **dmarc_analyzer.html**
Standalone HTML with upload interface and results display.
Can be embedded as a tab or used separately.

#### 2. **dmarc_analyzer.css**
Modern styling with:
- Drag-and-drop upload zone
- Progress indicators
- Data visualization
- Risk level color coding
- Responsive design

#### 3. **dmarc_analyzer.js**
Event handling and API integration:
- File upload handling
- Progress tracking
- API calls to backend
- Dynamic result rendering
- Error handling

## Usage

### For End Users

1. Navigate to the "📊 Report Analyzer" tab in the DMARC Policy Engine
2. Drag and drop a DMARC XML report or click to browse
3. Click "Analyze Report"
4. Review insights:
   - Mail servers sending on your behalf
   - Authentication pass/fail rates
   - Suspicious IPs and spoofing indicators
   - Risk assessment
   - Actionable recommendations

### For Developers

#### Upload and Analyze a Report

```bash
curl -X POST -F "file=@report.xml" http://localhost:3000/api/dmarc/upload
```

```bash
curl -X POST -H "Content-Type: application/json" \
  -d @parsed_report.json \
  http://localhost:3000/api/dmarc/analyze
```

#### Integration in Custom Applications

```javascript
// Parse DMARC XML
const { parseDMARCReport } = require('./services/dmarcXmlParser');
const parsed = await parseDMARCReport(xmlContent);

// Analyze results
const { analyzeDMARCReport } = require('./services/dmarcReportAnalyzer');
const analysis = analyzeDMARCReport(parsed);

// Use analysis data
console.log(analysis.riskAssessment.overallRiskScore);
console.log(analysis.recommendations);
```

## File Structure

```
client/
├── dmarc_analyzer.html       # Main UI template
├── dmarc_analyzer.css        # Styling
├── dmarc_analyzer.js         # Frontend logic
└── dmarc.html                # Integrated with analyzer tab

server/
├── routes/
│   └── dmarcRoutes.js        # Upload & analyze endpoints
└── services/
    ├── dmarcXmlParser.js     # XML parsing
    └── dmarcReportAnalyzer.js # Analysis engine

sample_dmarc_report.xml       # Example report for testing
```

## Testing

### Using Sample Report

1. Copy `sample_dmarc_report.xml` to your client directory
2. Open the Report Analyzer tab
3. Upload the sample file
4. Review generated analysis

### Expected Results for Sample

- **Organization**: Example Corp
- **Domain**: example.com
- **Total Emails**: 255
- **DMARC Policy**: quarantine (p=quarantine)
- **SPF Pass Rate**: ~71% (172/255)
- **DKIM Pass Rate**: ~67% (170/255)
- **Suspicious IPs**: 2 (198.51.100.200 with double auth failure)
- **Spoofing Detected**: Yes (78 emails with policy rejection)
- **Risk Level**: HIGH

## Error Handling

The analyzer handles various error cases:

- **Invalid XML**: Returns descriptive error message
- **Missing Elements**: Applies defaults or returns "unknown"
- **Empty Records**: Gracefully displays "No data"
- **File Upload Failures**: User-friendly error messages
- **API Failures**: Detailed error reporting

## Performance Considerations

- **XML Parsing**: Optimized for reports up to 10,000+ records
- **Analysis**: O(n) complexity with single pass through data
- **Memory**: In-memory processing suitable for typical DMARC reports
- **UI**: Smooth animations and progressive rendering

## Future Enhancements

- Database persistence for report history
- Batch report comparison
- Timeline visualization
- Custom alert thresholds
- Export to CSV/PDF
- Integration with SOAR platforms
- Real-time report streaming
- Machine learning based anomaly detection

## Dependencies

- `express` - Web framework
- `multer` - File upload handling
- `xml2js` - XML parsing
- Modern browser support (ES6+)

## License

Temasek Polytechnic · Diploma in Cybersecurity and Digital Forensics
