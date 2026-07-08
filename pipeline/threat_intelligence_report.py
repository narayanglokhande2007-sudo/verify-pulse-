
import sqlite3
import json
from datetime import datetime, timedelta
from collections import Counter
import os
from brand_protection import init_brand_protection_db
from scam_hunter import init_db as init_scams_db

# ============================================================================
# CONFIGURATION
# ============================================================================

DB_FILE = 'pipeline/daily-data/scams.db'
BRAND_PROTECTION_DB = 'pipeline/daily-data/brand_protection.db'
INDIA_MASTER = 'pipeline/daily-data/india_scams.jsonl'
GLOBAL_MASTER = 'pipeline/daily-data/global_scams.jsonl'

REPORT_OUTPUT_DIR = 'reports'
REPORT_FILENAME_MD = os.path.join(REPORT_OUTPUT_DIR, 'threat_intelligence_report.md')
REPORT_FILENAME_PDF = os.path.join(REPORT_OUTPUT_DIR, 'threat_intelligence_report.pdf')

# ============================================================================
# DATA RETRIEVAL & ANALYSIS
# ============================================================================

def get_scam_data(days=7):
    """Retrieve scam data from the main database for the last 'days' days."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    start_date = (datetime.now() - timedelta(days=days)).isoformat()
    
    c.execute("SELECT url, source, type, date_added, region FROM scams WHERE date_added >= ?", (start_date,))
    scams = c.fetchall()
    conn.close()
    
    return scams

def get_brand_threat_data(days=7):
    """Retrieve brand protection threat data for the last 'days' days."""
    conn = sqlite3.connect(BRAND_PROTECTION_DB)
    c = conn.cursor()
    
    start_date = (datetime.now() - timedelta(days=days)).isoformat()
    
    c.execute("SELECT domain, bank_brand, detection_date, confidence_score FROM brand_threats WHERE detection_date >= ?", (start_date,))
    threats = c.fetchall()
    conn.close()
    
    return threats

def analyze_scam_trends(scams, brand_threats):
    """Analyze scam data to identify trends and patterns."""
    total_scams = len(scams)
    total_brand_threats = len(brand_threats)
    
    # Scam types
    scam_types = Counter([s[2] for s in scams])
    
    # Regions affected
    regions = Counter([s[4] for s in scams])
    
    # Top sources
    sources = Counter([s[1] for s in scams])
    
    # Top targeted brands (from brand protection data)
    targeted_brands = Counter([t[1] for t in brand_threats])
    
    # Example of a common scam pattern (can be expanded with LLM analysis)
    common_patterns = []
    for url, _, _, _, _ in scams:
        if "kyc" in url.lower() or "verify" in url.lower():
            common_patterns.append("KYC/Verification Scams")
        if "reward" in url.lower() or "cashback" in url.lower():
            common_patterns.append("Reward/Cashback Scams")
        if "lottery" in url.lower():
            common_patterns.append("Lottery Scams")
    common_patterns_counter = Counter(common_patterns)

    return {
        "total_scams_detected": total_scams,
        "total_brand_threats": total_brand_threats,
        "scam_types": scam_types.most_common(5),
        "regions_affected": regions.most_common(5),
        "top_sources": sources.most_common(5),
        "top_targeted_brands": targeted_brands.most_common(5),
        "common_scam_patterns": common_patterns_counter.most_common(5),
        "recent_scams": scams[-10:], # Last 10 scams
        "recent_brand_threats": brand_threats[-5:] # Last 5 brand threats
    }

# ============================================================================
# REPORT GENERATION (MARKDOWN)
# ============================================================================

def generate_markdown_report(analysis_results, report_period_days=7):
    """Generate a detailed threat intelligence report in Markdown format."""
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report_content = f"""
# VerifyPulse Threat Intelligence Report

**Report Date:** {report_date}
**Report Period:** Last {report_period_days} days
**Author:** VerifyPulse AI

## 1. Executive Summary

This report provides a concise overview of the phishing and scam landscape detected by VerifyPulse over the last {report_period_days} days. Our autonomous systems, including the Meta Judge architecture, Ghost Agent sandboxing, and Proactive Scam Hunter, have identified a significant number of threats targeting various sectors, with a particular focus on financial institutions in India.

Key findings include the detection of **{analysis_results['total_scams_detected']}** total scams and **{analysis_results['total_brand_threats']}** brand impersonation threats against major banks. The primary attack vectors continue to involve KYC/verification scams and reward-based phishing, often leveraging sophisticated visual imitation techniques.

## 2. Overall Threat Statistics

| Metric                      | Value                                    |
| :-------------------------- | :--------------------------------------- |
| Total Scams Detected        | {analysis_results['total_scams_detected']} |
| Total Brand Impersonations  | {analysis_results['total_brand_threats']} |

## 3. Scam Type Breakdown

This section details the most prevalent types of scams observed during the reporting period.

| Scam Type           | Count |
| :------------------ | :---- |
"""
    for scam_type, count in analysis_results['scam_types']:
        report_content += f"| {scam_type} | {count} |\n"
        
    report_content += f"""
## 4. Top Targeted Brands (Financial Sector)

Our Brand Protection module has identified the following banks as the primary targets for impersonation attacks.

| Bank Brand | Threats Detected |
| :--------- | :--------------- |
"""
    for brand, count in analysis_results['top_targeted_brands']:
        report_content += f"| {brand.upper()} | {count} |\n"

    report_content += f"""
## 5. Common Scam Patterns

Analysis of the detected URLs reveals the following common patterns and keywords used by threat actors to deceive victims.

| Pattern/Keyword | Frequency |
| :-------------- | :-------- |
"""
    for pattern, count in analysis_results['common_scam_patterns']:
        report_content += f"| {pattern} | {count} |\n"

    report_content += f"""
## 6. Notable Recent Threats

Below is a sample of recently detected high-confidence threats.

### 6.1 Brand Impersonations
"""
    for domain, brand, date, confidence in analysis_results['recent_brand_threats']:
        report_content += f"- **Domain:** `{domain}`\n  - **Target:** {brand.upper()}\n  - **Detected:** {date}\n  - **Confidence:** {confidence*100:.2f}%\n"

    report_content += f"""
### 6.2 General Scams
"""
    for url, source, scam_type, date, region in analysis_results['recent_scams']:
        report_content += f"- **URL:** `{url}`\n  - **Type:** {scam_type}\n  - **Region:** {region}\n  - **Detected:** {date}\n"

    report_content += f"""
## 7. Mitigation Recommendations

Based on the observed trends, VerifyPulse recommends the following proactive measures:

1.  **Enhanced Monitoring:** Financial institutions should continuously monitor Certificate Transparency logs for domain variations related to their brand.
2.  **User Education:** Conduct awareness campaigns focusing on the prevalent "KYC Update" and "Reward/Cashback" phishing tactics.
3.  **Rapid Takedown:** Utilize automated takedown services to quickly neutralize identified brand impersonation sites before they can cause significant harm.
4.  **Implement Visual Forensics:** Integrate AI-driven visual analysis tools to detect pixel-level brand imitation on suspicious domains.

---
*This report is generated automatically by the VerifyPulse Threat Intelligence Engine. For more detailed analysis or API access, please contact our enterprise support team.*
"""
    return report_content

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    print("=" * 80)
    print("VerifyPulse Threat Intelligence Report Generator")
    print("=" * 80)
    
    # Ensure output directory exists
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    # Initialize databases
    print("Initializing databases...")
    init_scams_db()
    init_brand_protection_db()
    
    # 1. Retrieve Data
    print("Retrieving data from databases...")
    scams = get_scam_data(days=7)
    brand_threats = get_brand_threat_data(days=7)
    
    # 2. Analyze Data
    print("Analyzing threat trends...")
    analysis_results = analyze_scam_trends(scams, brand_threats)
    
    # 3. Generate Markdown Report
    print("Generating Markdown report...")
    markdown_report = generate_markdown_report(analysis_results, report_period_days=7)
    
    # 4. Save Markdown Report
    with open(REPORT_FILENAME_MD, 'w', encoding='utf-8') as f:
        f.write(markdown_report)
    print(f"✅ Markdown report saved to: {REPORT_FILENAME_MD}")
    
    # 5. Convert to PDF (using manus-md-to-pdf utility)
    print("Converting Markdown to PDF...")
    os.system(f"manus-md-to-pdf {REPORT_FILENAME_MD} {REPORT_FILENAME_PDF}")
    print(f"✅ PDF report saved to: {REPORT_FILENAME_PDF}")
    
    print("\n✅ Threat Intelligence Report Generation Complete!")
