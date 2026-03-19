"""
Author: Ugur Ates
Enhanced Intelligent Scoring System
Blue Team Tools Integration
"""

# Base scoring factors (existing)
BASE_SCORE_FACTORS = {
    'source_detected': 10,
    'high_confidence_source': 15,
    'malware_family_identified': 25,
    'c2_communication': 30,
    'exploit_detected': 35
}

# ========== BLUE TEAM ENHANCEMENTS ==========

# Additional scoring factors from Sooty + Blue Team tools
ENHANCED_SCORE_FACTORS = {
    'oletools_macro_detected': 30,
    'oletools_dde_detected': 50,
    'oletools_suspicious_objects': 20,
    'phishing_critical_risk': 40,
    'phishing_high_risk': 30,
    'phishing_medium_risk': 20,
    'brand_impersonation': 25,
    'credential_harvesting': 35,
    'suspicious_attachment': 25,
    'auth_failures': 20,  # SPF/DKIM/DMARC
    'bec_critical': 40,
    'bec_high': 30,
    'bec_medium': 15,
}

def calculate_enhanced_score(base_score: int, analysis_results: dict) -> int:
    """
    Calculate enhanced threat score with Blue Team tool integrations.
    
    Args:
        base_score: Original threat score
        analysis_results: Complete analysis results
    
    Returns:
        Enhanced threat score (0-100)
    """
    enhanced_score = base_score
    
    # OleTools enhancements
    oletools = analysis_results.get('oletools_analysis', {})
    if oletools.get('vba_macros', {}).get('has_macros'):
        enhanced_score += ENHANCED_SCORE_FACTORS['oletools_macro_detected']
    if oletools.get('dde_links', {}).get('has_dde'):
        enhanced_score += ENHANCED_SCORE_FACTORS['oletools_dde_detected']
    if oletools.get('ole_objects', {}).get('has_objects'):
        enhanced_score += ENHANCED_SCORE_FACTORS['oletools_suspicious_objects']
    
    # Phishing detector enhancements
    phishing = analysis_results.get('phishing_analysis', {})
    risk_level = phishing.get('risk_level', 'LOW')
    if risk_level == 'CRITICAL':
        enhanced_score += ENHANCED_SCORE_FACTORS['phishing_critical_risk']
    elif risk_level == 'HIGH':
        enhanced_score += ENHANCED_SCORE_FACTORS['phishing_high_risk']
    elif risk_level == 'MEDIUM':
        enhanced_score += ENHANCED_SCORE_FACTORS['phishing_medium_risk']
    
    # Specific threat indicators
    for indicator in phishing.get('indicators', []):
        if indicator.get('type') == 'BRAND_IMPERSONATION':
            enhanced_score += ENHANCED_SCORE_FACTORS['brand_impersonation']
        elif indicator.get('type') == 'CREDENTIAL_HARVESTING':
            enhanced_score += ENHANCED_SCORE_FACTORS['credential_harvesting']
        elif indicator.get('type') == 'SUSPICIOUS_ATTACHMENT':
            enhanced_score += ENHANCED_SCORE_FACTORS['suspicious_attachment']
    
    # BEC detection enhancements
    bec = analysis_results.get('bec_analysis', analysis_results.get('advanced_analysis', {}).get('bec_analysis', {}))
    bec_verdict = bec.get('verdict', 'LOW')
    if bec_verdict == 'CRITICAL':
        enhanced_score += ENHANCED_SCORE_FACTORS['bec_critical']
    elif bec_verdict == 'HIGH':
        enhanced_score += ENHANCED_SCORE_FACTORS['bec_high']
    elif bec_verdict == 'MEDIUM':
        enhanced_score += ENHANCED_SCORE_FACTORS['bec_medium']

    return min(enhanced_score, 100)
