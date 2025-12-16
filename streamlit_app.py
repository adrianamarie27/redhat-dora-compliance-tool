import streamlit as st
import pypdf
from docx import Document
import re
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import io
import csv
import base64

# Google Drive API imports
try:
    from google.oauth2.credentials import Credentials
    from google.oauth2 import service_account
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseDownload
    from googleapiclient.errors import HttpError
    GOOGLE_DRIVE_AVAILABLE = True
except ImportError:
    GOOGLE_DRIVE_AVAILABLE = False
    # Warning will be shown in the UI when Google Drive is accessed

# Proxy/VPN support
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Red Hat Risk Assessment
try:
    from redhat_risk_assessment import get_redhat_risk_assessment, format_risk_factors
    REDHAT_RISK_AVAILABLE = True
except ImportError:
    REDHAT_RISK_AVAILABLE = False
    def get_redhat_risk_assessment(gap_type, pillar, gap_status):
        return None
    def format_risk_factors(risk_factors):
        return []

# Page configuration
st.set_page_config(
    page_title="DORA Compliance Analyzer - ICT Service Provider Edition",
    page_icon="📋",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'google_drive_service' not in st.session_state:
    st.session_state.google_drive_service = None
if 'analyzed_documents' not in st.session_state:
    st.session_state.analyzed_documents = []
if 'current_document' not in st.session_state:
    st.session_state.current_document = None
if 'current_document_name' not in st.session_state:
    st.session_state.current_document_name = None

# Mitigating controls database
MITIGATING_CONTROLS = {
    "ICT Risk Management": {
        "missing_rmf": [
            "Implement a documented ICT Risk Management Framework aligned with ISO 27001 or NIST Cybersecurity Framework",
            "Establish quarterly review cycles for the RMF with documented evidence",
            "Create a risk register with identified threats, vulnerabilities, and controls"
        ],
        "missing_asset_inventory": [
            "Develop a comprehensive ICT asset inventory using automated discovery tools",
            "Categorize assets by criticality (Critical, Important, Standard)",
            "Document dependencies and interdependencies between systems"
        ],
        "missing_governance": [
            "Define clear roles and responsibilities in a RACI matrix",
            "Establish a governance committee with management body representation",
            "Document escalation procedures and decision-making authority"
        ]
    },
    "ICT Incident Management": {
        "missing_classification": [
            "Define incident severity levels (Critical, High, Medium, Low) with clear criteria",
            "Establish time-based classification thresholds (e.g., downtime duration, data exposure)",
            "Create an incident classification matrix with examples"
        ],
        "missing_reporting": [
            "Document internal reporting timelines (e.g., Critical: 1 hour, High: 4 hours)",
            "Establish external reporting procedures to national competent authorities",
            "Create reporting templates and escalation workflows"
        ],
        "missing_rca": [
            "Implement a structured RCA methodology (e.g., 5 Whys, Fishbone, Fault Tree Analysis)",
            "Document RCA procedures with mandatory completion timelines",
            "Establish lessons learned processes and knowledge base"
        ]
    },
    "Digital Operational Resilience Testing": {
        "missing_testing_program": [
            "Develop a comprehensive testing program covering vulnerability scans, penetration tests, and red team exercises",
            "Establish testing frequency (e.g., quarterly vulnerability scans, annual penetration tests)",
            "Document testing methodologies and tools used"
        ],
        "missing_tlpt": [
            "Plan and execute Threat-Led Penetration Testing (TLPT) for critical functions",
            "Engage certified TLPT providers or establish internal TLPT capabilities",
            "Document TLPT results and remediation actions"
        ],
        "missing_remediation": [
            "Establish vulnerability remediation SLAs based on severity",
            "Implement a tracking system for identified weaknesses",
            "Create remediation verification procedures"
        ]
    },
    "Managing ICT Third-Party Risk": {
        "missing_vendor_register": [
            "Create a comprehensive vendor register with all ICT service providers",
            "Categorize vendors by criticality (Critical/Important Functions vs. Standard)",
            "Maintain up-to-date contract information and service descriptions"
        ],
        "missing_exit_strategy": [
            "Document exit strategies for all critical ICT service providers",
            "Establish data portability and transition procedures",
            "Create exit strategy testing and validation processes"
        ],
        "missing_audit_rights": [
            "Include audit and inspection rights clauses in all critical vendor contracts",
            "Establish procedures for exercising audit rights",
            "Document audit findings and remediation actions"
        ]
    },
    "Information Sharing": {
        "missing_sharing_mechanisms": [
            "Join industry information sharing organizations (e.g., FS-ISAC, national CERTs)",
            "Establish internal threat intelligence sharing procedures",
            "Create channels for sharing TTPs (Tactics, Techniques, Procedures) and IoCs (Indicators of Compromise)"
        ],
        "missing_confidentiality": [
            "Implement data classification and handling procedures for threat intelligence",
            "Establish secure communication channels for information sharing",
            "Create confidentiality agreements and NDAs for sharing partners"
        ]
    }
}

def get_proxy_config():
    """Get proxy configuration from environment variables or config file."""
    proxy_config = {
        'http': os.getenv('HTTP_PROXY') or os.getenv('http_proxy'),
        'https': os.getenv('HTTPS_PROXY') or os.getenv('https_proxy'),
    }
    
    # Try to load from config file
    try:
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                config = json.load(f)
                if 'proxy' in config:
                    proxy_config.update(config['proxy'])
    except Exception:
        pass
    
    # Remove None values
    return {k: v for k, v in proxy_config.items() if v}

def create_http_session_with_proxy():
    """Create a requests session with proxy support for VPN."""
    session = requests.Session()
    proxy_config = get_proxy_config()
    
    if proxy_config:
        session.proxies.update(proxy_config)
        st.info(f"🔒 Using proxy configuration for VPN access")
    
    # Add retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

@st.cache_data(ttl=3600)  # Cache for 1 hour
def load_dora_requirements():
    """Load and parse DORA requirements from online source or local file."""
    try:
        # Try to fetch from online source first (GitHub raw URL)
        online_urls = [
            "https://raw.githubusercontent.com/adrianamarie27/redhat-dora-compliance-tool/main/dora_requirements.txt.txt",
            "https://raw.githubusercontent.com/adrianamarie27/redhat-dora-compliance-tool/main/dora_requirements.txt"
        ]
        
        content = None
        source = None
        
        # Try online sources first
        for url in online_urls:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    content = response.text
                    source = "online"
                    break
                else:
                    # Log the error for debugging
                    if 'requirements_fetch_error' not in st.session_state:
                        st.session_state.requirements_fetch_error = f"HTTP {response.status_code} for {url}"
            except Exception as e:
                # Log the error for debugging
                if 'requirements_fetch_error' not in st.session_state:
                    st.session_state.requirements_fetch_error = str(e)
                continue
        
        # Fallback to local files if online fetch fails
        if content is None:
            file_paths = ['dora_requirements.txt', 'dora_requirements.txt.txt']
            for file_path in file_paths:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    source = "local"
                    break
                except FileNotFoundError:
                    continue
        
        if content is None:
            st.error("Error: Unable to load DORA requirements from online source or local file.")
            return None
        
        lines = content.strip().split('\n')
        pillars_requirements = {}
        current_pillar = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('Pillar'):
                if ':' in line:
                    current_pillar = line.split(':', 1)[1].strip()
                    if current_pillar not in pillars_requirements:
                        pillars_requirements[current_pillar] = {"requirements": []}
            elif line.startswith('Requirement:'):
                req_text = line.replace('Requirement:', '').strip()
                if current_pillar and req_text:
                    keywords = generate_keywords_from_requirement(req_text)
                    pillars_requirements[current_pillar]["requirements"].append({
                        "text": req_text,
                        "keywords": keywords
                    })
        
        # Log source for debugging (only show once per session)
        if 'requirements_source_shown' not in st.session_state:
            if source == "online":
                st.success("✅ Loaded DORA requirements from online source (always up-to-date)")
            elif source == "local":
                error_info = ""
                if 'requirements_fetch_error' in st.session_state:
                    error_info = f" Error: {st.session_state.requirements_fetch_error}"
                st.warning(f"⚠️ Loaded from local file (online failed{error_info}). App works but won't auto-update.")
            st.session_state.requirements_source_shown = True
        
        # Also store source for debugging
        if 'requirements_source' not in st.session_state:
            st.session_state.requirements_source = source
        
        return pillars_requirements
    except Exception as e:
        st.error(f"Error loading DORA requirements: {str(e)}")
        return None

def generate_keywords_from_requirement(req_text):
    """Generate search keywords from requirement text."""
    req_lower = req_text.lower()
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'must', 'should', 'may', 'can', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'shall'}
    
    words = re.findall(r'\b\w+\b', req_lower)
    important_words = [w for w in words if w not in stop_words and len(w) > 3]
    
    keywords = [req_lower]
    
    for i in range(len(important_words) - 1):
        bigram = f"{important_words[i]} {important_words[i+1]}"
        if len(bigram) > 5:
            keywords.append(bigram)
    
    keywords.extend([w for w in important_words if len(w) > 4])
    
    # Add common acronyms
    if 'rmf' in req_lower or 'risk management framework' in req_lower:
        keywords.extend(['rmf', 'risk management framework'])
    if 'tlpt' in req_lower or 'threat-led' in req_lower:
        keywords.extend(['tlpt', 'threat-led penetration testing', 'threat-led'])
    if 'cif' in req_lower or 'critical/important functions' in req_lower:
        keywords.extend(['cif', 'critical important functions'])
    if 'ttp' in req_lower or 'ioc' in req_lower:
        keywords.extend(['ttp', 'ioc', 'indicators of compromise'])
    if 'rca' in req_lower or 'root cause' in req_lower:
        keywords.extend(['rca', 'root cause analysis'])
    
    return list(set(keywords))

def extract_text_from_file(file_content, file_name):
    """Extract text from file content based on file type."""
    file_type = file_name.split('.')[-1].lower()
    
    try:
        if file_type == 'pdf':
            pdf_reader = pypdf.PdfReader(io.BytesIO(file_content))
            text = ""
            for page in pdf_reader.pages:
                page_text = page.extract_text()
                # Clean up common PDF extraction issues
                page_text = re.sub(r'\s+', ' ', page_text)  # Normalize whitespace
                text += page_text + "\n"
            # Apply additional cleaning
            text = clean_text(text)
            return text
        
        elif file_type == 'docx':
            doc = Document(io.BytesIO(file_content))
            text = "\n".join([paragraph.text for paragraph in doc.paragraphs])
            # Clean up text
            text = clean_text(text)
            return text
        
        elif file_type == 'txt':
            text = file_content.decode('utf-8')
            # Clean up text
            text = clean_text(text)
            return text
        
        else:
            st.error(f"Unsupported file type: {file_type}")
            return None
    
    except Exception as e:
        st.error(f"Error extracting text from file: {str(e)}")
        return None

def clean_text(text):
    """Clean extracted text to fix common OCR/PDF extraction errors."""
    # Fix common OCR errors
    replacements = {
        r'\s+': ' ',  # Multiple spaces to single space
        r'([a-z])([A-Z])': r'\1 \2',  # Add space between lowercase and uppercase
        r'([.!?])([A-Z])': r'\1 \2',  # Add space after punctuation
    }
    
    # Fix common typos from PDF extraction
    common_fixes = {
        'rn': 'm',  # Common OCR error
        'vv': 'w',
        'ii': 'n',
        'I I': 'H',
    }
    
    cleaned = text
    for pattern, replacement in replacements.items():
        cleaned = re.sub(pattern, replacement, cleaned)
    
    # Apply common fixes (be careful not to over-correct)
    for typo, correct in common_fixes.items():
        # Only fix if it's clearly a typo (surrounded by spaces or punctuation)
        cleaned = re.sub(rf'\b{typo}\b', correct, cleaned)
    
    return cleaned

def find_evidence_in_text(policy_text, keywords):
    """Find evidence of requirement compliance in text."""
    # Clean the text first
    policy_cleaned = clean_text(policy_text)
    policy_lower = policy_cleaned.lower()
    policy_normalized = re.sub(r'\s+', ' ', policy_lower)
    
    found_keywords = []
    evidence_snippets = []
    
    for keyword in keywords:
        if keyword in policy_normalized:
            found_keywords.append(keyword)
            # Find context around keyword
            idx = policy_normalized.find(keyword)
            start = max(0, idx - 150)
            end = min(len(policy_normalized), idx + len(keyword) + 150)
            snippet = policy_normalized[start:end].strip()
            # Clean snippet and capitalize first letter for readability
            snippet = snippet.capitalize()
            evidence_snippets.append(snippet)
    
    return found_keywords, evidence_snippets

def get_mitigating_controls(pillar, gap_type):
    """Get mitigating controls for a specific gap."""
    if pillar in MITIGATING_CONTROLS:
        if gap_type in MITIGATING_CONTROLS[pillar]:
            return MITIGATING_CONTROLS[pillar][gap_type]
    return []

def analyze_policy_enhanced(policy_text, document_name=""):
    """Enhanced analysis with detailed justifications and gap analysis."""
    if not policy_text:
        return []
    
    pillars_requirements = load_dora_requirements()
    if not pillars_requirements:
        return []
    
    policy_lower = policy_text.lower()
    policy_normalized = re.sub(r'\s+', ' ', policy_lower)
    
    results = []
    
    for pillar, pillar_data in pillars_requirements.items():
        requirements = pillar_data["requirements"]
        total_requirements = len(requirements)
        requirement_details = []
        
        for req in requirements:
            keywords = req["keywords"]
            found_keywords, evidence_snippets = find_evidence_in_text(policy_text, keywords)
            
            # Calculate compliance score
            keyword_match_ratio = len(found_keywords) / len(keywords) if keywords else 0
            
            # Create detailed justification with context
            keyword_explanation = (
                f"The analysis searched for {len(keywords)} key terms and phrases related to this requirement "
                f"(such as '{keywords[0] if keywords else 'N/A'}' and related concepts). "
                f"Found {len(found_keywords)} matching terms in the document. "
            )
            
            if keyword_match_ratio >= 0.7:  # 70% or more keywords found
                status = "Met"
                status_explanation = (
                    "✅ **MET** - The requirement appears to be fully addressed. "
                    "The document contains sufficient evidence (70%+ of key terms found) indicating this requirement is covered."
                )
                justification = (
                    keyword_explanation +
                    f"This indicates strong evidence that the requirement is addressed in the document. "
                    f"Key terms found: {', '.join(found_keywords[:5])}" + 
                    (f" and {len(found_keywords) - 5} more" if len(found_keywords) > 5 else "")
                )
            elif keyword_match_ratio >= 0.4:  # 40-70% keywords found
                status = "Partial"
                status_explanation = (
                    "⚠️ **PARTIAL** - The requirement may be partially addressed but needs manual verification. "
                    "Some key terms were found (40-70%), but the requirement may not be fully covered or may need clarification."
                )
                justification = (
                    keyword_explanation +
                    f"This suggests the requirement might be addressed, but the evidence is incomplete. "
                    f"Manual review recommended to verify full compliance. "
                    f"Terms found: {', '.join(found_keywords[:5])}" +
                    (f" and {len(found_keywords) - 5} more" if len(found_keywords) > 5 else "") +
                    f". Missing terms may indicate gaps in coverage."
                )
            else:
                status = "Missing"
                status_explanation = (
                    "❌ **MISSING** - The requirement appears to be missing or inadequately addressed. "
                    "Less than 40% of key terms were found, suggesting this requirement is not covered in the document."
                )
                justification = (
                    keyword_explanation +
                    f"This indicates weak or insufficient evidence that the requirement is addressed. "
                    f"The document likely does not adequately cover this requirement. "
                    f"Action required: Add content addressing this requirement to achieve compliance."
                )
            
            # Determine gap type for mitigating controls
            gap_type = None
            req_lower = req["text"].lower()
            if 'risk management framework' in req_lower or 'rmf' in req_lower:
                gap_type = "missing_rmf"
            elif 'asset' in req_lower or 'dependency' in req_lower:
                gap_type = "missing_asset_inventory"
            elif 'role' in req_lower or 'responsibility' in req_lower or 'governance' in req_lower:
                gap_type = "missing_governance"
            elif 'classifying' in req_lower or 'classification' in req_lower:
                gap_type = "missing_classification"
            elif 'reporting' in req_lower:
                gap_type = "missing_reporting"
            elif 'root cause' in req_lower or 'rca' in req_lower:
                gap_type = "missing_rca"
            elif 'testing program' in req_lower or 'vulnerability' in req_lower or 'penetration' in req_lower:
                gap_type = "missing_testing_program"
            elif 'tlpt' in req_lower or 'threat-led' in req_lower:
                gap_type = "missing_tlpt"
            elif 'remediation' in req_lower or 'weakness' in req_lower:
                gap_type = "missing_remediation"
            elif 'register' in req_lower or 'vendor' in req_lower or 'cif' in req_lower:
                gap_type = "missing_vendor_register"
            elif 'exit strategy' in req_lower or 'exit' in req_lower:
                gap_type = "missing_exit_strategy"
            elif 'audit' in req_lower or 'inspection' in req_lower:
                gap_type = "missing_audit_rights"
            elif 'sharing' in req_lower or 'ttp' in req_lower or 'ioc' in req_lower:
                gap_type = "missing_sharing_mechanisms"
            elif 'confidentiality' in req_lower or 'security' in req_lower:
                gap_type = "missing_confidentiality"
            
            mitigating_controls = []
            if status != "Met" and gap_type:
                mitigating_controls = get_mitigating_controls(pillar, gap_type)
            
            requirement_details.append({
                "requirement": req["text"],
                "status": status,
                "justification": justification,
                "status_explanation": status_explanation,
                "evidence_snippets": evidence_snippets[:5],  # Limit to 5 snippets
                "found_keywords": found_keywords,
                "mitigating_controls": mitigating_controls
            })
        
        # Calculate overall pillar status
        met_count = sum(1 for r in requirement_details if r["status"] == "Met")
        partial_count = sum(1 for r in requirement_details if r["status"] == "Partial")
        missing_count = sum(1 for r in requirement_details if r["status"] == "Missing")
        
        if met_count == total_requirements:
            overall_status = "Met"
        elif met_count > 0 or partial_count > 0:
            overall_status = "Partial"
        else:
            overall_status = "Missing"
        
        # Collect gaps for this pillar with Red Hat risk assessment
        gaps = []
        for req_detail in requirement_details:
            if req_detail["status"] != "Met":
                # Get gap type from requirement details (already determined above)
                gap_type = None
                req_lower = req_detail["requirement"].lower()
                if 'risk management framework' in req_lower or 'rmf' in req_lower:
                    gap_type = "missing_rmf"
                elif 'asset' in req_lower or 'dependency' in req_lower:
                    gap_type = "missing_asset_inventory"
                elif 'role' in req_lower or 'responsibility' in req_lower or 'governance' in req_lower:
                    gap_type = "missing_governance"
                elif 'classifying' in req_lower or 'classification' in req_lower:
                    gap_type = "missing_classification"
                elif 'reporting' in req_lower:
                    gap_type = "missing_reporting"
                elif 'root cause' in req_lower or 'rca' in req_lower:
                    gap_type = "missing_rca"
                elif 'testing program' in req_lower or 'vulnerability' in req_lower or 'penetration' in req_lower:
                    gap_type = "missing_testing_program"
                elif 'tlpt' in req_lower or 'threat-led' in req_lower:
                    gap_type = "missing_tlpt"
                elif 'remediation' in req_lower or 'weakness' in req_lower:
                    gap_type = "missing_remediation"
                elif 'register' in req_lower or 'vendor' in req_lower or 'cif' in req_lower:
                    gap_type = "missing_vendor_register"
                elif 'exit strategy' in req_lower or 'exit' in req_lower:
                    gap_type = "missing_exit_strategy"
                elif 'audit' in req_lower or 'inspection' in req_lower:
                    gap_type = "missing_audit_rights"
                elif 'sharing' in req_lower or 'ttp' in req_lower or 'ioc' in req_lower:
                    gap_type = "missing_sharing_mechanisms"
                elif 'confidentiality' in req_lower or 'security' in req_lower:
                    gap_type = "missing_confidentiality"
                
                # Get Red Hat risk assessment
                risk_assessment = None
                if REDHAT_RISK_AVAILABLE and gap_type:
                    risk_assessment = get_redhat_risk_assessment(gap_type, pillar, req_detail["status"])
                
                gaps.append({
                    "requirement": req_detail["requirement"],
                    "status": req_detail["status"],
                    "justification": req_detail["justification"],
                    "mitigating_controls": req_detail["mitigating_controls"],
                    "severity": "High" if req_detail["status"] == "Missing" else "Medium",
                    "risk_assessment": risk_assessment,
                    "gap_type": gap_type
                })
        
        results.append({
            "pillar": pillar,
            "overall_status": overall_status,
            "requirement_details": requirement_details,
            "met_count": met_count,
            "partial_count": partial_count,
            "missing_count": missing_count,
            "total_requirements": total_requirements,
            "document_name": document_name,
            "gaps": gaps,
            "gap_count": len(gaps)
        })
    
    return results

# Google Drive Integration Functions
def authenticate_google_drive(credentials_file=None, token_file=None):
    """Authenticate with Google Drive API."""
    if not GOOGLE_DRIVE_AVAILABLE:
        st.error("Google Drive API libraries not available. Please install required packages.")
        return None
    
    SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
    
    try:
        # Try Streamlit secrets first (for cloud deployment)
        try:
            if 'google_drive' in st.secrets:
                gd_secrets = st.secrets['google_drive']
                # If service_account_file is JSON string in secrets, parse it
                if 'service_account_file' in gd_secrets:
                    sa_content = gd_secrets['service_account_file']
                    if isinstance(sa_content, str) and sa_content.strip().startswith('{'):
                        # It's a JSON string, create temp file
                        import tempfile
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                            f.write(sa_content)
                            temp_file = f.name
                        creds = service_account.Credentials.from_service_account_file(
                            temp_file, scopes=SCOPES)
                        service = build('drive', 'v3', credentials=creds)
                        os.unlink(temp_file)  # Clean up temp file
                        return service
                    elif os.path.exists(sa_content):
                        # It's a file path
                        creds = service_account.Credentials.from_service_account_file(
                            sa_content, scopes=SCOPES)
                        service = build('drive', 'v3', credentials=creds)
                        return service
        except (AttributeError, KeyError, FileNotFoundError):
            pass  # No secrets available, continue with file-based config
        
        # Try service account authentication first
        if credentials_file and os.path.exists(credentials_file):
            creds = service_account.Credentials.from_service_account_file(
                credentials_file, scopes=SCOPES)
            service = build('drive', 'v3', credentials=creds)
            return service
        
        # Try OAuth2 flow
        if token_file and os.path.exists(token_file):
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
            if creds and creds.valid:
                service = build('drive', 'v3', credentials=creds)
                return service
        
        # Check for credentials in config
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                config = json.load(f)
                if 'google_drive' in config:
                    gd_config = config['google_drive']
                    if 'service_account_file' in gd_config:
                        creds = service_account.Credentials.from_service_account_file(
                            gd_config['service_account_file'], scopes=SCOPES)
                        service = build('drive', 'v3', credentials=creds)
                        return service
        
        return None
    except Exception as e:
        st.error(f"Error authenticating with Google Drive: {str(e)}")
        return None

def list_google_drive_files(service, folder_id=None, file_types=None):
    """List files from Google Drive."""
    if not service:
        return []
    
    try:
        query = "trashed=false"
        if folder_id:
            query += f" and '{folder_id}' in parents"
        if file_types:
            mime_types = []
            for ft in file_types:
                if ft == 'pdf':
                    mime_types.append("application/pdf")
                elif ft == 'docx':
                    mime_types.append("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                elif ft == 'txt':
                    mime_types.append("text/plain")
            if mime_types:
                query += f" and ({' or '.join([f'mimeType=\"{mt}\"' for mt in mime_types])})"
        
        results = service.files().list(
            q=query,
            pageSize=100,
            fields="files(id, name, mimeType, modifiedTime, size)"
        ).execute()
        
        return results.get('files', [])
    except HttpError as error:
        st.error(f"Error listing Google Drive files: {str(error)}")
        return []

def download_google_drive_file(service, file_id):
    """Download a file from Google Drive."""
    if not service:
        return None, None
    
    try:
        # Get file metadata
        file_metadata = service.files().get(fileId=file_id).execute()
        file_name = file_metadata.get('name')
        
        # Download file content
        request = service.files().get_media(fileId=file_id)
        file_content = io.BytesIO()
        downloader = MediaIoBaseDownload(file_content, request)
        
        done = False
        while done is False:
            status, done = downloader.next_chunk()
        
        file_content.seek(0)
        return file_content.read(), file_name
    except HttpError as error:
        st.error(f"Error downloading file: {str(error)}")
        return None, None

def generate_compliance_report(results):
    """Generate a comprehensive compliance report."""
    report = []
    report.append("# DORA Compliance Analysis Report\n")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report.append("---\n\n")
    
    # Executive Summary
    total_pillars = len(results)
    met_pillars = sum(1 for r in results if r["overall_status"] == "Met")
    partial_pillars = sum(1 for r in results if r["overall_status"] == "Partial")
    missing_pillars = sum(1 for r in results if r["overall_status"] == "Missing")
    total_gaps = sum(r["gap_count"] for r in results)
    high_severity_gaps = sum(1 for r in results for gap in r["gaps"] if gap["severity"] == "High")
    
    report.append("## Executive Summary\n\n")
    report.append(f"- **Total Pillars Analyzed:** {total_pillars}\n")
    report.append(f"- **✅ Fully Compliant:** {met_pillars}\n")
    report.append(f"- **⚠️ Partially Compliant:** {partial_pillars}\n")
    report.append(f"- **❌ Non-Compliant:** {missing_pillars}\n")
    report.append(f"- **🔴 Total Gaps Identified:** {total_gaps}\n")
    report.append(f"- **⚠️ High Severity Gaps:** {high_severity_gaps}\n\n")
    report.append("---\n\n")
    
    # Gap Summary Section
    if total_gaps > 0:
        report.append("## 🔴 Gap Summary by Pillar\n\n")
        report.append("This section highlights all compliance gaps identified across all DORA pillars.\n\n")
        
        for result in results:
            if result["gap_count"] > 0:
                report.append(f"### {result['pillar']} - {result['gap_count']} Gap(s)\n\n")
                for i, gap in enumerate(result["gaps"], 1):
                    severity_icon = "🔴" if gap["severity"] == "High" else "🟡"
                    status_icon = "❌" if gap["status"] == "Missing" else "⚠️"
                report.append(f"**{severity_icon} Gap #{i} ({gap['severity']} Severity):** {status_icon} {gap['requirement']}\n\n")
                report.append(f"*Justification:* {gap['justification']}\n\n")
                
                # Red Hat Risk Assessment
                if gap.get("risk_assessment"):
                    risk = gap["risk_assessment"]
                    risk_icon = "🔴" if risk["level"] == "Critical" else "🟠" if risk["level"] == "High" else "🟡" if risk["level"] == "Medium" else "🟢"
                    report.append(f"**{risk_icon} Red Hat Risk Assessment (as ICT Provider):**\n\n")
                    report.append(f"- **Risk Level:** {risk['level']} (Score: {risk['score']}/100)\n")
                    report.append(f"- **Context:** {risk['description']}\n\n")
                    if risk.get("factors"):
                        report.append("**Risk Factors:**\n")
                        for factor in format_risk_factors(risk["factors"]):
                            report.append(f"- {factor}\n")
                        report.append("\n")
                
                if gap["mitigating_controls"]:
                    report.append("**Recommended Actions:**\n")
                    for j, control in enumerate(gap["mitigating_controls"], 1):
                        report.append(f"{j}. {control}\n")
                    report.append("\n")
                report.append("---\n\n")
        
        report.append("\n## Detailed Pillar Analysis\n\n")
    
    # Detailed Analysis
    for result in results:
        pillar = result["pillar"]
        status = result["overall_status"]
        status_icon = "✅" if status == "Met" else "⚠️" if status == "Partial" else "❌"
        
        report.append(f"## {status_icon} {pillar}\n\n")
        report.append(f"**Overall Compliance Status:** {status}\n\n")
        report.append(f"**Requirements Met:** {result['met_count']}/{result['total_requirements']}\n")
        report.append(f"**Gaps Identified:** {result['gap_count']}\n\n")
        
        # Highlight gaps prominently at the start of each pillar section
        if result["gap_count"] > 0:
            report.append("### 🔴 Compliance Gaps in This Pillar\n\n")
            for i, gap in enumerate(result["gaps"], 1):
                severity_icon = "🔴" if gap["severity"] == "High" else "🟡"
                status_icon = "❌" if gap["status"] == "Missing" else "⚠️"
                report.append(f"**{severity_icon} Gap #{i} - {gap['severity']} Severity:**\n\n")
                report.append(f"{status_icon} **Requirement:** {gap['requirement']}\n\n")
                report.append(f"**Issue:** {gap['justification']}\n\n")
                
                # Red Hat Risk Assessment
                if gap.get("risk_assessment"):
                    risk = gap["risk_assessment"]
                    risk_icon = "🔴" if risk["level"] == "Critical" else "🟠" if risk["level"] == "High" else "🟡" if risk["level"] == "Medium" else "🟢"
                    report.append(f"**{risk_icon} Red Hat Risk Assessment (as ICT Provider):**\n\n")
                    report.append(f"- **Risk Level:** {risk['level']} (Score: {risk['score']}/100)\n")
                    report.append(f"- **Context:** {risk['description']}\n\n")
                    if risk.get("factors"):
                        report.append("**Risk Factors:**\n")
                        for factor in format_risk_factors(risk["factors"]):
                            report.append(f"  - {factor}\n")
                        report.append("\n")
                
                if gap["mitigating_controls"]:
                    report.append("**🚀 Recommended Mitigating Controls:**\n")
                    for j, control in enumerate(gap["mitigating_controls"], 1):
                        report.append(f"   {j}. {control}\n")
                    report.append("\n")
            report.append("---\n\n")
        
        report.append("### All Requirements Analysis\n\n")
        
        for req_detail in result["requirement_details"]:
            req_status = req_detail["status"]
            status_icon = "✅" if req_status == "Met" else "⚠️" if req_status == "Partial" else "❌"
            
            report.append(f"### {status_icon} {req_detail['requirement']}\n\n")
            report.append(f"**Status:** {req_status}\n\n")
            report.append(f"**Justification:** {req_detail['justification']}\n\n")
            
            if req_detail["evidence_snippets"]:
                report.append("**Evidence Found:**\n")
                for snippet in req_detail["evidence_snippets"]:
                    report.append(f"- *{snippet[:200]}...*\n")
                report.append("\n")
            
            if req_detail["mitigating_controls"]:
                report.append("**Recommended Mitigating Controls:**\n")
                for i, control in enumerate(req_detail["mitigating_controls"], 1):
                    report.append(f"{i}. {control}\n")
                report.append("\n")
        
        report.append("---\n\n")
    
    return "\n".join(report)

def generate_json_report(results):
    """Generate JSON format report for programmatic access."""
    report_data = {
        "metadata": {
            "generated": datetime.now().isoformat(),
            "document": results[0]["document_name"] if results else "Unknown",
            "total_pillars": len(results)
        },
        "summary": {
            "met_pillars": sum(1 for r in results if r["overall_status"] == "Met"),
            "partial_pillars": sum(1 for r in results if r["overall_status"] == "Partial"),
            "missing_pillars": sum(1 for r in results if r["overall_status"] == "Missing"),
            "total_gaps": sum(r["gap_count"] for r in results),
            "high_severity_gaps": sum(1 for r in results for gap in r["gaps"] if gap["severity"] == "High")
        },
        "pillars": results
    }
    return json.dumps(report_data, indent=2, ensure_ascii=False)

def generate_csv_report(results):
    """Generate CSV format report for spreadsheet analysis."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "Pillar", "Requirement", "Status", "Severity", "Justification", 
        "Risk Level", "Risk Score", "Mitigating Controls"
    ])
    
    # Data rows
    for result in results:
        pillar = result["pillar"]
        for req_detail in result["requirement_details"]:
            status = req_detail["status"]
            requirement = req_detail["requirement"]
            justification = req_detail["justification"]
            
            # Check if this requirement has a gap
            gap = next((g for g in result["gaps"] if g["requirement"] == requirement), None)
            severity = gap["severity"] if gap else "N/A"
            risk_level = gap.get("risk_assessment", {}).get("level", "N/A") if gap else "N/A"
            risk_score = gap.get("risk_assessment", {}).get("score", "N/A") if gap else "N/A"
            controls = "; ".join(gap["mitigating_controls"]) if gap and gap.get("mitigating_controls") else "N/A"
            
            writer.writerow([
                pillar, requirement, status, severity, justification,
                risk_level, risk_score, controls
            ])
    
    return output.getvalue()

def get_download_button_for_file(file_content, file_name, button_label="📥 Download Original Document"):
    """Create a download button for binary file content."""
    b64 = base64.b64encode(file_content).decode()
    file_extension = file_name.split('.')[-1].lower()
    
    mime_types = {
        'pdf': 'application/pdf',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'txt': 'text/plain'
    }
    mime_type = mime_types.get(file_extension, 'application/octet-stream')
    
    href = f'<a href="data:{mime_type};base64,{b64}" download="{file_name}" style="text-decoration: none;">{button_label}</a>'
    return href

# Main UI
def check_password():
    """Check if user has entered correct password."""
    import os
    
    # Try to get password from Streamlit secrets (for cloud deployment)
    correct_password = None
    
    # Check Streamlit secrets (for cloud deployment)
    # Catch StreamlitSecretNotFoundError which is raised when secrets.toml doesn't exist
    try:
        # Try to access secrets - this will raise StreamlitSecretNotFoundError if file doesn't exist
        if 'app_password' in st.secrets:
            correct_password = st.secrets['app_password']
    except Exception as e:
        # Secrets file doesn't exist or can't be accessed - this is fine for local development
        # StreamlitSecretNotFoundError or other exceptions are expected here
        # App will work without password for local development
        pass
    
    # Fallback: check environment variable
    if not correct_password:
        correct_password = os.getenv('APP_PASSWORD', '')
    
    # If no password is set anywhere, allow access (for local development)
    if not correct_password:
        return True
    
    # If password is set, require authentication
    if 'password_entered' not in st.session_state:
        st.session_state.password_entered = False
    
    if not st.session_state.password_entered:
        st.title("🔒 DORA Compliance Analyzer")
        st.markdown("### Password Required")
        
        password_input = st.text_input(
            "Enter password to access the application:",
            type="password",
            help="Contact the administrator for access"
        )
        
        if st.button("🔓 Unlock", type="primary"):
            if password_input == correct_password:
                st.session_state.password_entered = True
                st.rerun()
            else:
                st.error("❌ Incorrect password. Please try again.")
        
        st.markdown("---")
        st.caption("This application is password protected. Please contact your administrator for access.")
        st.stop()
    
    return True

def main():
    # Check password first
    check_password()
    
    st.title("📋 DORA Compliance Analyzer - ICT Service Provider Edition")
    st.markdown("**Comprehensive tool for ICT service providers to verify documentation adherence to DORA pillar requirements**")
    st.info("ℹ️ This tool assesses DORA compliance from an **ICT Service Provider** perspective, focusing on obligations relevant to providers of critical ICT services to financial entities.")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Help section
        with st.expander("ℹ️ Understanding Status Indicators", expanded=False):
            st.markdown("""
            **Status Meanings:**
            
            **✅ MET** - Requirement is fully addressed
            - 70%+ of key terms found
            - Strong evidence of compliance
            - No action needed
            
            **⚠️ PARTIAL** - Requirement may be partially addressed
            - 40-70% of key terms found
            - Some evidence, but may need clarification
            - Manual review recommended
            
            **❌ MISSING** - Requirement appears missing
            - Less than 40% of key terms found
            - Weak or insufficient evidence
            - Action required to achieve compliance
            
            **How it works:**
            The analyzer searches for key terms and phrases related to each DORA requirement. 
            The percentage of terms found indicates how well the requirement is covered.
            """)
        
        st.markdown("---")
        
        # Data source selection
        data_source = st.radio(
            "Data Source",
            ["Local File Upload", "Google Drive"],
            help="Choose where to get documents from"
        )
        
        # Google Drive configuration
        if data_source == "Google Drive":
            st.subheader("Google Drive Settings")
            
            if GOOGLE_DRIVE_AVAILABLE:
                credentials_file = st.text_input(
                    "Service Account JSON File Path",
                    value="",
                    help="Path to Google Service Account credentials JSON file"
                )
                
                folder_id = st.text_input(
                    "Google Drive Folder ID",
                    value="",
                    help="ID of the folder containing documents (leave empty for root)"
                )
                
                if st.button("🔗 Connect to Google Drive"):
                    if credentials_file and os.path.exists(credentials_file):
                        with st.spinner("Authenticating with Google Drive..."):
                            service = authenticate_google_drive(credentials_file=credentials_file)
                            if service:
                                st.session_state.google_drive_service = service
                                st.success("✅ Connected to Google Drive")
                            else:
                                st.error("❌ Failed to connect to Google Drive")
                    else:
                        st.warning("Please provide a valid credentials file path")
            else:
                st.error("Google Drive API not available. Install required packages.")
        
        # Proxy/VPN configuration
        st.subheader("VPN/Proxy Settings")
        use_proxy = st.checkbox("Use Proxy/VPN", help="Enable if accessing resources behind VPN")
        if use_proxy:
            proxy_http = st.text_input("HTTP Proxy", value=os.getenv('HTTP_PROXY', ''))
            proxy_https = st.text_input("HTTPS Proxy", value=os.getenv('HTTPS_PROXY', ''))
            if proxy_http:
                os.environ['HTTP_PROXY'] = proxy_http
            if proxy_https:
                os.environ['HTTPS_PROXY'] = proxy_https
    
    # Main content area
    if data_source == "Local File Upload":
        uploaded_file = st.file_uploader(
            "Upload Policy Document",
            type=['pdf', 'docx', 'txt'],
            help="Supported formats: PDF, DOCX, TXT"
        )
        
        if uploaded_file is not None:
            st.info(f"📄 File uploaded: **{uploaded_file.name}** ({uploaded_file.size:,} bytes)")
            
            with st.spinner("Extracting text from document..."):
                file_content = uploaded_file.read()
                policy_text = extract_text_from_file(file_content, uploaded_file.name)
            
            if policy_text:
                st.success(f"✅ Successfully extracted {len(policy_text):,} characters")
                
                # Store document for later download
                uploaded_file.seek(0)  # Reset file pointer
                st.session_state.current_document = uploaded_file.read()
                st.session_state.current_document_name = uploaded_file.name
                
                if st.button("🔍 Analyze Policy", type="primary"):
                    with st.spinner("Analyzing policy against DORA requirements..."):
                        results = analyze_policy_enhanced(policy_text, uploaded_file.name)
                    
                    if results:
                        display_results(results)
        
    elif data_source == "Google Drive":
        if not st.session_state.google_drive_service:
            st.warning("⚠️ Please connect to Google Drive first using the sidebar configuration.")
        else:
            st.subheader("📁 Google Drive Documents")
            
            # List files
            if st.button("🔄 Refresh File List"):
                with st.spinner("Fetching files from Google Drive..."):
                    files = list_google_drive_files(
                        st.session_state.google_drive_service,
                        folder_id=folder_id if 'folder_id' in locals() else None,
                        file_types=['pdf', 'docx', 'txt']
                    )
                    
                    if files:
                        st.session_state.drive_files = files
                        st.success(f"✅ Found {len(files)} document(s)")
                    else:
                        st.warning("No documents found")
            
            if 'drive_files' in st.session_state and st.session_state.drive_files:
                file_options = {f["name"]: f["id"] for f in st.session_state.drive_files}
                selected_file = st.selectbox("Select a document to analyze", list(file_options.keys()))
                
                if st.button("📥 Download & Analyze", type="primary"):
                    file_id = file_options[selected_file]
                    with st.spinner(f"Downloading {selected_file}..."):
                        file_content, file_name = download_google_drive_file(
                            st.session_state.google_drive_service, file_id
                        )
                    
                    if file_content:
                        st.success(f"✅ Downloaded {file_name}")
                        
                        # Store document for later download
                        st.session_state.current_document = file_content
                        st.session_state.current_document_name = file_name
                        
                        with st.spinner("Extracting text..."):
                            policy_text = extract_text_from_file(file_content, file_name)
                        
                        if policy_text:
                            with st.spinner("Analyzing against DORA requirements..."):
                                results = analyze_policy_enhanced(policy_text, file_name)
                            
                            if results:
                                display_results(results)
                    else:
                        st.error("Failed to download file")

def display_results(results):
    """Display comprehensive analysis results."""
    st.markdown("---")
    st.header("📊 DORA Compliance Analysis Results")
    
    # Pillar filter section
    all_pillars = [r["pillar"] for r in results]
    st.markdown("### 🔍 Filter by Pillar")
    
    # Create columns for filter controls
    filter_col1, filter_col2, filter_col3 = st.columns([4, 1, 1])
    
    with filter_col1:
        selected_pillars = st.multiselect(
            "Select pillars to display:",
            options=all_pillars,
            default=all_pillars,
            help="Choose which DORA pillars to view. You can select one or multiple pillars.",
            label_visibility="collapsed"
        )
    
    with filter_col2:
        if st.button("Select All", use_container_width=True):
            selected_pillars = all_pillars
            st.rerun()
    
    with filter_col3:
        if st.button("Clear", use_container_width=True):
            selected_pillars = []
            st.rerun()
    
    # Filter results based on selection
    if not selected_pillars:
        st.warning("⚠️ No pillars selected. Please select at least one pillar to view results.")
        # Still show export options with all results
        st.markdown("---")
        st.header("📤 Export Analysis Results")
        # Show export section inline
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📄 Original Document")
            if st.session_state.current_document and st.session_state.current_document_name:
                st.download_button(
                    label="📥 Download Original Document",
                    data=st.session_state.current_document,
                    file_name=st.session_state.current_document_name,
                    mime="application/octet-stream",
                    help="Download the analyzed document for further work"
                )
            else:
                st.info("No document available for download")
        with col2:
            st.subheader("📊 Analysis Reports")
            st.markdown("Export analysis results in different formats:")
        export_col1, export_col2, export_col3 = st.columns(3)
        with export_col1:
            report = generate_compliance_report(results)
            st.download_button(
                label="📝 Download Markdown Report",
                data=report,
                file_name=f"dora_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                help="Full detailed report in Markdown format"
            )
        with export_col2:
            json_report = generate_json_report(results)
            st.download_button(
                label="📋 Download JSON Report",
                data=json_report,
                file_name=f"dora_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                help="Structured data in JSON format for programmatic access"
            )
        with export_col3:
            csv_report = generate_csv_report(results)
            st.download_button(
                label="📊 Download CSV Report",
                data=csv_report,
                file_name=f"dora_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                help="Spreadsheet-compatible CSV format"
            )
        return
    
    filtered_results = [r for r in results if r["pillar"] in selected_pillars]
    
    # Show filter status
    if len(selected_pillars) < len(all_pillars):
        st.info(f"📋 Showing {len(selected_pillars)} of {len(all_pillars)} pillar(s): {', '.join(selected_pillars)}")
    
    # Summary metrics (for filtered results)
    col1, col2, col3, col4 = st.columns(4)
    total_pillars = len(filtered_results)
    met_pillars = sum(1 for r in filtered_results if r["overall_status"] == "Met")
    partial_pillars = sum(1 for r in filtered_results if r["overall_status"] == "Partial")
    missing_pillars = sum(1 for r in filtered_results if r["overall_status"] == "Missing")
    
    with col1:
        st.metric("Total Pillars", total_pillars)
    with col2:
        st.metric("✅ Fully Compliant", met_pillars)
    with col3:
        st.metric("⚠️ Partially Compliant", partial_pillars)
    with col4:
        st.metric("❌ Non-Compliant", missing_pillars)
    
    if len(selected_pillars) < len(all_pillars):
        st.info(f"📋 Showing {len(selected_pillars)} of {len(all_pillars)} pillars: {', '.join(selected_pillars)}")
    
    st.markdown("---")
    
    # Detailed results for each filtered pillar
    for result in filtered_results:
        status_icon = "✅" if result["overall_status"] == "Met" else "⚠️" if result["overall_status"] == "Partial" else "❌"
        with st.expander(f"{status_icon} **{result['pillar']}** - {result['overall_status']}", expanded=True):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Requirements Met:** {result['met_count']}/{result['total_requirements']}")
            with col2:
                if result['gap_count'] > 0:
                    st.markdown(f"**🔴 Gaps Identified:** {result['gap_count']}")
                else:
                    st.markdown("**✅ No Gaps**")
            
            # Highlight gaps prominently at the start
            if result["gap_count"] > 0:
                st.markdown("---")
                st.subheader("🔴 Compliance Gaps in This Pillar")
                for i, gap in enumerate(result["gaps"], 1):
                    severity_color = "🔴" if gap["severity"] == "High" else "🟡"
                    status_icon = "❌" if gap["status"] == "Missing" else "⚠️"
                    
                    with st.container():
                        st.markdown(f"**{severity_color} Gap #{i} - {gap['severity']} Severity**")
                        st.markdown(f"{status_icon} **Requirement:** {gap['requirement']}")
                        st.markdown(f"**Issue:** {gap['justification']}")
                        
                        # Red Hat Risk Assessment
                        if gap.get("risk_assessment"):
                            risk = gap["risk_assessment"]
                            risk_color = "red" if risk["level"] == "Critical" else "orange" if risk["level"] == "High" else "yellow" if risk["level"] == "Medium" else "green"
                            risk_icon = "🔴" if risk["level"] == "Critical" else "🟠" if risk["level"] == "High" else "🟡" if risk["level"] == "Medium" else "🟢"
                            
                            with st.expander(f"{risk_icon} Red Hat Risk Assessment (as ICT Provider) - {risk['level']} Risk (Score: {risk['score']}/100)", expanded=True):
                                st.markdown(f"**Context:** {risk['description']}")
                                if risk.get("factors"):
                                    st.markdown("**Risk Factors:**")
                                    for factor in format_risk_factors(risk["factors"]):
                                        st.markdown(f"- {factor}")
                        
                        if gap["mitigating_controls"]:
                            st.markdown("**🚀 Recommended Mitigating Controls:**")
                            for j, control in enumerate(gap["mitigating_controls"], 1):
                                st.markdown(f"{j}. {control}")
                        st.markdown("---")
                
                st.markdown("### All Requirements Analysis")
                st.markdown("---")
            
            for req_detail in result["requirement_details"]:
                status_icon = "✅" if req_detail["status"] == "Met" else "⚠️" if req_detail["status"] == "Partial" else "❌"
                
                # Display the actual DORA requirement/regulation prominently
                st.markdown("---")
                st.markdown(f"### {status_icon} DORA Regulation Requirement")
                with st.container():
                    st.markdown(f"**{req_detail['requirement']}**")
                    st.caption("📋 This is the actual DORA requirement that must be addressed in your documentation.")
                
                # Status with explanation
                status = req_detail['status']
                col1, col2 = st.columns([2, 3])
                with col1:
                    st.markdown(f"**Compliance Status:** `{status}`")
                with col2:
                    if req_detail.get("status_explanation"):
                        with st.expander("ℹ️ What does this status mean?", expanded=False):
                            st.markdown(req_detail["status_explanation"])
                
                # Enhanced justification with context
                st.markdown("**📊 Analysis Results:**")
                st.info(req_detail['justification'])
                
                # Show found keywords
                if req_detail.get("found_keywords"):
                    with st.expander(f"🔍 Key Terms Found ({len(req_detail['found_keywords'])} terms)"):
                        keywords_display = ", ".join(req_detail['found_keywords'][:10])
                        if len(req_detail['found_keywords']) > 10:
                            keywords_display += f" ... and {len(req_detail['found_keywords']) - 10} more"
                        st.markdown(f"**Terms detected in document:** {keywords_display}")
                        st.caption("These are the key terms and phrases the analysis searched for to determine compliance.")
                
                if req_detail["evidence_snippets"]:
                    with st.expander(f"📄 View Evidence Snippets ({len(req_detail['evidence_snippets'])} snippets)"):
                        st.caption("These are excerpts from your document where relevant terms were found. "
                                 "Note: Text may contain minor formatting issues from PDF extraction.")
                        for i, snippet in enumerate(req_detail["evidence_snippets"][:5], 1):
                            st.markdown(f"**Snippet {i}:**")
                            # Clean and format snippet for better readability
                            snippet_clean = snippet.replace('\n', ' ').strip()
                            # Limit length and add ellipsis
                            if len(snippet_clean) > 400:
                                snippet_clean = snippet_clean[:400] + "..."
                            st.text(snippet_clean)
                            if i < len(req_detail["evidence_snippets"][:5]):
                                st.markdown("---")
                        if len(req_detail["evidence_snippets"]) > 5:
                            st.caption(f"... and {len(req_detail['evidence_snippets']) - 5} more snippets")
                
                if req_detail["mitigating_controls"]:
                    st.markdown("**Recommended Mitigating Controls:**")
                    for i, control in enumerate(req_detail["mitigating_controls"], 1):
                        st.markdown(f"{i}. {control}")
                
                st.markdown("---")
    
    # Export section - always export all results, not just filtered
    st.markdown("---")
    st.header("📤 Export Analysis Results")
    if len(selected_pillars) < len(all_pillars):
        st.info(f"💡 Note: Exports will include all {len(all_pillars)} pillars, not just the filtered view.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📄 Original Document")
        if st.session_state.current_document and st.session_state.current_document_name:
            st.download_button(
                label="📥 Download Original Document",
                data=st.session_state.current_document,
                file_name=st.session_state.current_document_name,
                mime="application/octet-stream",
                help="Download the analyzed document for further work"
            )
        else:
            st.info("No document available for download")
    
    with col2:
        st.subheader("📊 Analysis Reports")
        st.markdown("Export analysis results in different formats:")
    
    # Export buttons in columns
    export_col1, export_col2, export_col3 = st.columns(3)
    
    with export_col1:
        # Markdown report
        report = generate_compliance_report(results)
        st.download_button(
            label="📝 Download Markdown Report",
            data=report,
            file_name=f"dora_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            help="Full detailed report in Markdown format"
        )
    
    with export_col2:
        # JSON report
        json_report = generate_json_report(results)
        st.download_button(
            label="📋 Download JSON Report",
            data=json_report,
            file_name=f"dora_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            help="Structured data in JSON format for programmatic access"
        )
    
    with export_col3:
        # CSV report
        csv_report = generate_csv_report(results)
        st.download_button(
            label="📊 Download CSV Report",
            data=csv_report,
            file_name=f"dora_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            help="Spreadsheet-compatible CSV format"
        )
    
    # Combined document option
    st.markdown("---")
    with st.expander("🔗 Create Combined Document (Original + Analysis)"):
        st.markdown("Create a single document containing both the original document and the analysis report.")
        
        combined_doc = f"""# DORA Compliance Analysis - Combined Report

**Document Analyzed:** {results[0]["document_name"] if results else "Unknown"}  
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Original Document

*[Original document content would be embedded here]*

---

## Compliance Analysis Report

{report}
"""
        
        st.download_button(
            label="📑 Download Combined Document",
            data=combined_doc,
            file_name=f"dora_combined_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            help="Single document with original content and analysis"
        )
    
    # Save to session state
    st.session_state.analyzed_documents.append({
        "timestamp": datetime.now().isoformat(),
        "document": results[0]["document_name"] if results else "Unknown",
        "results": results
    })

if __name__ == "__main__":
    main()

