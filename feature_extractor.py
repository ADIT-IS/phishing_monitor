# app/feature_extractor.py

import re
import urllib.parse
import tldextract
import numpy as np
from math import log2
from collections import Counter

# Helper Functions
def get_entropy(string):
    if not string:
        return 0
    counter = Counter(string)
    total = len(string)
    return -sum((count / total) * log2(count / total) for count in counter.values())

def count_vowels(s):
    return len(re.findall(r'[aeiouAEIOU]', s))

def count_consonants(s):
    return len(re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]', s))

def is_ip_address(domain):
    return 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0

# Main feature extraction function
def extract_features(url):
    parsed = urllib.parse.urlparse(url)
    ext = tldextract.extract(url)

    domain = parsed.netloc or ext.domain + '.' + ext.suffix
    subdomain = ext.subdomain
    path = parsed.path
    query = parsed.query
    filename = path.split('/')[-1]
    file_ext = filename.split('.')[-1] if '.' in filename else ''
    
    domain_tokens = re.split(r'\W+', domain)
    path_tokens = re.split(r'\W+', path)

    features = {}

    # Binary features
    features['having_IP_Address'] = is_ip_address(domain)
    features['URL_Length'] = len(url)
    features['Shortining_Service'] = 1 if re.search(r'(bit\.ly|goo\.gl|tinyurl\.com|t\.co)', url) else 0
    features['having_At_Symbol'] = 1 if '@' in url else 0
    features['double_slash_redirecting'] = 1 if url.count('//') > 1 else 0
    features['Prefix_Suffix'] = 1 if '-' in ext.domain else 0
    features['having_Sub_Domain'] = 1 if subdomain else 0
    features['SSLfinal_State'] = 1 if parsed.scheme == 'https' else 0
    features['Domain_registeration_length'] = 1  # Placeholder
    features['Favicon'] = 0  # Placeholder
    features['port'] = 1 if ':' in domain else 0
    features['HTTPS_token'] = 1 if 'https' in domain else 0
    features['Request_URL'] = 1 if len(path) else 0
    features['executable'] = 1 if '.exe' in url else 0
    features['isPortEighty'] = 1 if ':80' in domain else 0
    features['ISIpAddressInDomainName'] = 1 if is_ip_address(domain) else 0

    # Token-based features
    features['querylength'] = len(query)
    features['domain_token_count'] = len(domain_tokens)
    features['path_token_count'] = len(path_tokens)
    features['avgdomaintokenlen'] = np.mean([len(t) for t in domain_tokens]) if domain_tokens else 0
    features['longdomaintokenlen'] = max([len(t) for t in domain_tokens]) if domain_tokens else 0
    features['avgpathtokenlen'] = np.mean([len(t) for t in path_tokens]) if path_tokens else 0

    # Character composition
    features['charcompvowels'] = count_vowels(url)
    features['charcompace'] = url.count('%20')
    features['URL_DigitCount'] = sum(c.isdigit() for c in url)
    features['host_DigitCount'] = sum(c.isdigit() for c in domain)
    features['Directory_DigitCount'] = sum(c.isdigit() for c in path)
    features['File_name_DigitCount'] = sum(c.isdigit() for c in filename)
    features['Extension_DigitCount'] = sum(c.isdigit() for c in file_ext)
    features['Query_DigitCount'] = sum(c.isdigit() for c in query)

    features['URL_Letter_Count'] = sum(c.isalpha() for c in url)
    features['host_letter_count'] = sum(c.isalpha() for c in domain)
    features['Directory_LetterCount'] = sum(c.isalpha() for c in path)
    features['Filename_LetterCount'] = sum(c.isalpha() for c in filename)
    features['Extension_LetterCount'] = sum(c.isalpha() for c in file_ext)
    features['Query_LetterCount'] = sum(c.isalpha() for c in query)

    # Length based
    features['ldl_url'] = len(url)
    features['domainlength'] = len(domain)
    features['pathLength'] = len(path)
    features['subDirLen'] = len('/'.join(path.split('/')[:-1]))
    features['fileNameLen'] = len(filename)
    features['ArgLen'] = len(query)
    features['LongestVariableValue'] = max([len(p) for p in query.split('&')]) if query else 0
    features['LongestPathTokenLength'] = max([len(p) for p in path_tokens]) if path_tokens else 0
    features['Domain_LongestWordLength'] = max([len(p) for p in domain_tokens]) if domain_tokens else 0
    features['Path_LongestWordLength'] = max([len(p) for p in path_tokens]) if path_tokens else 0
    features['sub-Directory_LongestWordLength'] = max([len(p) for p in path.split('/')[:-1]]) if '/' in path else 0
    features['Arguments_LongestWordLength'] = max([len(p) for p in query.split('&')]) if query else 0

    # Ratios
    features['pathurlRatio'] = len(path)/len(url) if len(url) else 0
    features['ArgUrlRatio'] = len(query)/len(url) if len(url) else 0
    features['argDomanRatio'] = len(query)/len(domain) if len(domain) else 0
    features['domainUrlRatio'] = len(domain)/len(url) if len(url) else 0
    features['pathDomainRatio'] = len(path)/len(domain) if len(domain) else 0
    features['argPathRatio'] = len(query)/len(path) if len(path) else 0

    # Number rate
    features['NumberRate_URL'] = features['URL_DigitCount']/len(url) if len(url) else 0
    features['NumberRate_Domain'] = features['host_DigitCount']/len(domain) if len(domain) else 0
    features['NumberRate_DirectoryName'] = features['Directory_DigitCount']/len(path) if len(path) else 0
    features['NumberRate_FileName'] = features['File_name_DigitCount']/len(filename) if len(filename) else 0
    features['NumberRate_Extension'] = features['Extension_DigitCount']/len(file_ext) if file_ext else 0
    features['NumberRate_AfterPath'] = features['Query_DigitCount']/len(query) if len(query) else 0

    # Symbol count
    features['SymbolCount_URL'] = len(re.findall(r'\W', url))
    features['SymbolCount_Domain'] = len(re.findall(r'\W', domain))
    features['SymbolCount_Directoryname'] = len(re.findall(r'\W', path))
    features['SymbolCount_FileName'] = len(re.findall(r'\W', filename))
    features['SymbolCount_Extension'] = len(re.findall(r'\W', file_ext))
    features['SymbolCount_Afterpath'] = len(re.findall(r'\W', query))

    # Entropy
    features['entropy_url'] = get_entropy(url)
    features['entropy_domain'] = get_entropy(domain)
    features['entropy_path'] = get_entropy(path)
    features['entropy_file'] = get_entropy(filename)
    features['entropy_ext'] = get_entropy(file_ext)
    features['entropy_after_path'] = get_entropy(query)

    # Extra content placeholder
    features['URL_sensitiveWord'] = int(any(word in url.lower() for word in ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'banking']))
    features['URLQueries_variable'] = query.count('=')
    features['spcharUrl'] = len(re.findall(r'[^\w]', url))
    features['delimeter_Domain'] = domain.count('.')
    features['delimeter_path'] = path.count('/')
    features['delimeter_Count'] = url.count('/') + url.count('.') + url.count('-') + url.count('?')

    return features

# Wrapper to return feature vector as list
def extract_features_from_url(url):
    features = extract_features(url)
    return features
