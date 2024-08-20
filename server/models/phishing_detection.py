import pandas as pd
import re
from difflib import SequenceMatcher
from bs4 import BeautifulSoup

# Load the blacklist and benign lists from the CSV files
email_blacklist_df = pd.read_csv('./data/mail_list/mail_list.csv')  # Adjust the file path if necessary
url_blacklist_df = pd.read_csv('./data/url_list/url_list.csv')  # Adjust the file path if necessary
benign_site_df = pd.read_csv('./data/benign_site_list/benign_site_list.csv')  # Load benign site list
benign_domain_df = pd.read_csv('./data/benign_domain_list/benign_domain_list.csv')  # Load benign domain list

# Example inputs (these would be passed to the function in practice)
psender = "example@naver.c0m"
ptitle = "Subject of the email"
pcontent = "test@naver.com test@0utlook.kr Please visit https://www.naver.c0m and www.amaz0n.com for more details. Contact badguy@malicious.com."
pwhole = """
<div dir="ltr" style="display:none; visibility:hidden; font-size:0; color:transparent;"><strong>&quot;Hello Cleopatra, the best potato chips in the world<br>Hello Kleopatra potato<br><a rel="noopener" href="https://www.ewha.ac.kr/ewha/news/notice.do" style="display:none; visibility:hidden; font-size:0; color:transparent;">https://www.ewha.ac.kr/ewha/news/notice.do</a></strong>The Center for Educational Innovation is conducting a workshop on <strong>Communication Strategies</strong> that can be utilized in <strong>team projects</strong> and <strong>post-employment workplace scenarios</strong> for enrolled students.<br>We encourage all Ewha students to show great interest and participate. Click the poster image below or scan the QR code to be directed to the application page.2024-2 Workshop on Enhancing Convergence and Communication Competence: &quot;Practical Communication Strategies&quot; applicable for Team Projects and Post-Employment Workplace Scenarios Target Audience<pre style="display:none; visibility:hidden; font-size:0; color:transparent;"><div class="gmail-dark gmail-bg-gray-950 gmail-rounded-md gmail-border-[0.5px] gmail-border-token-border-medium"><div class="gmail-overflow-y-auto gmail-p-4" dir="ltr"><code class="gmail-!whitespace-pre gmail-hljs gmail-language-sql"><span class="gmail-hljs-number">60</span> undergraduate students (<span class="gmail-hljs-keyword">first</span><span class="gmail-hljs-operator">-</span>come, <span class="gmail-hljs-keyword">first</span><span class="gmail-hljs-operator">-</span>served basis)</code></div></div></pre> Method<pre style="display:none; visibility:hidden; font-size:0; color:transparent;"><div class="gmail-dark gmail-bg-gray-950 gmail-rounded-md gmail-border-[0.5px] gmail-border-token-border-medium"><div class="gmail-overflow-y-auto gmail-p-4" dir="ltr"><code class="gmail-!whitespace-pre gmail-hljs gmail-language-vbnet">Cyber Campus ZOOM online non-face-<span class="gmail-hljs-keyword">to</span>-face (The URL will be <span class="gmail-hljs-keyword">shared</span> the day before <span class="gmail-hljs-built_in">and</span> the morning <span class="gmail-hljs-keyword">of</span> the <span class="gmail-hljs-keyword">event</span>)</code></div></div></pre> Lecture Overview and Content<strong style="display:none; visibility:hidden; font-size:0; color:transparent;">&quot;</strong><a href="http://the.ewha.ac.kr/user/subject/nsubject/view.do?idx=8431&amp;tp=1" target="_blank"><img src="https://mailer.ewha.ac.kr:20058/html/mail_image/20240816164950971030.png" border="0" width="700" class="gmail-CToWUd"></a><br></div>
"""
pfile_ex = "testfile.exe"

# Function to check if the email or any email in the content is in the blacklist
def check_bad_mail(psender, pcontent):
    if psender in email_blacklist_df['bad_mail'].values:
        return f"Harmful email check result: {psender} is in the harmful email list."
    
    email_addresses = extract_emails(pcontent)
    for email in email_addresses:
        if email in email_blacklist_df['bad_mail'].values:
            return f"Harmful email check result: {email} in the email content is in the harmful email list."
    
    return "Harmful email check result: No harmful emails found."

# Function to extract email addresses from the content
def extract_emails(pcontent):
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    return email_pattern.findall(pcontent)

# Function to extract domains from email addresses
def extract_domains(emails):
    return [email.split('@')[-1] for email in emails]

# Function to check similarity between email domains and benign domains
def check_domain_similarity(psender, pcontent, threshold=0.8):
    benign_domains = benign_domain_df['benign_domain'].values
    domains_to_check = extract_domains([psender] + extract_emails(pcontent))
    similar_domains = set()  # Use a set to avoid duplicates
    
    for domain in domains_to_check:
        if domain in benign_domains:
            continue  # Skip exact matches
        for benign_domain in benign_domains:
            similarity = SequenceMatcher(None, domain, benign_domain).ratio()
            if similarity >= threshold:
                similar_domains.add(domain)
    
    if similar_domains:
        return f"Domain similarity check result: Found similar domains to benign list: {', '.join(similar_domains)}."
    else:
        return "Domain similarity check result: No similar domains found to benign list."

# Function to check similarity between URLs in the content against benign sites
def check_site_similarity(pcontent, threshold=0.7):
    benign_sites = benign_site_df['benign_url'].values
    site_addresses = extract_urls(pcontent)
    similar_site = set()  # Use a set to avoid duplicates
    
    for site in site_addresses:
        if site in benign_sites:
            continue  # Skip exact matches
        for benign_site in benign_sites:
            similarity = SequenceMatcher(None, site, benign_site).ratio()
            if similarity >= threshold:
                similar_site.add(site)  # Add to set to avoid duplicates
    
    if similar_site:
        return f"Site similarity check result: Found similar site addresses to benign list: {', '.join(similar_site)}."
    else:
        return "Site similarity check result: No similar site addresses found to benign list."

# Function to extract URLs from the email content
def extract_urls(pcontent):
    url_pattern = re.compile(r'(http[s]?://\S+|www\.\S+)')
    return url_pattern.findall(pcontent)

# Function to check if any extracted URL is in the harmful URL list
def check_bad_urls(pcontent):
    extracted_urls = extract_urls(pcontent)
    harmful_urls = url_blacklist_df['bad_url'].values
    harmful_found = [url for url in extracted_urls if url in harmful_urls]
    
    if harmful_found:
        return f"Harmful URL check result: Found harmful URLs: {', '.join(harmful_found)}."
    else:
        return "Harmful URL check result: No harmful URLs found."

# Function to analyze URL structure for suspicious patterns
def is_suspicious_url_structure(url):
    suspicious_patterns = [
        r'@',  # Redirection attempt using @ symbol
        r'//[^/]*//',  # Double slashes in the URL
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address in the URL
        r'(^|\.)\d{1,3}\.(\d{1,3}\.){2}\d{1,3}($|\.)',  # IP address embedded in the domain
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    
    return False

# Function to check all URLs for suspicious structures
def check_suspicious_urls(pcontent):
    extracted_urls = extract_urls(pcontent)
    suspicious_found = [url for url in extracted_urls if is_suspicious_url_structure(url)]
    
    if suspicious_found:
        return f"Suspicious URL structure found in: {', '.join(suspicious_found)}."
    else:
        return "No suspicious URL structures found."

# Function to check if the file extension is suspicious
def check_suspicious_file_extension(pfile_ex):
    suspicious_extensions = [
        'exe', 'bat', 'cmd', 'vbs', 'js', 'jar', 'scr', 'msi', 'com', 'pif', 'jse', 'wsf', 'vbe', 'vba', 'hta', 'cpl'
    ]
    
    file_extension = pfile_ex.split('.')[-1].lower()
    
    if file_extension in suspicious_extensions:
        return f"Suspicious file extension detected: {pfile_ex}."
    else:
        return f"File extension {file_extension} is not considered suspicious."

# Function to analyze HTML/CSS for hidden text
def is_hidden_style(style):
    hidden_conditions = {
        'display:none': 'Display is set to none',
        'visibility:hidden': 'Visibility is set to hidden',
        'font-size:0': 'Font size is set to 0',
        'color:transparent': 'Text color is set to transparent',
    }
    style = style.lower()
    
    reasons = []
    for condition, description in hidden_conditions.items():
        if condition in style:
            reasons.append(description)
    
    return reasons

def analyze_html_for_hidden_text(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    hidden_texts = []
    
    for element in soup.find_all(text=True):
        parent_style = element.parent.get('style', '')
        hidden_reasons = is_hidden_style(parent_style)
        if hidden_reasons:
            hidden_texts.append((element.strip(), hidden_reasons))
    
    if hidden_texts:
        report = "Warning: Hidden text found:\n"
        for text, reasons in hidden_texts:
            report += f"Text: '{text}' - Hidden because: {', '.join(reasons)}\n"
        return report.strip()
    else:
        return "No hidden text found."

# Function to analyze HTML/CSS for suspicious links
def extract_hidden_links(soup):
    hidden_links = []
    
    for a_tag in soup.find_all('a'):
        href = a_tag.get('href')
        style = a_tag.get('style', '').lower()

        if is_hidden_style(style) or 'color:transparent' in style:
            hidden_links.append((a_tag.text.strip(), href))
        
        img_tag = a_tag.find('img')
        if img_tag and (is_hidden_style(img_tag.get('style', '').lower()) or 'color:transparent' in style):
            hidden_links.append(('Image link', href))

    return hidden_links

def check_url_against_blacklist(url, blacklist):
    return url.lower() in blacklist

def analyze_html_for_suspicious_links(html_content, blacklist):
    soup = BeautifulSoup(html_content, 'html.parser')
    hidden_links = extract_hidden_links(soup)
    hidden_links_result = []
    
    if hidden_links:
        for text, url in hidden_links:
            result = f"Hidden link text: '{text}', URL: {url}"
            if check_url_against_blacklist(url, blacklist):
                result += f" - Warning: URL '{url}' is in the blacklist."
            else:
                result += f" - URL '{url}' is not in the blacklist."
            hidden_links_result.append(result)
    
    if hidden_links_result:
        return "Suspicious links found:\n" + "\n".join(hidden_links_result)
    else:
        return "No suspicious links found."

# Create the report DataFrame
report_df = pd.DataFrame({
    'psender': [psender],
    'ptitle': [ptitle],
    'pcontent': [pcontent],
    'pwhole': [pwhole],
    'pfile_ex': [pfile_ex],
        'chk_bad_mail': [check_bad_mail(psender, pcontent)],
    'chk_site_similarity': [check_site_similarity(pcontent)],
    'chk_domain_similarity': [check_domain_similarity(psender, pcontent)],
    'chk_bad_urls': [check_bad_urls(pcontent)],
    'chk_suspicious_urls': [check_suspicious_urls(pcontent)],
    'chk_suspicious_file_ex': [check_suspicious_file_extension(pfile_ex)],
    'chk_hidden_text': [analyze_html_for_hidden_text(pwhole)],
    'chk_suspicious_links': [analyze_html_for_suspicious_links(pwhole, set(url_blacklist_df['bad_url'].values))]
})

# Custom print format: Print each column and its corresponding data
for column in report_df.columns:
    print(f"{column} : {report_df[column].values[0]}")

# Optionally save the report to a CSV file
report_df.to_csv('./report.csv', index=False)

   
