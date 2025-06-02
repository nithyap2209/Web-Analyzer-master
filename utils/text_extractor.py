import requests
from scrapy.selector import Selector
from flask import flash
import re
from markupsafe import Markup

def extract_text(url):
    """
    Extract all visible text from the given URL using Scrapy's Selector.
    Text within <script> and <style> tags is excluded.
    """
    try:
        resp = requests.get(url)
        resp.raise_for_status()
    except Exception as e:
        return f"Error fetching URL: {e}"
    sel = Selector(text=resp.text)
    # Get all text nodes under <body> that are not descendants of script or style.
    texts = sel.xpath('//body//text()[not(ancestor::script) and not(ancestor::style)]').getall()
    cleaned_text = " ".join(t.strip() for t in texts if t.strip())
    return cleaned_text.strip()

def process_keywords(text, keywords):
    """
    Given the full extracted text and a list of keywords,
    returns a dictionary with the total word count and, for each keyword,
    the count and density (percentage).
    
    Now modified to only count exact word matches.
    """
    results = {}
    words = text.split()
    total_words = len(words)
    
    for keyword in keywords:
        # Use word boundaries to find exact matches only
        pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
        # Find all matches in the text
        matches = re.findall(pattern, text.lower())
        count = len(matches)
        
        # Calculate density
        density = (count * 100 / total_words) if total_words > 0 else 0
        results[keyword] = {'count': count, 'density': density}
        
    return {'total_words': total_words, 'keywords': results}

def correct_text(text):
    """
    Dummy function to simulate correction of the extracted text.
    In a real implementation, you might call an external API.
    """
    corrected = text.replace('mistaekn', 'mistaken')
    return {'original': text, 'corrected': corrected}

def highlight_keywords(text, keywords_colors):
    """
    Wrap each occurrence of each keyword (case-insensitive) in the text with a <span> tag
    that styles it with the specified color and bold font.
    The matched text preserves its original case.
    
    Modified to only highlight exact word matches.
    """
    highlighted = text
    for keyword, color in keywords_colors.items():
        # Use word boundary markers to match exact words only
        pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
        highlighted = pattern.sub(
            lambda m: f'<span style="color: {color}; font-weight: bold;">{m.group(0)}</span>',
            highlighted
        )
    return Markup(highlighted)