import requests
from scrapy.selector import Selector
from flask import flash

def extract_headings_in_order(url):
    """
    Fetches a URL and extracts all <h1> through <h6> tags in the order 
    they appear in the DOM, even if they are empty.
    """
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        flash(f"Error fetching URL: {e}", "danger")
        return []
    
    sel = Selector(text=resp.text)
    
    # One XPath to get h1..h6 in DOM order (including empty)
    heading_elements = sel.xpath('//h1|//h2|//h3|//h4|//h5|//h6')
    
    headings_in_order = []
    for elem in heading_elements:
        tag_name = elem.root.tag.lower()  # e.g. 'h2'
        level = int(tag_name[-1])         # e.g. '2'
        
        # Get combined text
        texts = elem.xpath('.//text()').getall()
        heading_text = " ".join(t.strip() for t in texts)  # might be empty
        
        headings_in_order.append({
            'tag': tag_name,       
            'level': level,        
            'text': heading_text,   
        })

    return headings_in_order