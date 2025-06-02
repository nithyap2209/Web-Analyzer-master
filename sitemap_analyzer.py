import requests
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

logger = logging.getLogger(__name__)

def check_url_status(url, timeout=5):
    """
    Check the HTTP status code of a URL.
    
    Args:
        url (str): URL to check
        timeout (int): Timeout in seconds
        
    Returns:
        int: HTTP status code or 0 if error
    """
    try:
        # Use HEAD request first for efficiency
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        
        # If HEAD request returns 405 (Method Not Allowed), try GET
        if response.status_code == 405:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            
        return response.status_code
    except requests.RequestException:
        return 0  # Return 0 for connection errors

def categorize_url(url):
    """
    Categorize URL by type and extract search terms if present.
    
    Args:
        url (str): URL to categorize
        
    Returns:
        dict: URL category information
    """
    parsed_url = urlparse(url)
    path = parsed_url.path.strip('/')
    path_segments = path.split('/')
    
    # Initialize category data
    category = {
        'is_blog': False,
        'is_search': False,
        'search_terms': [],
        'path_level': len(path_segments),
        'path_hierarchy': path_segments
    }
    
    # Check if it's a blog URL
    if 'blog' in path_segments or re.search(r'/(post|article)s?/', path):
        category['is_blog'] = True
    
    # Check if it's a search URL and extract search terms
    query_params = parse_qs(parsed_url.query)
    search_param_keys = ['q', 'query', 'search', 's', 'keyword', 'term']
    
    for key in search_param_keys:
        if key in query_params:
            category['is_search'] = True
            category['search_terms'] = query_params[key]
            break
    
    return category

def parse_sitemap(sitemap_url, max_urls=10000, check_status=True, max_workers=10):
    """
    Parse a sitemap XML file and extract URLs.
    
    Args:
        sitemap_url (str): URL of the sitemap to parse
        max_urls (int): Maximum number of URLs to extract
        check_status (bool): Whether to check HTTP status codes
        max_workers (int): Maximum number of concurrent workers for status checks
        
    Returns:
        list: List of dictionaries with URL information
    """
    try:
        # Fetch the sitemap
        response = requests.get(sitemap_url, timeout=10)
        response.raise_for_status()
        
        # Parse XML
        root = ET.fromstring(response.content)
        
        # Define namespace mapping
        ns = {
            'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9',
            'xhtml': 'http://www.w3.org/1999/xhtml'
        }
        
        # Check if this is a sitemap index (contains other sitemaps)
        is_index = root.tag.endswith('sitemapindex')
        
        results = []
        if is_index:
            # Process sitemap index
            for sitemap_elem in root.findall('.//sm:sitemap', ns):
                loc_elem = sitemap_elem.find('./sm:loc', ns)
                if loc_elem is not None and loc_elem.text:
                    child_sitemap_url = loc_elem.text.strip()
                    # Recursively parse child sitemap
                    child_results = parse_sitemap(child_sitemap_url, max_urls=max_urls - len(results), check_status=check_status)
                    results.extend(child_results)
                    
                    # Check if we've reached the maximum number of URLs
                    if len(results) >= max_urls:
                        return results[:max_urls]
        else:
            # Process regular sitemap
            urls_to_process = []
            
            # First collect all URLs without checking status
            for url_elem in root.findall('.//sm:url', ns):
                # Extract URL location (mandatory)
                loc_elem = url_elem.find('./sm:loc', ns)
                if loc_elem is None or not loc_elem.text:
                    continue
                    
                url = loc_elem.text.strip()
                
                # Extract optional elements
                lastmod_elem = url_elem.find('./sm:lastmod', ns)
                lastmod = lastmod_elem.text.strip() if lastmod_elem is not None and lastmod_elem.text else None
                
                changefreq_elem = url_elem.find('./sm:changefreq', ns)
                changefreq = changefreq_elem.text.strip() if changefreq_elem is not None and changefreq_elem.text else None
                
                priority_elem = url_elem.find('./sm:priority', ns)
                priority = priority_elem.text.strip() if priority_elem is not None and priority_elem.text else None
                
                # Extract alternate language versions (XHTML namespace)
                alternates = []
                for alternate_elem in url_elem.findall('./xhtml:link', ns):
                    if alternate_elem.get('rel') == 'alternate':
                        alternates.append({
                            'href': alternate_elem.get('href'),
                            'hreflang': alternate_elem.get('hreflang')
                        })
                
                # Parse URL to extract domain and path
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                path = parsed_url.path
                
                # Format lastmod date if present
                formatted_lastmod = None
                if lastmod:
                    try:
                        # Try different date formats
                        for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%d'):
                            try:
                                parsed_date = datetime.strptime(lastmod, fmt)
                                formatted_lastmod = parsed_date.strftime('%Y-%m-%d %H:%M:%S')
                                break
                            except ValueError:
                                continue
                    except Exception as e:
                        logger.warning(f"Could not parse lastmod date: {lastmod} - {str(e)}")
                
                # Categorize URL
                category_info = categorize_url(url)
                
                url_data = {
                    'url': url,
                    'domain': domain,
                    'path': path,
                    'lastmod': formatted_lastmod,
                    'changefreq': changefreq,
                    'priority': priority,
                    'alternates': alternates,
                    'status_code': None,
                    'status_group': None,
                    'is_blog': category_info['is_blog'],
                    'is_search': category_info['is_search'],
                    'search_terms': category_info['search_terms'],
                    'path_level': category_info['path_level'],
                    'path_hierarchy': category_info['path_hierarchy']
                }
                
                urls_to_process.append(url_data)
                
                # Check if we've reached the maximum number of URLs
                if len(urls_to_process) >= max_urls:
                    urls_to_process = urls_to_process[:max_urls]
                    break
            
            # Check HTTP status if requested
            if check_status and urls_to_process:
                # Prepare a list of URLs
                urls_list = [data['url'] for data in urls_to_process]
                
                # Use thread pool to check status codes concurrently
                status_dict = {}
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all tasks and map them to their URLs
                    future_to_url = {executor.submit(check_url_status, url): url for url in urls_list}
                    
                    # Process results as they complete
                    for future in as_completed(future_to_url):
                        url = future_to_url[future]
                        try:
                            status_code = future.result()
                            status_dict[url] = status_code
                        except Exception as e:
                            logger.error(f"Error checking status for {url}: {str(e)}")
                            status_dict[url] = 0
                
                # Update status codes in our url data
                for url_data in urls_to_process:
                    status_code = status_dict.get(url_data['url'], 0)
                    url_data['status_code'] = status_code
                    
                    # Set status group based on status code
                    if status_code == 0:
                        url_data['status_group'] = 'Error'
                    else:
                        url_data['status_group'] = f"{status_code // 100}xx"
            
            results.extend(urls_to_process)
                    
        return results
        
    except requests.RequestException as e:
        logger.error(f"Error fetching sitemap {sitemap_url}: {str(e)}")
        return []
    except ET.ParseError as e:
        logger.error(f"Error parsing sitemap XML {sitemap_url}: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error processing sitemap {sitemap_url}: {str(e)}")
        return []

def extract_sitemap_urls(url, check_status=True):
    """
    Extract URLs from sitemaps mentioned in robots.txt
    
    Args:
        url (str): Base URL to check for robots.txt and sitemaps
        check_status (bool): Whether to check HTTP status codes
        
    Returns:
        dict: Dictionary with sitemap information and URLs
    """
    from robots_parser import analyze_robots_txt
    
    # Get robots.txt information
    robots_info = analyze_robots_txt(url)
    if not robots_info.get('success', False):
        return {
            'success': False,
            'message': 'Could not analyze robots.txt',
            'sitemaps': [],
            'urls': []
        }
    
    # Get sitemaps from robots.txt
    sitemaps = robots_info.get('sitemaps', [])
    if not sitemaps:
        # Try the default sitemap location if none found in robots.txt
        default_sitemap = f"{url.rstrip('/')}/sitemap.xml"
        try:
            response = requests.head(default_sitemap, timeout=5)
            if response.status_code == 200:
                sitemaps = [default_sitemap]
        except requests.RequestException:
            pass
            
    if not sitemaps:
        return {
            'success': True,
            'message': 'No sitemaps found in robots.txt or at default location',
            'sitemaps': [],
            'urls': []
        }
    
    # Parse each sitemap
    all_urls = []
    processed_sitemaps = []
    
    for sitemap_url in sitemaps:
        sitemap_data = {
            'url': sitemap_url,
            'urls_count': 0,
            'success': False
        }
        
        # Parse the sitemap
        try:
            urls = parse_sitemap(sitemap_url, check_status=check_status)
            all_urls.extend(urls)
            
            sitemap_data['success'] = True
            sitemap_data['urls_count'] = len(urls)
        except Exception as e:
            sitemap_data['error'] = str(e)
        
        processed_sitemaps.append(sitemap_data)
    
    # Add statistics on status codes
    status_stats = {}
    if check_status:
        for url_data in all_urls:
            status_group = url_data.get('status_group', 'Unknown')
            if status_group not in status_stats:
                status_stats[status_group] = 0
            status_stats[status_group] += 1
    
    # Count blog and search URLs
    blog_count = sum(1 for url_data in all_urls if url_data.get('is_blog', False))
    search_count = sum(1 for url_data in all_urls if url_data.get('is_search', False))
    
    # Process path hierarchy for structure visualization
    path_structure = {}
    for url_data in all_urls:
        path_parts = url_data.get('path_hierarchy', [])
        current_level = path_structure
        
        for part in path_parts:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]
    
    return {
        'success': True,
        'message': f'Found {len(all_urls)} URLs in {len(sitemaps)} sitemaps',
        'sitemaps': processed_sitemaps,
        'urls': all_urls,
        'status_stats': status_stats,
        'blog_count': blog_count,
        'search_count': search_count,
        'path_structure': path_structure
    }