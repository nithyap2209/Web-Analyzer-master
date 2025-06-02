import asyncio
import json
import re
import os
import csv
from urllib.parse import urljoin, urlparse
import aiohttp
import nest_asyncio

# Apply nest_asyncio to allow nested event loops
nest_asyncio.apply()

# Fix for "aiodns needs a SelectorEventLoop on Windows"
if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

###############################################################################
# 1) Pre-compile your regex for finding links to avoid re-compiling on each URL
###############################################################################
LINK_REGEX = re.compile(r'href\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)

def add_to_tree(tree, url, status_codes):
    """Recursively adds a URL to the nested dictionary tree with status information."""
    parsed = urlparse(url)
    parts = [part for part in parsed.path.strip('/').split('/') if part]
    domain = parsed.netloc

    # If the domain doesn't exist in the tree, add it as a node.
    if domain not in tree:
        domain_url = f"https://{domain}"
        domain_status = status_codes.get(domain_url, {}).get("status", "Unknown")
        tree[domain] = {
            "name": domain,
            "url": domain_url,
            "status": domain_status,
            "children": {}
        }
    
    node = tree[domain]["children"]

    # Build the tree recursively for each part of the path.
    for index, part in enumerate(parts):
        # Create a full URL for this node (join domain with the path up to here)
        path = "/".join(parts[:index+1])
        full_url = f"https://{domain}/{path}"
        if part not in node:
            # Look up the status for the full URL from the status_codes mapping.
            node[part] = {
                "name": part,
                "url": full_url,
                "status": status_codes.get(full_url, {}).get("status", "Unknown"),
                "children": {}
            }
        node = node[part]["children"]

def build_tree(links, status_codes):
    """Builds a nested dictionary tree from a set of URLs and adds status for each node."""
    tree = {}
    for link in links:
        add_to_tree(tree, link, status_codes)
    return tree

async def fetch_page(session, url):
    """Fetch the page and return its HTML content with detailed error handling."""
    try:
        async with session.get(url, timeout=5) as resp:
            if resp.status != 200:
                # Return HTML as empty if not 200, but store status code
                return url, resp.status, "", None
            html = await resp.text()
            return url, resp.status, html, None
    except asyncio.TimeoutError:
        return url, None, "", "TimeoutError"
    except aiohttp.ClientError as e:
        return url, None, "", f"ClientError: {str(e)}"
    except Exception as e:
        return url, None, "", f"UnexpectedError: {str(e)}"

def clean_url(url):
    """Removes fragments (#) and trailing slashes from a URL."""
    parsed = urlparse(url)
    clean_path = parsed.path.rstrip("/")
    return parsed._replace(fragment="", path=clean_path).geturl()

def is_unwanted(link):
    path = urlparse(link).path.lower()
    unwanted_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.js', '.css', '.ico', '.svg')
    return any(path.endswith(ext) for ext in unwanted_extensions)

async def extract_links(session, url, base_domain, visited):
    """Fetch a URL, parse links, and return sets of home-domain links and other-domain links."""
    url, status, html, error = await fetch_page(session, url)
    if error or not html:
        # If an error or empty HTML, pass back minimal info
        return url, status, error, set(), set()

    ###############################################################################
    # 2) Use the globally compiled regex to speed up repeated link extractions
    ###############################################################################
    all_links = set(LINK_REGEX.findall(html))
    all_links = {urljoin(url, link) for link in all_links
                 if not link.lower().startswith("javascript:")}

    cleaned_links = {
        clean_url(link)
        for link in all_links
        if "#" not in link and not is_unwanted(link)
    }

    # Separate home domain links from external domain links
    home_links = {link for link in cleaned_links if urlparse(link).netloc == base_domain}
    other_links = cleaned_links - home_links

    # An example of optional extra filtering: pagination links
    pagination_links = {link for link in cleaned_links if 'page' in link and link not in visited}
    home_links.update(pagination_links)

    return url, status, error, home_links, other_links

async def worker(session, queue, visited, url_status, home_links, external_links, base_domain):
    """Worker function to process URLs from the queue."""
    while True:
        url = await queue.get()
        if url in visited:
            queue.task_done()
            continue

        visited.add(url)
        url, status, error, new_home_links, new_other_links = await extract_links(
            session, url, base_domain, visited
        )

        # Store the status code or mark as "not connected"
        url_status[url] = {
            "status": status if status else "not connected",
            "error": error or "No error",
        }

        home_links.update(new_home_links)
        external_links.update(new_other_links)

        # Enqueue newly found home-domain links for further crawling
        for link in new_home_links:
            if link not in visited:
                await queue.put(link)

        queue.task_done()

async def crawl(start_url, max_concurrency=50):
    """
    Highly optimized asynchronous web crawler with pagination handling,
    higher concurrency by default.
    """
    visited = set()
    url_status = {}
    base_domain = urlparse(start_url).netloc
    home_links = set()
    external_links = set()

    queue = asyncio.Queue()
    await queue.put(start_url)

    ###########################################################################
    # 3) Increase the TCPConnector limit to allow more simultaneous connections.
    #    You can adjust limit_per_host if you want to avoid hitting rate limits.
    ###########################################################################
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit_per_host=20),
        headers={"User-Agent": "Mozilla/5.0"}
    ) as session:
        
        workers = [
            asyncio.create_task(
                worker(session, queue, visited, url_status, home_links, external_links, base_domain)
            )
            for _ in range(max_concurrency)
        ]

        await queue.join()  # Wait until all tasks are done

        for w in workers:
            w.cancel()

    return url_status, home_links, external_links

def save_to_json(url_status, home_links, other_links, domain):
    """Saves crawled data as JSON and also prepares a CSV download using the provided domain."""
    
    if not domain:
        raise ValueError("A valid domain must be provided")
    
    # Build tree structure for JSON storage
    home_tree = build_tree(home_links, url_status)
    other_tree = build_tree(other_links, url_status)

    data = {
        "domain": domain,
        "status_codes": url_status,
        "home_links": home_tree,
        "other_links": other_tree,
    }

    # Prepare CSV data as a list of dictionaries
    csv_data = []
    for link in home_links:
        status = url_status.get(link, {}).get("status", "Unknown")
        csv_data.append({"Link": link, "Status": status, "Type": "Home"})
    for link in other_links:
        status = url_status.get(link, {}).get("status", "Unknown")
        csv_data.append({"Link": link, "Status": status, "Type": "Other"})

    os.makedirs("crawled_data", exist_ok=True)
    print(f"Directory for crawled data: 'crawled_data'")

    json_path = f"crawled_data/crawl_{domain}.json"
    csv_path = f"crawled_data/crawl_{domain}.csv"

    print(f"Saving JSON to: {json_path}")
    print(f"Saving CSV to: {csv_path}")

    # Save the data as JSON
    with open(json_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)

    # Save the data as CSV
    with open(csv_path, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["Link", "Status", "Type"])
        writer.writeheader()
        writer.writerows(csv_data)

    return json_path, csv_path

###############################################################################
# Example usage (uncomment to run in a script):
# if __name__ == "__main__":
#     start_url = "https://example.com"
#     url_status, home_links, other_links = asyncio.run(crawl(start_url))
#     domain = urlparse(start_url).netloc
#     save_to_json(url_status, home_links, other_links, domain)
###############################################################################
