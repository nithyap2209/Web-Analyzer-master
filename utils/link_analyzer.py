import requests
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
from scrapy.selector import Selector
from flask import flash
import random
import time
import logging
from typing import List, Dict, Optional, Tuple
import re
import json

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# Import the robots parser
from robots_parser import RobotsParser, analyze_robots_txt

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('link_analyzer.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class LinkAnalyzer:
    """
    Advanced link analyzer with robust error handling, 
    requests, and Selenium as a fallback mechanism.
    """
    
    # Expanded and more diverse user agents
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36 Edg/93.0.961.47'
    ]

    # Regex to filter out unwanted link types
    INVALID_LINK_PATTERNS = [
        r'^javascript:',
        r'^mailto:',
        r'^tel:',
        r'^#',
        r'^data:',
        r'^blob:',
        r'^file:'
    ]

    def __init__(
        self, 
        url: str, 
        user_agent: Optional[str] = None, 
        retry_count: int = 3, 
        delay_between_retries: int = 2, 
        respect_robots: bool = True,
        headless: bool = True
    ):
        """
        Initialize the Link Analyzer with Selenium fallback.
        
        :param url: URL to analyze
        :param user_agent: Custom user agent (optional)
        :param retry_count: Number of retry attempts
        :param delay_between_retries: Seconds between retries
        :param respect_robots: Whether to respect robots.txt
        :param headless: Whether to run browser in headless mode
        """
        self.url = url
        self.user_agent = user_agent or random.choice(self.USER_AGENTS)
        self.retry_count = retry_count
        self.delay_between_retries = delay_between_retries
        self.respect_robots = respect_robots
        self.headless = headless
        self.robots_info = None
        self.robots_parser = None
        self.driver = None

    def _setup_selenium_driver(self) -> Optional[webdriver.Chrome]:
        """
        Set up Selenium WebDriver with custom options.
        
        :return: Configured Chrome WebDriver
        """
        try:
            # Configure Chrome options
            chrome_options = Options()
            
            # Set user agent
            chrome_options.add_argument(f'user-agent={self.user_agent}')
            
            # Headless mode
            if self.headless:
                chrome_options.add_argument('--headless')
            
            # Additional Chrome options to mimic real browser
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--remote-debugging-port=9222')
            
            # Disable automation flags
            chrome_options.add_experimental_option(
                "excludeSwitches", ["enable-automation"]
            )
            chrome_options.add_experimental_option(
                'useAutomationExtension', False
            )
            
            # Setup WebDriver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            return driver
        
        except Exception as e:
            logger.error(f"Error setting up Selenium WebDriver: {e}")
            flash("Failed to initialize Selenium WebDriver", "danger")
            return None

    def _extract_links_selenium(self, driver) -> List[str]:
        """
        Extract links using Selenium.
        
        :param driver: Selenium WebDriver
        :return: List of extracted links
        """
        try:
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )
            
            # Find all anchor elements
            links = driver.find_elements(By.TAG_NAME, 'a')
            
            # Extract href attributes
            extracted_links = [
                link.get_attribute('href') 
                for link in links 
                if link.get_attribute('href')
            ]
            
            return extracted_links
        
        except Exception as e:
            logger.error(f"Error extracting links with Selenium: {e}")
            return []

    def _make_request(self) -> Optional[str]:
        """
        Make request with fallback to Selenium.
        
        :return: Page source or None
        """
        # First, try requests
        for attempt in range(self.retry_count):
            try:
                # Sophisticated headers
                headers = {
                    'User-Agent': self.user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                }
                
                # Add random delay
                if attempt > 0:
                    time.sleep(self.delay_between_retries * (2 ** attempt) + random.random())
                
                resp = requests.get(
                    self.url, 
                    headers=headers,
                    timeout=15,
                    allow_redirects=True
                )
                
                # Check for successful response
                if resp.status_code == 200:
                    return resp.text
                
                logger.warning(f"Attempt {attempt+1} failed with status code {resp.status_code}")
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error on attempt {attempt+1}: {e}")
        
        # Fallback to Selenium
        try:
            # Setup Selenium WebDriver
            self.driver = self._setup_selenium_driver()
            
            if not self.driver:
                flash("Failed to initialize Selenium WebDriver", "danger")
                return None
            
            # Navigate to URL
            self.driver.get(self.url)
            
            # Return page source
            return self.driver.page_source
        
        except Exception as e:
            logger.error(f"Selenium request failed: {e}")
            flash("Failed to fetch URL with Selenium", "danger")
            return None

    def analyze_links(self) -> Tuple[List[str], List[str], Optional[Dict]]:
        """
        Analyze links from the given URL.
        
        :return: Tuple of (home_links, other_links, robots_info)
        """
        # Validate initial URL
        if not self.url.startswith(("http://", "https://")):
            flash("Error: The URL must start with 'http' or 'https'.", "danger")
            return [], [], None

        # Check robots.txt if needed
        if self.respect_robots:
            try:
                self.robots_info = analyze_robots_txt(self.url)
                if self.robots_info and self.robots_info.get('success'):
                    parser_id = self.robots_info.get('parser_id')
                    if hasattr(analyze_robots_txt, 'parsers') and parser_id in analyze_robots_txt.parsers:
                        self.robots_parser = analyze_robots_txt.parsers[parser_id]
            except Exception as e:
                logger.error(f"Error analyzing robots.txt: {e}")
                self.robots_info = None
                self.robots_parser = None

        # Make request (with Selenium fallback)
        page_source = self._make_request()
        
        # Clean up Selenium driver if used
        if self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                logger.error(f"Error closing Selenium driver: {e}")

        if not page_source:
            return [], [], self.robots_info

        # Extract links
        try:
            # Method 1: Scrapy Selector
            sel = Selector(text=page_source)
            links_xpath = sel.xpath('//a[@href]/@href').getall()
            
            # Method 2: BeautifulSoup
            soup = BeautifulSoup(page_source, "html.parser")
            links_bs = [a['href'] for a in soup.find_all('a', href=True)]
            
            # Combine and deduplicate
            all_links = list(set(links_xpath + links_bs))
            
        except Exception as e:
            logger.error(f"Error parsing HTML: {e}")
            flash(f"Error parsing HTML: {e}", "danger")
            return [], [], self.robots_info

        # Convert relative URLs to absolute and normalize
        absolute_links = [
            self._normalize_url(urljoin(self.url, link)) 
            for link in all_links 
            if self._is_valid_link(link)
        ]

        # Filter links by robots.txt if needed
        if self.respect_robots and self.robots_parser:
            absolute_links = [
                link for link in absolute_links 
                if self.robots_parser.is_allowed(link)
            ]

        # Get base domain
        base_domain = urlparse(self.url).netloc.lower().replace('www.', '')

        # Categorize links
        home_links = []
        other_links = []

        for link in absolute_links:
            # Skip if link is invalid
            parsed_link = urlparse(link)
            if not parsed_link.netloc:
                continue

            # Compare domain, removing 'www.' for consistency
            link_domain = parsed_link.netloc.lower().replace('www.', '')

            if link_domain == base_domain:
                home_links.append(link)
            else:
                other_links.append(link)

        return sorted(set(home_links)), sorted(set(other_links)), self.robots_info

    def _is_valid_link(self, link: str) -> bool:
        """
        Check if a link is valid based on predefined patterns.
        
        :param link: URL to validate
        :return: Boolean indicating link validity
        """
        if not link or not isinstance(link, str):
            return False
            
        return not any(
            re.match(pattern, link, re.IGNORECASE) 
            for pattern in self.INVALID_LINK_PATTERNS
        )

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL by removing fragments and standardizing
        
        :param url: URL to normalize
        :return: Normalized URL
        """
        try:
            parsed = urlparse(url)
            # Remove fragment
            cleaned = parsed._replace(fragment='')
            # Lowercase the URL
            return urlunparse(cleaned).lower().rstrip('/')
        except Exception:
            return url

def analyze_links(
    url: str, 
    user_agent: Optional[str] = None, 
    retry_count: int = 3, 
    delay_between_retries: int = 2, 
    respect_robots: bool = True,
    headless: bool = True
) -> Tuple[List[str], List[str], Optional[Dict]]:
    """
    Convenience function to analyze links from a URL.
    
    :param url: URL to analyze
    :param user_agent: Custom user agent (optional)
    :param retry_count: Number of retry attempts
    :param delay_between_retries: Seconds between retries
    :param respect_robots: Whether to respect robots.txt
    :param headless: Whether to run browser in headless mode
    :return: Tuple of (home_links, other_links, robots_info)
    """
    analyzer = LinkAnalyzer(
        url, 
        user_agent, 
        retry_count, 
        delay_between_retries, 
        respect_robots,
        headless
    )
    return analyzer.analyze_links()

# Example usage
if __name__ == "__main__":
    # Example of how to use the function
    example_url = "https://example.com"
    home_links, other_links, robots_info = analyze_links(example_url)
    
    print("Home Links:", home_links)
    print("Other Links:", other_links)
    print("Robots Info:", robots_info)