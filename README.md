# endpoints_explore
Endpoints Explorer is a Python script that employs multiple bypass rules to discover sensitive SpringBoot Actuator Endpoints (and supports other sensitive endpoints).

## Overview
This script uses the aiohttp library to make asynchronous HTTP requests and scans the SpringBoot Actuator (and supports other) endpoints for sensitive information in a highly concurrent manner. The script attempts multiple bypass rules and returns as soon as sensitive information is found.

## Features
- Tests with bypass rules(`/..;/`,`/;/`,`/;js/`,`/../`,`urlencode` etc.)
- Performs highly concurrent scanning with asynchronous HTTP requests
- Supports checking if paths exist before scanning

## Usage
First, you need to install the Python libraries that this script depends on, which can be installed with the following command:
```
pip install aiohttp asyncio colorama
```

Then, you can run this script with command-line arguments. Here is the basic usage of the script:
```
python3 endpoints_explorer.py <base_url> <normal_paths_dict> <sensitive_files_dict> [-c <concurrency>] [-v] [-e]
```
Here is a detailed explanation of the parameters:

- base_url: The base URL to scan.
- normal_paths_dict: The path to the normal paths dictionary.
- sensitive_files_dict: The path to the sensitive files dictionary.
- -c, --concurrency: The concurrency level, default is 5.
- -v, --verbose: Enable verbose output.
- -e, --check-existence: Check if the paths exist before scanning.

example:

```
$ cat sensitive_files_dict.txt

/actuator/env
/env
```
It's worth noting that the normal_paths_dict can be collected from active or passive crawling methods. This largely depends on the capabilities of your crawling tools and is not covered by the functionality of this script.

```
$ cat normal_paths_dict.txt

/api/
/manage/
```

### Tips
Although the script does not directly support multi-URL scanning, you can use it in conjunction with other security tools.

- Bulk scanning for sensitive information on live URLs
```
cat urls_list.txt | httpx -silent | parallel -j 50 -- python3 endpoints_explorer.py {} normal_paths_dict.txt sensitive_files_dict.txt -c 50 -e
```
- Automatically scan for sensitive information on live subdomains
```
subfinder -d example.com -silent | httpx -silent | xargs -I {} python3 endpoints_explorer.py {} normal_paths_dict.txt sensitive_files_dict.txt -c 50 -e
```

In a sense, this script serves as a permission bypass tool, so its utility extends beyond just detecting actuator endpoints. 

### Notes

Please note that while the code has been thoroughly tested, there may be potential bugs and inaccuracies. The path existence checks are not foolproof and the scanning speed is influenced by factors like your own system, the target server, and network conditions. Be aware that high concurrency might impact the server's performance. Always ensure that you have proper authorization before initiating any scans to avoid legal or ethical issues. Use responsibly.

## Disclaimer
This script is intended only for lawful, authorized security testing activities and must not be used for any illegal activities. Users are responsible for all consequences of using this script.
