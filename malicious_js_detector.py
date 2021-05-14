import argparse
import clamd
import os
import requests
import yara
import jsbeautifier
import urllib.request
import pymongo
from bs4 import BeautifulSoup
from pymongo import MongoClient
from entropy_calc import calculate_entropy
from urllib.parse import urljoin
from urllib.error import HTTPError


def clamscan_file(file):
    """
    Uses ClamAV to scan given file.
    :param file: file to be scanned
    :return:
    """
    cd = clamd.ClamdUnixSocket()
    open('/tmp/EICAR', 'wb').write(clamd.EICAR)
    scan_result = cd.scan(file).__str__()
    if 'FOUND' in scan_result:
        print('ClamAV has detected an infected file!')
        print(f'ClamAV\'s output: {scan_result}')
    else:
        print('ClamAV has not detected malicious code.')


def yara_scan(file: str):
    rules = yara.compile('yara_js.yar')
    with open(file, 'rb') as f:
        matches = rules.match(data=f.read())
        if matches:
            print("Malicious code has been detected by applying YARA rules.")
        else:
            print("No malicious code has been detected by applying YARA rules.")


def load_from_file(file: str):
    file = os.path.abspath(file)
    perform_detection(file)


def perform_detection(file: str):
    entropy_before = calculate_entropy(file)
    contents = str()
    with open(file, mode='r', encoding='utf-8', errors='ignore') as f:
        contents = f.read()
    with open(file, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(contents)
    res = jsbeautifier.beautify_file(file)
    with open('temp.js', 'w', encoding='utf-8', errors='ignore') as f:
        f.write(res)
    entropy_after = calculate_entropy('temp.js')
    if abs(entropy_before - entropy_after) > 0.5:
        print("Warning! JS code was obfuscated, which can be a sign of malware.")
    else:
        print("Code was not obfuscated.")
    clamscan_file('temp.js')
    yara_scan('temp.js')


def load_from_webpage(url: str):
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "html.parser")
    script_files = []
    with open('temp.txt', 'w') as file:
        for tag in soup.select('script'):
            if tag.string is not None:
                file.write(tag.string)
            if tag.attrs.get("src"):
                script_url = urljoin(url, tag.attrs.get("src"))
                script_files.append(script_url)

    js_files = []
    for count, script in enumerate(script_files):
        try:
            js_files.append(urllib.request.urlretrieve(script, 'temp' + str(count) + '.js')[0])
        except HTTPError:
            print(f"Could not download script {script}")
    file = os.path.abspath('temp.txt')
    perform_detection(file)
    for js_file in js_files:
        perform_detection(js_file)




def load_from_mongodb(url: str):
    client = MongoClient("mongodb://rouser:MiLaBiLaFiLa123@127.0.0.1:27017/websecradar?authSource=websecradar")
    db = client['websecradar']
    url_collection = db['crawled_data_urls_v0']
    document = url_collection.find_one({"url": url})
    checks = document["checks"]
    hash_set = set()
    # scan each check from database, but only once per version (per same hash)
    for check in checks:
        hash_set.add(check['hash'])

    pages_collection = db['crawled_data_pages_v0']
    for hash in hash_set:
        web_page = pages_collection.find_one({"hash": hash})
        # print(web_page['page'])
        with open('temp', 'w') as f:
            f.write(web_page['page'])
        perform_detection('temp')


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', help='Provide path to HTML/JS file')
    group.add_argument('-w', '--web', action='store', type=str, help='Provide URL of website')
    group.add_argument('-m', '--mongo', action='store', type=str, help='Provide URL stored in websecradar DB')
    args = parser.parse_args()

    if args.file is not None:
        load_from_file(args.file)
    elif args.web is not None:
        load_from_webpage(args.web)
    elif args.mongo is not None:
        load_from_mongodb(args.mongo)


if __name__ == '__main__':
    main()
