import argparse
# import clamd
import os
import requests
import yara
import jsbeautifier
from bs4 import BeautifulSoup


def clamscan_file(file):
    """
    Uses ClamAV to scan given file.
    :param file: file to be scanned
    :return:
    """
    """
    cd = clamd.ClamdUnixSocket()
    open('/tmp/EICAR', 'wb').write(clamd.EICAR)
    scan_result = cd.scan(file).__str__()
    if 'FOUND' in scan_result:
        print('ClamAV has detected an infected file!')
        print(f'ClamAV\'s output: {scan_result}')
    else:
        print('ClamAV has not detected malicious code.')
    """
    pass


def yara_scan(file: str):
    rules = yara.compile('yara_js.yar')
    with open(file, 'rb') as f:
        matches = rules.match(data=f.read())
        if matches:
            print("Malicious code has been detected by applying YARA rules.")


def load_from_file(file: str):
    file = os.path.abspath(file)
    perform_detection(file)


def perform_detection(file: str):
    res = jsbeautifier.beautify_file(file)
    with open('temp.js', 'w') as f:
        f.write(res)
    # print(res)
    clamscan_file('temp.js')
    yara_scan('temp.js')


def load_from_webpage(url: str):
    html_content = requests.get(url).text
    soup = BeautifulSoup(html_content, "html.parser")  # lxml kao brža alternativa
    with open('temp.txt', 'w') as file:
        for tag in soup.select('script'):
            if tag.string is not None:
                file.write(tag.string)

    file = os.path.abspath('temp.txt')
    perform_detection(file)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', help='Provide path to HTML/JS file')
    group.add_argument('-w', '--web', action='store', type=str, help='Provide URL of website')
    args = parser.parse_args()

    if args.file is not None:
        load_from_file(args.file)
    elif args.web is not None:
        load_from_webpage(args.web)


if __name__ == '__main__':
    main()
