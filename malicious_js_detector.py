import argparse
import clamd
import os


def clamscan_file(file):
    """
    Uses ClamAV to scan given file.
    :param file: file to be scanned
    :return:
    """
    cd = clamd.ClamdUnixSocket()
    cd.ping()
    open('/tmp/EICAR', 'wb').write(clamd.EICAR)
    scan_result = cd.scan(file).__str__()
    if 'FOUND' in scan_result:
        print('ClamAV has detected an infected file!')
        print(f'ClamAV\'s output: {scan_result}')


def load_from_file(file):
    file = os.path.abspath(file)
    clamscan_file(file)


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-f', '--file', help='Provide path to HTML/JS file')
    group.add_argument('-w', '--web', action='store', type=str, help='Provide URL of website')
    args = parser.parse_args()

    if args.file is not None:
        load_from_file(args.file)
    elif args.web is not None:
        # TODO: dodati opciju zadavanja web stranice kao argumenta
        pass


if __name__ == '__main__':
    main()
