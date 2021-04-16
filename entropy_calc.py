import sys
from math import log, e


def calculate_entropy(file):
    opened_file = open(file, 'r')
    file_bytes = opened_file.read()
    opened_file.close()
    n = len(file_bytes)

    if n <= 1:
        return 0

    entropy = 0.0
    size = float(n)
    for b in range(128):
        freq = file_bytes.count(chr(b))
        if freq > 0:
            freq = float(freq) / size
            entropy = entropy + freq * log(freq, 2)

    return -entropy


if __name__ == '__main__':
    print(f'Entropija od {sys.argv[1]} je {calculate_entropy(sys.argv[1])}')
