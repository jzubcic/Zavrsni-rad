import sys
import re
import jsbeautifier
from math import log


def calculate_entropy(file):
    opened_file = open(file, 'r')
    file_bytes = str()
    try:
        file_bytes = opened_file.read()
    except UnicodeDecodeError:
        print("UnicodeDecodeError.")
    strings = re.findall('"[^"]*"', file_bytes)
    strings += re.findall("'.*'", file_bytes)
    opened_file.close()

    if strings:
        entropies = list()
        for string in strings:
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([p * log(p) / log(2.0) for p in prob])
            entropies.append(entropy)
        return sum(entropies) / len(entropies)
    else:
        return 0


if __name__ == '__main__':
    print(f'Entropija stringova u {sys.argv[1]} je {calculate_entropy(sys.argv[1])}')
    res = jsbeautifier.beautify_file(sys.argv[1])
    with open('temp.js', 'w') as f:
        f.write(res)
    file = 'temp.js'
    print(f'Entropija stringova u {sys.argv[1]} nakon deobfuskacije je {calculate_entropy(file)}')
