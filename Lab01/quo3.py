from numpy.ma.core import append
import numpy as np

def generateKey(key):
    n = len(key)
    keytable = []
    for i in range(5):
        row = []
        for j in range(5):
            flattened_list = [item for sublist in keytable for item in sublist]
            if n>0 :
                while key[-n] in flattened_list:
                    n -= 1
                row.append(key[-n])
                n -= 1
            else:
                row.append(0)
        keytable.append(row)

    print(keytable)


generateKey("hellllllosir")

arr = [['h', 'e', 'l', 'l', 'o'], ['s', 'i', 'r', 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0]]
flattened_list = [item for sublist in arr for item in sublist]

print('z' not in flattened_list)



