
with open("C:/Users/user/Desktop/temp/grid_matrix", 'rb') as hFile:
    data = b'\x00'
    info = {}
    count = 0
    while data != b'':
        data = hFile.read(4)
        if count == 16:
            count = 0
            print('')
        if data == b'\x81\xfb\x000':
            print('=', end='')
        if data == b'0\x00\x00\x00':
            print(' ', end='')
        if data == b'\x81\x7f\x050':
            print('+', end='')
        if data == b'\x81t\x050':
            print('x', end='')
        if data == b'\x81\x85\x050':
            print('!', end='')
        count += 1
        '''
        if data not in info:
            info[data] = 0
        else:
            info[data] += 1
        '''
    print(info)        
