import lief
import hashlib
import os
import sys


def verify_pe(filepath):
    pe = lief.parse(filepath)
    if pe.verify_signature() != lief.PE.Signature.VERIFICATION_FLAGS.OK:
        sha256 = hashlib.sha256(open(filepath,'rb').read()).hexdigest()
        print('{} | {}'.format(sha256, filepath))


pe_array = []
for root, dirs, files in os.walk(sys.argv[1]):
    path = root.split(os.sep)
    for file in files:
        if file.endswith('.exe') or file.endswith('.dll') or file.endswith('.sys'):
            filepath = root + '\\' + file
            pe_array.append(filepath)
            verify_pe(filepath)


print('files count:', len(pe_array))
for file in pe_array:
    print(file)