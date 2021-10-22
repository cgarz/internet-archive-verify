#!/usr/bin/env python3

import os, sys, sqlite3, hashlib
from zlib import crc32
import xml.etree.ElementTree as ETree
from argparse import ArgumentParser
from urllib.request import pathname2url

SQL_TABLE_NAME = 's3api_per_key_metadata'
SQL_COL_NAMES = 's3key,headers'

SQL_SUFFIX = '_META.SQLITE'
XML_SUFFIX = '_FILES.XML'
SUFFIXES = (XML_SUFFIX, SQL_SUFFIX)

READ_CHUNK_SIZE = 64 * 1024

STATUS_MISSING   = 'MISSING..:'
STATUS_VERIFIED  = 'VERIFIED.:'
STATUS_COLLISION = 'COLLISION:'
STATUS_BAD_SIZE  = 'BAD SIZE.:'
STATUS_CORRUPTED = 'CORRUPTED:'

MD5_EMPTY   = 'd41d8cd98f00b204e9800998ecf8427e'
CRC32_EMPTY = '00000000'
SHA1_EMPTY  = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

PROGRESS_LINE_FMT = '\r{f_pct:7.2%}, file {f_num:>{t_wid}} of {f_tot}'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def sqlite_parse(metafile_path):
    con = sqlite3.connect('file:{}?mode=ro'.format(pathname2url(metafile_path)), uri=True)
    cur = con.cursor()
    try:
        if not len(cur.execute(f'SELECT name FROM sqlite_master WHERE type="table" AND name="{SQL_TABLE_NAME}";')
                      .fetchall()) == 1:
            eprint('Not an internet archive database. Skipping.')
            return False
    except sqlite3.DatabaseError:
        eprint('Not a valid sqlite database. Skipping.')
        return False

    try:
        entries = cur.execute(f'SELECT {SQL_COL_NAMES} FROM {SQL_TABLE_NAME}').fetchall()
    except sqlite3.Error:
        eprint('Unknown error when querying names and checksums. Skipping.')
        return False

    files_metadata = []
    for file_path, header in entries:
        file_metadata = {'type': 'sqlite',
                         'path': file_path,
                         'crc32': CRC32_EMPTY,
                         'sha1': SHA1_EMPTY}

        for header_line in header.split('\n'):
            if header_line.startswith('ETag: "'):
                file_metadata['md5'] = header_line[7:39].lower()
            elif header_line.startswith('content-length: '):
                file_metadata['size'] = int(header_line[16:])
            if {'md5', 'size'}.issubset(file_metadata):
                break

        if {'type', 'path', 'crc32', 'sha1', 'md5', 'size'}.issubset(file_metadata):
            files_metadata.append(file_metadata)
        else:
            eprint('Data missing. Skipping:', file_metadata['path'], sep='\n')
            continue
    return files_metadata


def xml_parse(metafile_path):
    try:
        files = ETree.parse(metafile_path).getroot()
    except ETree.ParseError:
        eprint('Not a valid xml file. Skipping.')
        return False

    if files.tag != 'files' or files[0].tag != 'file':
        eprint('Not an internet archive xml file list meta file. Skipping.')
        return False

    files_metadata = []
    for file in files:
        file_metadata = {'type': 'xml',
                         'path': file.get('name')}

        if metafile_path.endswith(file_metadata['path']):
            continue  # Don't process self

        for metadata in ('size', 'md5', 'crc32', 'sha1'):
            if type(m := file.find(metadata)) is ETree.Element:
                file_metadata[metadata] = m.text.lower()
            else:
                eprint('Data missing. Skipping:', file_metadata['path'], sep='\n')
                break
        if type(m) is ETree.Element:
            file_metadata['size'] = int(file_metadata['size'])
            files_metadata.append(file_metadata)
    return files_metadata


def main():
    parser = ArgumentParser(
        description='A tool to verify internet archive downloads offline using the xml or sqlite metadata files.')
    parser.add_argument('ia_paths', type=str, nargs='+', metavar='FILE_OR_FOLDER',
                        help='An IA meta file or a folder that contains them. Multiple may be specified.')
    parser.add_argument('-m', '--no-missing', action='store_true',
                        help="Don't print missing files.")
    parser.add_argument('-v', '--no-verified', action='store_true',
                        help="Don't print verified files.")
    parser.add_argument('--no-collision', action='store_true',
                        help="Don't print files with collisions. (Disagreement between algorithms / Tampered data)")
    parser.add_argument('-s', '--no-bad-size', action='store_true',
                        help="Don't print files that fail due to size mismatch.")
    parser.add_argument('-c', '--no-corrupted', action='store_true',
                        help="Don't print corrupted files.")
    parser.add_argument('-q', '--no-file-messages', action='store_true',
                        help="Don't print any file messages. Same as setting all --no options")
    args = parser.parse_args()

    if args.no_file_messages:
        args.no_missing = args.no_verified = args.no_collision = args.no_corrupted = args.no_bad_size = True

    for arg_idx, ia_path in enumerate(args.ia_paths):
        if arg_idx != 0:
            print()
        if len(args.ia_paths) > 1:
            print('Processing:', ia_path)

        if not os.path.exists(ia_path):
            eprint('Specified path does not exist.')
            continue

        if os.path.isdir(ia_path):
            ia_dir = ia_path
            metafile_path = [os.path.join(ia_dir, f) for f in os.listdir(ia_dir) if f.upper().endswith(SUFFIXES)]
            if metafile_path:
                metafile_path = sorted(metafile_path)[0]
                print('Selected metadata file:', os.path.basename(metafile_path))
            else:
                eprint('No xml or sqlite meta files found.')
                continue
        else:
            if ia_path.upper().endswith(SUFFIXES):
                metafile_path = ia_path
                ia_dir = os.path.dirname(metafile_path)
            else:
                eprint('Not an internet archive file list meta file.')
                continue

        if metafile_path.upper().endswith(XML_SUFFIX):
            if not (files_metadata := xml_parse(metafile_path)):
                continue
        else:
            if not (files_metadata := sqlite_parse(metafile_path)):
                continue

        files_count = len(files_metadata)
        files_width = len(str(files_count))
        clear_progress = '\r' + (' ' * len(PROGRESS_LINE_FMT.format(f_pct=0, f_num=0, t_wid=files_width,
                                                                    f_tot=files_count)))
        summary = {'missing': 0, 'verified': 0, 'collision': 0, 'bad_size': 0, 'corrupted': 0}
        for f_idx, file_metadata in enumerate(files_metadata, start=1):
            file_path = os.path.join(ia_dir, file_metadata['path'])

            if not os.path.isfile(file_path):
                if not args.no_missing:
                    print(STATUS_MISSING, file_metadata['path'])
                summary['missing'] += 1
                continue

            if file_metadata['size'] != (size := os.path.getsize(file_path)):
                if not args.no_bad_size:
                    print(STATUS_BAD_SIZE, file_metadata['path'])
                summary['bad_size'] += 1
                continue

            hash_md5 = hashlib.md5()
            hash_crc32 = 0
            hash_sha1 = hashlib.sha1()
            with open(file_path, 'rb') as file:
                while chunk := file.read(READ_CHUNK_SIZE):
                    hash_md5.update(chunk)
                    if file_metadata['type'] == 'xml':
                        hash_crc32 = crc32(chunk, hash_crc32)
                        hash_sha1.update(chunk)
                    eprint(PROGRESS_LINE_FMT.format(
                               f_pct=(file.tell() / size), f_num=f_idx, t_wid=files_width, f_tot=files_count),
                           end='', flush=True)
            eprint(clear_progress, end='\r')

            calculated_hashes = {'md5': hash_md5.hexdigest(),
                                 'crc32': f'{hash_crc32:08x}',
                                 'sha1': hash_sha1.hexdigest()}
            expected_hashes = {key: file_metadata[key] for key in ('md5', 'crc32', 'sha1')}

            if calculated_hashes == expected_hashes:
                if not args.no_verified:
                    print(STATUS_VERIFIED, file_metadata['path'])
                summary['verified'] += 1
            elif file_metadata['type'] == 'sqlite' or all(calculated != expected for calculated, expected in
                                                          zip(calculated_hashes.values(), expected_hashes.values())):
                if not args.no_corrupted:
                    print(STATUS_CORRUPTED, file_metadata['path'])
                summary['corrupted'] += 1
            elif not args.no_collision:
                print(STATUS_COLLISION, file_metadata['path'])
                eprint('Algorithms disagree! This should not occur, likely the data or metadata has been altered!',
                       f'Hash data of "{file_metadata["path"]}":',
                       f'Expected MD5...: {expected_hashes["md5"]}',
                       f'Returned MD5...: {calculated_hashes["md5"]}',
                       f'Expected CRC32.: {expected_hashes["crc32"]}',
                       f'Returned CRC32.: {calculated_hashes["crc32"]}',
                       f'Expected SHA1..: {expected_hashes["sha1"]}',
                       f'Returned SHA1..: {calculated_hashes["sha1"]}',
                       sep='\n')
                summary['collision'] += 1

        print('total:', files_count, end='')
        for status, count in summary.items():
            if count > 0:
                print(f', {status}: {count}', end='')
        print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nGot KeyboardInterrupt, quitting.')
