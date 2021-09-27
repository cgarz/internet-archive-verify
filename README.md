# ia-verify (internet-archive-verify)
A simple python script to help verify downloads from archive.org offline using the metadata files.

It can process either the `*_files.xml` or `*_meta.sqlite` meta files. If both are present and only the folder is specified, it will prefer the xml file as it contains entries for the other metadata files as well.

It makes use of the walrus operator and so requires at least python 3.8. Other than that, all imports are from the standard library so no installation beyond python 3.8+ is needed.

## usage:
    usage: ia-verify.py [-h] [-m] [-v] [--no-collision] [-s] [-c] FILE_OR_FOLDER [FILE_OR_FOLDER ...]

    positional arguments:
        FILE_OR_FOLDER      An IA meta file or a folder that contains them. Multiple may be specified.

    optional arguments:
        -h, --help          show this help message and exit
        -m, --no-missing    Don't print missing files.
        -v, --no-verified   Don't print verified files.
        --no-collision      Don't print files with collisions. (Disagreement between algorithms / Tampered data)
        -s, --no-bad-size   Don't print files that fail due to size mismatch.
        -c, --no-corrupted  Don't print corrupted files.
