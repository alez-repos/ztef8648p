# F8648P Supertool

A tool to automatize obtaining a root shell and config decryption

Install:
- Prepare an USB drive NTFS formatted which the following files in the root folder. These files are in the repo:
    - busybox
    - nc (just copy busybox to this name or symlink it)
    - sh (just copy busybox to this name or symlink it)
    - raiz (symlink that can be made with the command ln -s / raiz)
- Clone or download this repo/folder

Execution:
- python3 -m pip install -r requirements.txt
- python3 zte-supertool.py

![demo](demo.gif)


