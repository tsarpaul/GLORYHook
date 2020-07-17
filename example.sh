#!/bin/sh

gcc -shared -zrelro -znow hook.c -o hook
python3 glory.py /bin/ls ./hook -o ./hooked-ls

