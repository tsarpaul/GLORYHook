# GLORYHook
The first Linux hooking framework which allows to merge two binary files into one!

<p align="center">
<img src="https://raw.githubusercontent.com/tsarpaul/GLORYHook/master/glory-penguin.png" />
</p>

## How is this different?
Other hooking methods do not allow calling libraries from within the hook, so you must resort to writing shellcode or your own implementation for libc APIs. This is not the case with GLORYHook. Check out hook.c, you can call any libc API you want!

## Usecases
1. Debugging - Can't use LD_PRELOAD? Don't want to mess with injecting dependency shared objects and can't bother installing dependency libraries on the system each time? Just hook your file instantly and ship it with zero extra steps.
2. File Infection/Backdoor - Can be used as an alternative for an LD_PRELOAD rootkit but with **extra stealth sauce**. Defenders contact me for how to detect.

## Important Notes
GLORYHook supports only x64.
Currently hooking is only supported on imports (e.g. libc functions).
Currently interacting with globals in your hook is unsupported but will be added soon.

## Installation
1. Install my custom LIEF (I customized LIEF to make ELF manipulations easier):
```
git clone https://github.com/tsarpaul/LIEF
cd LIEF
python3 ./setup.py install
```
2. ```pip3 install -r requirements.txt```

## Usage

![usage](https://raw.githubusercontent.com/tsarpaul/GLORYHook/master/usage.png)

1. Define gloryhook_<import_to_hook> in your hook file
2. `gcc -shared -zrelro -znow hook.c -o hook`
3. `python3 glory.py ./file-to-hook ./hook -o ./hooked-file`

Check hook.c and example.sh.

## GLORY TO YOU!
