# Ares Banking Trojan DGA tool

# Description
This tool can be used to generate domains for the Ares banking trojan. Note: the DGA algorithm was previously used by Qakbot with slightly different paramaters. The Ares DGA will generate 150 domains per month (or 50 domains per interval).


# Usage
usage: ares_qakbot_dga.py [-h] [-d DATE] [-n NR] [-s SEED]

optional arguments:
  -h, --help            show this help message and exit
  -d DATE, --date DATE  date for which to generate domains
  -n NR, --nr NR        nr of domains
  -s SEED, --seed SEED  seed


# Example
```
% python3 ares_qakbot_dga.py -d 2022-09-06  --seed 0x9283920
avlycvwhwcol.org
aeqpxqnrpvmudmbxtmjo.info
osnktkctrsevlgtlnabcmzruo.org
zelwyuspp.com
eukvwqet.org
pziqexexorsnivchiaedsg.org
ihyzsusqstpvkiozncgaer.info
bkvbdnvxojgpmbrvhji.org
wjyusebg.org
mjhoddxzwopcte.net
...
```
