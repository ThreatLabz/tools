# module used by Limepad
# reference blog: https://www.zscaler.com/blogs/security-research/new-and-improved-ttps-apt-36-targeting-indian-governmental-organizations
import os, logging, time, random
billet = logging.getLogger('Limepad')
list_files = []

def timespoofer(depthname):
    global list_files
    try:
        start = time.time()
        for root, dirs, files in os.walk(depthname, topdown=False):
            for name in files:
                print os.path.join(root, name)

            for name in dirs:
                print os.path.join(root, name)
                list_files.append(os.path.join(root, name))

            end = time.time()
            elapsed = end - start
            print 'elapsed time : ' + str(elapsed)

        if len(list_files) > 0:
            list_files = []
            print 'returning true'
            return True
        list_files = []
        print 'returning false'
        return False
    except Exception as e:
        billet.exception(e)
        print str(e)
        return False


if __name__ == '__main__':
    print timespoofer(depthname)
