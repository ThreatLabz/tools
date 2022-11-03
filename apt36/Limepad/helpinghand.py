# module used by Limepad
# reference blog: https://www.zscaler.com/blogs/security-research/new-and-improved-ttps-apt-36-targeting-indian-governmental-organizations
import os
from pysqlite2 import dbapi2 as sqlite
from instrument import attempt_retries_decorator, tryagain
from controls import SYNC_RULES_CONFIG, DBTABLES, DBTABLES_INDEXES, FILEFLAG, OPTIMIZED_SEND_BLOCKSIZE
from regulator import FileMatcher as r
import logging
billet = logging.getLogger('Limepad')
retrydec = attempt_retries_decorator(5, 0.5, sqlite.Error)

class helpinghand:
    """ SQLite Persistence """

    def __init__(self, filename):
        global billet
        try:
            self.conn = tryagain(sqlite.connect)(filename)
        except Exception as e:
            billet.warn('Unable to connect to DB. Trying to delete and restart')
            os.unlink(filename)
            self.conn = sqlite.connect(filename)

        self.conform_schema()
        cursor = self.conn.cursor()
        cursor.execute('UPDATE file SET state = ? WHERE state = ?', (FILEFLAG.QUEUED, FILEFLAG.SYNCING))

    @retrydec
    def conform_schema(self):
        self.create_tables_if_not_exist()

    def get_usercreds(self):
        username = self.get_config('username')
        password = self.get_config('password')
        if not username or not password:
            return []
        return (
         username, password)

    @retrydec
    def createuserlocal(self, username, password):
        self.set_config('username', username)
        self.set_config('password', password)

    def get_file(self, path, filename):
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite.Row
        cursor.execute('SELECT path, filename, size, state, modified, created FROM file WHERE path=? and filename=?', (path, filename))
        row = cursor.fetchone()
        if row:
            return dict(row)

    def pop_queue(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT path from file where state=? order by queuepriority asc limit 1', (FILEFLAG.QUEUED,))
        row = cursor.fetchone()
        if not row:
            return []
        basepath = row[0]
        ret = []
        queued_file_ids = []
        totalsize = 0
        cursor.execute('SELECT id, path, filename, size from file where state=? and path=? order by queuepriority asc limit 200', (FILEFLAG.QUEUED, basepath))
        row = cursor.fetchone()
        while row and totalsize < OPTIMIZED_SEND_BLOCKSIZE:
            fileid, path, filename, filesize = row
            queued_file_ids.append(fileid)
            ret.append((fileid, filename.encode('utf-8')))
            totalsize += filesize
            row = cursor.fetchone()

        tryagain(cursor.execute)('UPDATE file SET state = %s WHERE id in (%s)' % (str(FILEFLAG.SYNCING), (',').join([ str(i) for i in queued_file_ids ])))
        self.conn.commit()
        return (basepath.encode('utf-8'), ret)

    @retrydec
    def re_enqueue(self, fileids, lower_priority_factor=None):
        cursor = self.conn.cursor()
        if lower_priority_factor == None:
            cursor.execute('UPDATE file SET state = %s WHERE id in (%s)' % (str(FILEFLAG.QUEUED), (',').join([ str(i) for i in fileids ])))
        else:
            cursor.execute('UPDATE file SET state = %s, queuepriority = queuepriority + %s WHERE id in (%s)' % (str(FILEFLAG.QUEUED), str(lower_priority_factor), (',').join([ str(i) for i in fileids ])))
        self.conn.commit()
        return

    @retrydec
    def change_files_state(self, fileids, state):
        cursor = self.conn.cursor()
        str_ids = (',').join([ str(i) for i in fileids ])
        cursor.execute('UPDATE file SET state = ? WHERE id in (%s)' % str_ids, (state,))
        billet.debug('Changed state to %s of files %s' % (str(state), str_ids))
        self.conn.commit()

    def get_config(self, key):
        cursor = self.conn.cursor()
        cursor.execute('SELECT value FROM config WHERE key = ?', (key,))
        ret = cursor.fetchone()
        if ret:
            return ret[0]
        else:
            return
            return

    def get_config_all(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT key, value FROM config')
        ret = cursor.fetchall()

    @retrydec
    def set_config(self, key, value):
        cursor = self.conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)', (key, str(value)))
        self.conn.commit()
        cursor.close()

    def get_sync_rules(self):
        cursor = self.conn.cursor()
        cursor.execute('Select path, rule from syncdirs')
        res = cursor.fetchall()
        ret = []
        for path, rule in res:
            ret.append((path, r(rule)))

        return ret

    @retrydec
    def set_sync_rules(self, rules_items, remove_old=True):
        cursor = self.conn.cursor()
        if remove_old:
            cursor.execute('delete from syncdirs ')
        for path, rule in rules_items:
            cursor.execute('Insert into syncdirs (path, rule) VALUES (?, ?)', (path, rule.str_rule))

        self.conn.commit()
        cursor.close()

    def create_tables_if_not_exist(self):
        cursor = self.conn.cursor()
        for tname, tschema in DBTABLES.items():
            tschema_str = (', ').join('%s %s' % (i, j) for i, j in tschema)
            str_command = 'CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY, %s)' % (tname, tschema_str)
            cursor.execute(str_command)

        for tname, indexes in DBTABLES_INDEXES.items():
            for index in indexes:
                if index.lower().startswith('unique:'):
                    index = index.replace('unique:', '')
                    unique = 'UNIQUE'
                else:
                    unique = ''
                index_name = ('').join(index.replace(',', '_').split())
                str_sql_command = 'CREATE %s INDEX IF NOT EXISTS %s ON %s (%s)' % (unique, index_name, tname, index)
                billet.debug(str_sql_command)
                cursor.execute(str_sql_command)

        self.conn.commit()

    @retrydec
    def add_file(self, path, filename, size, mtime, ctime, state=FILEFLAG.QUEUED, queuepriority=0, defer_till=0, rpath=None):
        cursor = self.conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO file(path, filename, size, state, modified, created, queuepriority, defertill, rpath) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) ', (
         path, filename, size, state, mtime, ctime, queuepriority, defer_till, rpath))
        self.conn.commit()
        cursor.close()

    def _get_all_files(self):
        cursor = self.conn.cursor()
        cursor.execute('Select path, filename, size, state, modified, created, queuepriority from file limit 20')
        return cursor.fetchall()

    def _closeconn(self):
        self.conn.close()


if __name__ == '__main__':
    test()
