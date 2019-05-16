#!/usr/bin/env python
import sys
import os
import errno
import fcntl
import time
import getopt
import re
import subprocess
import signal

try:
    # Python 2
    from urllib import urlencode, urlopen
except ImportError:
    # Python 3
    from urllib.parse import urlencode
    from urllib.request import urlopen
from socket import gethostname

# The pCache Version
pcacheversion = "4.2.3"

# Log message levels
DEBUG, INFO, WARN, ERROR = "DEBUG", "INFO ", "WARN ", "ERROR"

# filename for locking
LOCK_NAME = ".LOCK"

# Session ID
sessid = "%s.%s" % (int(time.time()), os.getpid())


# Run a command with a timeout
def run_cmd(args, timeout=0):

    class Alarm(Exception):
        pass

    def alarm_handler(signum, frame):
        raise Alarm

    # Execute the command as a subprocess
    try:
        p = subprocess.Popen(args=args,
                             shell=False,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

    except:
        return (-2, None)

    # Set the timer if a timeout value was given
    if (timeout > 0):
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(timeout)

    # Wait for the command to complete
    try:

        # Collect the output when the command completes
        stdout = p.communicate()[0][:-1]

        # Commmand completed in time, cancel the alarm
        if (timeout > 0):
            signal.alarm(0)

    # Command timed out
    except Alarm:

        # The pid of our spawn
        pids = [p.pid]

        # The pids of the spawn of our spawn
        pids.extend(get_process_children(p.pid))

        # Terminate all of the evil spawn
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

        # Return a timeout error
        return (-1, None)

    return (p.returncode, stdout)


def get_process_children(pid):

    # Get a list of all pids assocaited with a given pid
    p = subprocess.Popen(args='ps --no-headers -o pid --ppid %d' % pid,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)

    # Wait and fetch the stdout
    stdout, stderr = p.communicate()

    # Return a list of pids as tuples
    return [int(pr) for pr in stdout.split()]


def unitize(x):

    suff = 'BKMGTPEZY'

    while ((x >= 1024) and suff):
        x /= 1024.0
        suff = suff[1:]
    return "%.4g%s" % (x, suff[0])


class Pcache:

    def Usage(self):
        msg = """Usage: %s [flags] copy_prog [copy_flags] input output""" % self.progname
        sys.stderr.write("%s\n" % msg)  # py3, py2
    #  print>>sys.stderr, "  flags are: "
    #  "s:r:m:Cy:A:R:t:r:g:fFl:VvqpH:S:",
    #  "scratch-dir=",
    #  "storage-root=",
    #  "max-space=",
    #  "clean",
    #  "hysterisis=",
    #  "accept=",
    #  "reject=",
    #  "timeout=",
    #  "retry=",
    #  "force",
    #  "flush-cache",
    #  "guid=",
    #  "log=",
    #  "version",
    #  "verbose",
    #  "debug",
    #  "quiet",
    #  "panda",
    #  "hostname",
    #  "sitename"

    def __init__(self):
        os.umask(0)
        self.storage_root = "/pnfs"
        self.scratch_dir = "/scratch/"
        self.pcache_dir = self.scratch_dir + "pcache/"
        self.log_file = self.pcache_dir + "pcache.log"
        self.max_space = "80%"
        self.percent_max = None
        self.bytes_max = None
        # self.max_space = "10T"
        self.hysterisis = 0.75
        # self.hysterisis = 0.9
        self.clean = False
        self.transfer_timeout = "600"
        self.max_retries = 3
        self.guid = None
        self.accept_patterns = []
        self.reject_patterns = []
        self.force = False
        self.flush = False
        self.verbose = False
        self.quiet = False
        self.debug = False
        self.hostname = None
        self.sitename = None  # XXX can we get this from somewhere?
        self.update_panda = False
        self.panda_url = "https://pandaserver.cern.ch:25443/server/panda/"
        self.local_src = None
        self.skip_download = False

        # internal variables
        self.sleep_interval = 15
        self.force = False
        self.locks = {}
        self.deleted_guids = []
        self.version = pcacheversion

    def parse_args(self, args):
        # handle pcache flags and leave the rest in self.args

        try:
            opts, args = getopt.getopt(args,
                                       "s:x:m:Cy:A:R:t:r:g:fFl:VvdqpPH:S:L:X:",
                                       ["scratch-dir=",
                                        "storage-root=",
                                        "max-space=",
                                        "clean",
                                        "hysterisis=",
                                        "accept=",
                                        "reject=",
                                        "timeout=",
                                        "retry=",
                                        "force",
                                        "flush-cache",
                                        "guid=",
                                        "log=",
                                        "version",
                                        "verbose",
                                        "debug",
                                        "quiet",
                                        "print-stats",
                                        "panda",
                                        "hostname",
                                        "sitename",
                                        "local-src"])

            # XXXX cache, stats, reset, clean, delete, inventory
            # TODO: move checksum/size validation from lsm to pcache
        except getopt.GetoptError as err:
            sys.stderr.write("%s\n" % str(err))
            self.Usage()
            self.fail(100)

        for opt, arg in opts:
            if opt in ("-s", "--scratch-dir"):
                self.scratch_dir = arg
                # Make sure scratch_dir endswith /
                if not self.scratch_dir.endswith("/"):
                    self.scratch_dir += "/"
                self.pcache_dir = self.scratch_dir + "pcache/"
                self.log_file = self.pcache_dir + "pcache.log"
            elif opt in ("-x", "--storage-root"):
                self.storage_root = arg
            elif opt in ("-m", "--max-space"):
                self.max_space = arg
            elif opt in ("-y", "--hysterisis"):
                if arg.endswith('%'):
                    self.hysterisis = float(arg[:-1]) / 100
                else:
                    self.hysterisis = float(arg)
            elif opt in ("-A", "--accept"):
                self.accept_patterns.append(arg)
            elif opt in ("-R", "--reject"):
                self.reject_patterns.append(arg)
            elif opt in ("-t", "--timeout"):
                self.transfer_timeout = arg
            elif opt in ("-f", "--force"):
                self.force = True
            elif opt in ("-F", "--flush-cache"):
                self.flush = True
            elif opt in ("-C", "--clean"):
                self.clean = True
            elif opt in ("-g", "--guid"):
                if arg == 'None':
                    self.guid = None
                else:
                    self.guid = arg
            elif opt in ("-r", "--retry"):
                self.max_retries = int(arg)
            elif opt in ("-V", "--version"):
                print((str(self.version)))
                sys.exit(0)
            elif opt in ("-l", "--log"):
                self.log_file = arg
            elif opt in ("-v", "--verbose"):
                self.verbose = True
            elif opt in ("-d", "--debug"):
                self.debug = True
            elif opt in ("-q", "--quiet"):
                self.quiet = True
            elif opt in ("-p", "--print-stats"):
                self.print_stats()
                sys.exit(0)
            elif opt in ("-P", "--panda"):
                self.update_panda = True
            elif opt in ("-H", "--hostname"):
                self.hostname = arg
            elif opt in ("-S", "--sitename"):
                self.sitename = arg
            elif opt in ("-L", "--local-src"):
                self.local_src = str(arg)
            elif opt in ("-X", "--skip-download"):
                if str(arg) in ('True', 'true') or arg:
                    self.skip_download = True

        # Treatment of limits on pcache size
        self._convert_max_space()

        # Convert timeout to seconds
        t = self.transfer_timeout
        mult = 1
        suff = t[-1]
        if suff in ('H', 'h'):
            mult = 3600
            t = t[:-1]
        elif suff in ('M', 'm'):
            mult = 60
            t = t[:1]
        elif suff in ('S', 's'):
            mult = 1
            t = t[:-1]
        self.transfer_timeout = mult * int(t)

        # Pre-compile regexes
        self.accept_patterns = list(map(re.compile, self.accept_patterns))
        self.reject_patterns = list(map(re.compile, self.reject_patterns))

        # Set host and name
        if self.hostname is None:
            self.hostname = gethostname()
        if self.sitename is None:
            self.sitename = os.environ.get("SITE", "")  # XXXX

        # All done
        self.args = args

    def _convert_max_space(self):
        '''
        Added by Rucio team. Converts max allowed space usage of pcache into units used by this tool.
        :input self.max_space: limit set by user
        :output self.percent_max: max percentage of pcache space used
        :output self.bytes_max: max size in bytes of pcache space used
        '''

        # Convert max_space arg to percent_max or bytes_max
        if self.max_space.endswith('%'):
            self.percent_max = float(self.max_space[:-1])
            self.bytes_max = None
        else:  # handle suffix
            self.percent_max = None
            m = self.max_space.upper()
            index = "BKMGTPEZY".find(m[-1])
            if index >= 0:
                self.bytes_max = float(m[:-1]) * (1024**index)
            else:  # Numeric value w/o units (exception if invalid)
                self.bytes_max = float(self.max_space)

    def clean_pcache(self, max_space=None):
        '''
        Added by Rucio team. Cleans pcache in case it is over limit.
        Used for tests of the pcache functionality. Can be called without other init.
        '''

        self.t0 = time.time()
        self.progname = "pcache"

        # set max. occupancy of pcache:
        if max_space:
            self.max_space = max_space
        self._convert_max_space()

        # Fail on extra args
        if not self.scratch_dir:
            self.Usage()
            self.fail(100)

        # hardcoded pcache dir
        self.pcache_dir = self.scratch_dir + '/pcache/'

        # clean pcache
        self.maybe_start_cleaner_thread()

    def check_and_link(self, src='', dst='', dst_prefix='', scratch_dir='/scratch/', storage_root=None, force=False,
                       guid=None, log_file=None, version='', hostname=None, sitename=None, local_src=None):
        '''
        Added by Rucio team. Replacement for the main method.
        Checks whether a file is in pcache:
         - if yes: creates a hardlink to the file in pcahce
         - if not:
              - returns 500 and leaves it to Rucio
              - Rucio downloads a file
        Makes hardlink in pcache to downloaded file:
         - needs :param local_src: path to downloaded file
        '''
        self.t0 = time.time()
        self.progname = "pcache"
        self.pcache_dir = scratch_dir + '/pcache/'
        self.src = src
        self.dst = dst
        self.dst_prefix = dst_prefix
        self.sitename = sitename
        self.hostname = hostname
        self.guid = guid
        if log_file:
            self.log_file = log_file
        self.local_src = local_src
        self.version = version
        self.storage_root = storage_root

        # Cache dir may have been wiped
        if ((not os.path.exists(self.pcache_dir)) and self.update_panda):
            self.panda_flush_cache()

        # Create the pCache directory
        if (self.mkdir_p(self.pcache_dir)):
            self.fail(101)

        self.log(INFO, "%s %s invoked as: API", self.progname, self.version)

        # Fail on extra args
        if not scratch_dir:
            self.Usage()
            self.fail(100)

        # If the source is lfn:, execute original command, no further action
        if (self.src.startswith('lfn:')):
            # status = os.execvp(self.copy_util, self.args)
            os._exit(1)

        # If the destination is a local file, do some rewrites
        if (self.dst.startswith('file:')):
            self.dst_prefix = 'file:'
            self.dst = self.dst[5:]
            # Leave one '/' on dst
            while ((len(self.dst) > 1) and (self.dst[1] == '/')):
                self.dst_prefix += '/'
                self.dst = self.dst[1:]

        # load file into pcache
        self.create_pcache_dst_dir()
        # XXXX TODO _ dst_dir can get deleted before lock!
        waited = False

        # If another transfer is active, lock_dir will block
        if (self.lock_dir(self.pcache_dst_dir, blocking=False)):
            waited = True
            self.log(INFO, "%s locked, waiting", self.pcache_dst_dir)
            self.lock_dir(self.pcache_dst_dir, blocking=True)

        if (waited):
            self.log(INFO, "waited %.2f secs", time.time() - self.t0)

        if force:
            self.empty_dir(self.pcache_dst_dir)

        # The name of the cached version of this file
        cache_file = self.pcache_dst_dir + "data"

        # Check if the file is in cache or we need to transfer it down
        if (os.path.exists(cache_file)):
            exit_status = 0
            copy_status = None
            self.log(INFO, "check_and_link: file found in cache")
            self.log(INFO, "cache hit %s", self.src)
            self.update_stats("cache_hits")
            self.finish()
            if (os.path.exists(self.dst)):
                copy_status = 1
        elif self.local_src:
            exit_status = 1
            copy_status = None
            self.log(INFO, "check_and_link: local replica found, linking to pcache")
            self.finish()
        else:
            self.log(INFO, "check_and_link: %s file not found in pcache and was not downloaded yet", self.src)
            return (500, None)

        self.unlock_dir(self.pcache_dst_dir)
        self.log(INFO, "total time %.2f secs", time.time() - self.t0)

        # in case that the pcache is over limit
        self.maybe_start_cleaner_thread()

        # Return if the file was cached, copied or an error (and its code)
        return (exit_status, copy_status)

    def main(self, args):

        # args
        self.cmdline = ' '.join(args)
        self.t0 = time.time()
        self.progname = args[0] or "pcache"

        # Must have a list of arguments
        if (self.parse_args(args[1:])):
            self.Usage()
            self.fail(100)

        # Cache dir may have been wiped
        if ((not os.path.exists(self.pcache_dir)) and self.update_panda):
            self.panda_flush_cache()

        # Create the pCache directory
        if (self.mkdir_p(self.pcache_dir)):
            self.fail(101)

        self.log(INFO, "%s %s invoked as: %s", self.progname, self.version, self.cmdline)

        # Are we flushing the cache
        if (self.flush):
            if (self.args):
                sys.stderr.write("--flush not compatible with other options")
                self.fail(100)
            else:
                self.flush_cache()
                sys.exit(0)

        # Are we cleaning the cache
        if (self.clean):
            # size = self.do_cache_inventory()
            self.maybe_start_cleaner_thread()
            if (len(self.args) < 1):
                sys.exit(0)

        # Fail on extra args
        if (len(self.args) < 3):
            self.Usage()
            self.fail(100)

        self.copy_util = self.args[0]
        self.copy_args = self.args[1:-2]
        self.src = self.args[-2]
        self.dst = self.args[-1]
        self.dst_prefix = ''

        # If the source is lfn:, execute original command, no further action
        if (self.src.startswith('lfn:')):
            # status = os.execvp(self.copy_util, self.args)
            os._exit(1)

        # If the destination is a local file, do some rewrites
        if (self.dst.startswith('file:')):
            self.dst_prefix = 'file:'
            self.dst = self.dst[5:]
            # Leave one '/' on dst
            while ((len(self.dst) > 1) and (self.dst[1] == '/')):
                self.dst_prefix += '/'
                self.dst = self.dst[1:]

        # Execute original command, no further action
        if (not (self.dst.startswith(self.scratch_dir) and self.accept(self.src) and (not self.reject(self.src)))):
            os.execvp(self.copy_util, self.args)
            os._exit(1)

        # XXXX todo:  fast-path - try to acquire lock
        # first, if that succeeds, don't call
        # create_pcache_dst_dir

        # load file into pcache
        self.create_pcache_dst_dir()
        # XXXX TODO _ dst_dir can get deleted before lock!
        waited = False

        # If another transfer is active, lock_dir will block
        if (self.lock_dir(self.pcache_dst_dir, blocking=False)):
            waited = True
            self.log(INFO, "%s locked, waiting", self.pcache_dst_dir)
            self.lock_dir(self.pcache_dst_dir, blocking=True)

        if (waited):
            self.log(INFO, "waited %.2f secs", time.time() - self.t0)

        if (self.force):
            self.empty_dir(self.pcache_dst_dir)

        # The name of the cached version of this file
        cache_file = self.pcache_dst_dir + "data"

        # Check if the file is in cache or we need to transfer it down
        if (os.path.exists(cache_file)):
            exit_status = 1
            copy_status = None
            self.log(INFO, "cache hit %s", self.src)
            self.update_stats("cache_hits")
            self.finish()
        else:
            if self.skip_download:
                return (500, None)
            self.update_stats("cache_misses")
            exit_status, copy_status = self.pcache_copy_in()
            if ((exit_status == 0) or (exit_status == 2)):
                self.finish()

        self.unlock_dir(self.pcache_dst_dir)
        self.log(INFO, "total time %.2f secs", time.time() - self.t0)

        self.maybe_start_cleaner_thread()

        # Return if the file was cached, copied or an error (and its code)
        return (exit_status, copy_status)

    def finish(self, local_src=None):
        cache_file = self.pcache_dst_dir + "data"
        self.update_mru()
        if self.local_src:
            if (self.make_hard_link(self.local_src, cache_file)):
                self.fail(102)
        else:
            if (self.make_hard_link(cache_file, self.dst)):
                self.fail(102)

    def pcache_copy_in(self):

        cache_file = self.pcache_dst_dir + "data"

        # Record source URL
        try:
            fname = self.pcache_dst_dir + "src"
            f = open(fname, 'w')
            f.write(self.src + '\n')
            f.close()
            self.chmod(fname, 0o666)
        except:
            pass

        # Record GUID if given
        if (self.guid):
            try:
                fname = self.pcache_dst_dir + "guid"
                f = open(fname, 'w')
                f.write(self.guid + '\n')
                f.close()
                self.chmod(fname, 0o666)
            except:
                pass

        # Try to transfer the file up the the number of retries allowed
        retry = 0
        while (retry <= self.max_retries):

            # Is this is a retry attempt, log it as such
            if (retry > 0):
                self.log(INFO, "do_transfer: retry %s", retry)

            # Do the transfer. exit_status will be either
            # 0 - success
            # 3 - Transfer command failed. copy_status has the return code
            # 4 - Transfer command timed out
            # 5 - Transfer command was not found
            exit_status, copy_status = self.do_transfer()

            # If success, stop trying, otherwise increment the retry count
            if (exit_status == 0):
                break
            retry += 1

        # Did the transfer succeed
        if (exit_status == 0):

            # If we succeeded on a retry, return status 2 and the retries
            if (retry == 0):
                copy_status = None
            else:
                exit_status = 2
                copy_status = retry

            # Update the cache information
            if self.local_src:
                self.update_cache_size(os.stat(self.local_src).st_size)
            else:
                self.update_cache_size(os.stat(cache_file).st_size)

            # Update the panda cache
            if (self.guid and self.update_panda):
                self.panda_add_cache_files((self.guid,))

        return (exit_status, copy_status)

    def create_pcache_dst_dir(self):

        d = self.src
        index = d.find(self.storage_root)

        if (index >= 0):
            d = d[index:]
        else:
            index = d.find("SFN=")
            if (index >= 0):
                d = d[index + 4:]

        # self.log(INFO, '%s', self.storage_root)
        # self.log(INFO, '%s', d)
        # XXXX any more patterns to look for?
        d = os.path.normpath(self.pcache_dir + "CACHE/" + d)
        if (not d.endswith('/')):
            d += '/'

        self.pcache_dst_dir = d
        status = self.mkdir_p(d)
        if (status):
            self.log(ERROR, "mkdir %s %s", d, status)
            self.fail(103)

    def get_disk_usage(self):
        p = os.popen("df -P %s | tail -1" % self.pcache_dir, 'r')
        data = p.read()
        status = p.close()
        if status:
            self.log(ERROR, "get_disk_usage: df command failed, status=%s", status)
            sys.exit(1)
        tok = data.split()
        percent = tok[-2]
        if not percent.endswith('%'):
            self.log(ERROR, "get_disk_usage: cannot parse df output: %s", data)
            sys.exit(1)
        percent = int(percent[:-1])
        return percent

    def over_limit(self, factor=1.0):
        if self.percent_max:
            return self.get_disk_usage() > factor * self.percent_max
        if self.bytes_max:
            return self.get_cache_size() > factor * self.bytes_max
        return False

    def clean_cache(self):
        t0 = time.time()

        self.log(INFO, "starting cleanup, cache size=%s, usage=%s%%",
                 unitize(self.get_cache_size()),
                 self.get_disk_usage())

        for l in self.list_by_mru():
            try:
                d = os.readlink(l)

            except OSError as e:
                self.log(ERROR, "readlink: %s", e)
                continue

            self.log(DEBUG, "deleting %s", d)

            if os.path.exists(d):
                self.empty_dir(d)
            else:
                self.log(WARN, "Attempt to delete missing file %s", d)
                self.flush_cache()
                break

            # empty_dir should also delete MRU symlink, but
            # mop up here in there is some problem with the
            # backlink

            try:
                os.unlink(l)

            except OSError as e:
                if e.errno != errno.ENOENT:
                    self.log(ERROR, "unlink: %s", e)

            if not self.over_limit(self.hysterisis):
                break

        self.log(INFO, "cleanup complete, cache size=%s, usage=%s%%, time=%.2f secs",
                 self.get_cache_size(),
                 self.get_disk_usage(),
                 time.time() - t0)

    def list_by_mru(self):
        mru_dir = self.pcache_dir + "MRU/"
        for root, dirs, files in os.walk(mru_dir):
            dirs.sort()
            for d in dirs:
                path = os.path.join(root, d)
                if os.path.islink(path):
                    dirs.remove(d)
                    yield path
            if files:
                files.sort()
                for file in files:
                    path = os.path.join(root, file)
                    yield path

    def flush_cache(self):
        # Delete everything in CACHE, MRU, and reset stats
        self.log(INFO, "flushing cache")
        if self.update_panda:
            self.panda_flush_cache()
        self.reset_stats()
        ts = '.' + str(time.time())
        for d in "CACHE", "MRU":
            d = self.pcache_dir + d
            try:
                os.rename(d, d + ts)
                os.system("rm -rf %s &" % (d + ts))
            except OSError as e:
                if e.errno != errno.ENOENT:
                    self.log(ERROR, "%s: %s", d, e)

    def do_transfer(self):

        # Cache file and transfer file locations
        cache_file = self.pcache_dst_dir + "data"
        xfer_file = self.pcache_dst_dir + "xfer"

        # Remove any transfer file with the same name
        try:
            os.unlink(xfer_file)
        except OSError as e:
            if e.errno != errno.ENOENT:
                self.log(ERROR, "unlink: %s", e)

        # Build the copy command with the destination into the xfer location
        args = self.args[:]
        args[-1] = self.dst_prefix + xfer_file

        # Save the current time for timing output
        t0 = time.time()

        # Do the copy with a timeout
        if self.local_src:
            return(0, None)
        else:
            copy_status, copy_output = run_cmd(args, self.transfer_timeout)

        # Did the command timeout
        if (copy_status == -1):
            self.log(ERROR, "copy command timed out, elapsed time = %.2f sec", time.time() - t0)
            self.cleanup_failed_transfer()
            return (4, None)
        elif (copy_status == -2):
            self.log(ERROR, "copy command was not found")
            self.cleanup_failed_transfer()
            return (5, None)

        # Display any output from the copy
        if (copy_output):
            print('%s' % copy_output)

        # Did the copy succeed (good status and an existing file)
        if ((copy_status > 0) or (not os.path.exists(xfer_file))):
            self.log(ERROR, "copy command failed, elapsed time = %.2f sec", time.time() - t0)
            self.cleanup_failed_transfer()
            return (3, copy_status)

        self.log(INFO, "copy command succeeded, elapsed time = %.2f sec", time.time() - t0)

        try:
            os.rename(xfer_file, cache_file)
            # self.log(INFO, "rename %s %s", xfer_file, cache_file)
        except OSError as e:  # Fatal error if we can't do this
            self.log(ERROR, "rename %s %s", xfer_file, cache_file)
            try:
                os.unlink(xfer_file)
            except:
                pass
            self.fail(104)

        # Make the file readable to all
        self.chmod(cache_file, 0o666)

        # Transfer completed, return the transfer command status
        return (0, None)

    def maybe_start_cleaner_thread(self):
        if not self.over_limit():
            return
        # exit immediately if another cleaner is active
        cleaner_lock = os.path.join(self.pcache_dir, ".clean")
        if self.lock_file(cleaner_lock, blocking=False):
            self.log(INFO, "cleanup not starting:  %s locked", cleaner_lock)
            return
        # see http://www.faqs.org/faqs/unix-faq/faq/part3/section-13.html
        # for explanation of double-fork
        pid = os.fork()
        if pid:  # parent
            os.waitpid(pid, 0)
            return
        else:  # child
            self.daemonize()
            pid = os.fork()
            if pid:
                os._exit(0)
            # grandchild
            self.clean_cache()
            self.unlock_file(cleaner_lock)
            os._exit(0)

    def make_hard_link(self, src, dst):
        self.log(INFO, "linking %s to %s", src, dst)
        try:
            if os.path.exists(dst):
                os.unlink(dst)
            os.link(src, dst)
        except OSError as e:
            self.log(ERROR, "make_hard_link: %s", e)
            ret = e.errno
            if ret == errno.ENOENT:
                try:
                    stat_info = os.stat(src)
                    self.log(INFO, "stat(%s) = %s", src, stat_info)
                except:
                    self.log(INFO, "cannot stat %s", src)
                try:
                    stat_info = os.stat(dst)
                    self.log(INFO, "stat(%s) = %s", dst, stat_info)
                except:
                    self.log(INFO, "cannot stat %s", dst)
            return ret

    def reject(self, name):
        for pat in self.reject_patterns:
            if pat.search(name):
                return True
        return False

    def accept(self, name):
        if not self.accept_patterns:
            return True
        for pat in self.accept_patterns:
            if pat.search(name):
                return True
        return False

    def get_stat(self, stats_dir, stat_name):
        filename = os.path.join(self.pcache_dir, stats_dir, stat_name)
        try:
            f = open(filename, 'r')
            data = int(f.read().strip())
            f.close()
        except:
            data = 0
        return data

    def print_stats(self):
        print(("Cache size: %s", unitize(self.get_stat("CACHE", "size"))))
        print(("Cache hits: %s", self.get_stat("stats", "cache_hits")))
        print(("Cache misses: %s", self.get_stat("stats", "cache_misses")))

    def reset_stats(self):
        stats_dir = os.path.join(self.pcache_dir, "stats")
        try:
            for f in os.listdir(stats_dir):
                try:
                    os.unlink(os.path.join(stats_dir, f))
                except:
                    pass
        except:
            pass
        # XXXX error handling
        pass

    def update_stat_file(self, stats_dir, name, delta):  # internal
        stats_dir = os.path.join(self.pcache_dir, stats_dir)
        self.mkdir_p(stats_dir)
        self.lock_dir(stats_dir)
        stats_file = os.path.join(stats_dir, name)
        try:
            f = open(stats_file, 'r')
            data = f.read()
            f.close()
            value = int(data)
        except:
            # XXXX
            value = 0
        value += delta
        try:
            f = open(stats_file, 'w')
            f.write("%s\n" % value)
            f.close()
            self.chmod(stats_file, 0o666)
        except:
            pass
            # XXX
        self.unlock_dir(stats_dir)

    def update_stats(self, name, delta=1):
        return self.update_stat_file("stats", name, delta)

    def update_cache_size(self, bytes):
        return self.update_stat_file("CACHE", "size", bytes)

    def get_cache_size(self):
        filename = os.path.join(self.pcache_dir, "CACHE", "size")
        size = 0

        try:
            f = open(filename)
            data = f.read()
            size = int(data)
        except:
            pass

        # If we could not fetch the size, do a reinventory
        if size == 0:
            size = self.do_cache_inventory()

        # The size should never be negative, so lets cleanup and start over
        if size < 0:
            self.log(WARN, "CACHE corruption found. Negative CACHE size: %d", size)
            self.flush_cache()
            size = 0

        return size

    def do_cache_inventory(self):

        inventory_lock = os.path.join(self.pcache_dir, ".inventory")
        if self.lock_file(inventory_lock, blocking=False):
            return

        size = 0

        self.log(INFO, "starting inventory")

        for root, dirs, files in os.walk(self.pcache_dir):
            for f in files:
                if f == "data":
                    fullname = os.path.join(root, f)
                    try:
                        size += os.stat(fullname).st_size
                    except OSError as e:
                        self.log(ERROR, "stat(%s): %s", fullname, e)

        filename = os.path.join(self.pcache_dir, "CACHE", "size")

        try:
            f = open(filename, 'w')
            f.write("%s\n" % size)
            f.close()
            self.chmod(filename, 0o666)
        except:
            pass  # XXXX

        self.unlock_file(inventory_lock)
        self.log(INFO, "inventory complete, cache size %s", size)
        return size

    def daemonize(self):
        if self.debug:
            return
        try:
            os.setsid()
        except OSError:
            pass
        try:
            os.chdir("/")
        except OSError:
            pass
        try:
            os.umask(0)
        except OSError:
            pass
        n = os.open("/dev/null", os.O_RDWR)
        i, o, e = sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno()
        os.dup2(n, i)
        os.dup2(n, o)
        os.dup2(n, e)
        MAXFD = 1024
        try:
            import resource  # Resource usage information.
            maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            if (maxfd == resource.RLIM_INFINITY):
                maxfd = MAXFD
        except:
            try:
                maxfd = os.sysconf("SC_OPEN_MAX")
            except:
                maxfd = MAXFD  # use default value

        for fd in range(0, maxfd + 1):
            try:
                os.close(fd)
            except:
                pass

    # Panda server callback functions
    def do_http_post(self, url, data):
        # see http://www.faqs.org/faqs/unix-faq/faq/part3/section-13.html
        # for explanation of double-fork (is it overkill here?)
        pid = os.fork()
        if pid:  # parent
            os.waitpid(pid, 0)
            return
        else:  # child
            self.daemonize()
            pid = os.fork()
            if pid:
                os._exit(0)
            # grandchild
            retry = 0
            # This will retry for up to 1 hour, at 2 minute intervals
            while retry < 30:
                try:
                    u = urlopen(url, data=urlencode(data))
                    ret = u.read()
                    u.close()
                    self.log(INFO, "http post to %s, retry %s, data='%s', return='%s'",
                             url, retry, data, ret)
                    if ret == "True":
                        break
                except:
                    exc, msg, tb = sys.exc_info()
                    self.log(ERROR, "post to %s, data=%s, error=%s", url, data, msg)
                retry += 1
                time.sleep(120)
            # finished, don't keep the child thread around!
            os._exit(0)

    def panda_flush_cache(self):
        self.do_http_post(self.panda_url + "flushCacheDB",
                          data={"site": self.sitename,
                                "node": self.hostname})

    def panda_add_cache_files(self, guids):
        self.do_http_post(self.panda_url + "addFilesToCacheDB",
                          data={"site": self.sitename,
                                "node": self.hostname,
                                "guids": ','.join(guids)})

    def panda_del_cache_files(self, guids):
        self.do_http_post(self.panda_url + "deleteFilesFromCacheDB",
                          data={"site": self.sitename,
                                "node": self.hostname,
                                "guids": ','.join(guids)})

    # Locking functions
    def lock_dir(self, d, create=True, blocking=True):
        lock_name = os.path.join(d, LOCK_NAME)
        lock_status = self.lock_file(lock_name, blocking)
        if (not lock_status):  # succeeded
            return
        if ((lock_status == errno.ENOENT) and create):
            mkdir_status = self.mkdir_p(d)
            if (mkdir_status):
                self.log(ERROR, "mkdir %s %s", d, mkdir_status)
                self.fail(105)
            lock_status = self.lock_file(lock_name, blocking)
        return lock_status

    def unlock_dir(self, d):
        return self.unlock_file(os.path.join(d, LOCK_NAME))

    def lock_file(self, name, blocking=True):
        if name in self.locks:
            self.log(DEBUG, "lock_file: %s already locked", name)
            return
        try:
            f = open(name, 'w')
        except IOError as e:
            self.log(ERROR, "open: %s", e)
            return e.errno

        self.locks[name] = f
        flag = fcntl.LOCK_EX
        if not blocking:
            flag |= fcntl.LOCK_NB
        while True:
            try:
                status = fcntl.lockf(f, flag)
                break
            except IOError as e:
                if e.errno in (errno.EAGAIN, errno.EACCES) and not blocking:
                    f.close()
                    del self.locks[name]
                    return e.errno
                if e.errno != errno.EINTR:
                    status = e.errno
                    self.log(ERROR, "lockf: %s", e)
                    self.fail(106)
        return status

    def unlock_file(self, name):
        f = self.locks.get(name)
        if not f:
            self.log(DEBUG, "unlock_file: %s not locked", name)
            return

        # XXXX does this create a possible race condition?
        if 0:
            try:
                os.unlink(name)
            except:
                pass
        status = fcntl.lockf(f, fcntl.LOCK_UN)
        f.close()
        del self.locks[name]
        return status

    def unlock_all(self):
        for filename, f in list(self.locks.items()):
            try:
                f.close()
                os.unlink(filename)
            except:
                pass

    # Cleanup functions
    def delete_file_and_parents(self, name):
        try:
            os.unlink(name)
        except OSError as e:
            if e.errno != errno.ENOENT:
                self.log(ERROR, "unlink: %s", e)
                self.fail(107)
        self.delete_parents_recursive(name)

    def delete_parents_recursive(self, name):  # internal
        try:
            dirname = os.path.dirname(name)
            if not os.listdir(dirname):
                os.rmdir(dirname)
                self.delete_parents_recursive(dirname)
        except OSError as e:
            self.log(DEBUG, "delete_parents_recursive: %s", e)

    def update_mru(self):
        now = time.time()
        link_to_mru = self.pcache_dst_dir + "mru"
        if os.path.exists(link_to_mru):
            link = os.readlink(link_to_mru)
            self.delete_file_and_parents(link)

        try:
            os.unlink(link_to_mru)
        except OSError as e:
            if e.errno != errno.ENOENT:
                self.log(ERROR, "unlink: %s", e)
                self.fail(108)

        mru_dir = self.pcache_dir + "MRU/" + time.strftime("%Y/%m/%d/%H/%M/",
                                                           time.localtime(now))

        self.mkdir_p(mru_dir)

        # getting symlink
        name = "%.3f" % (now % 60)
        ext = 0
        while True:
            if ext:
                link_from_mru = "%s%s-%s" % (mru_dir, name, ext)
            else:
                link_from_mru = "%s%s" % (mru_dir, name)

            try:
                os.symlink(self.pcache_dst_dir, link_from_mru)
                break
            except OSError as e:
                if e.errno == errno.EEXIST:
                    ext += 1  # add an extension & retry if file exists
                    continue
                else:
                    self.log(ERROR, "symlink: %s %s", e, link_from_mru)
                    self.fail(109)

        while True:
            try:
                os.symlink(link_from_mru, link_to_mru)
                break
            except OSError as e:
                if e.errno == errno.EEXIST:
                    try:
                        os.unlink(link_to_mru)
                    except OSError as e:
                        if e.errno != errno.ENOENT:
                            self.log(ERROR, "unlink: %s %s", e, link_to_mru)
                            self.fail(109)
                else:
                    self.log(ERROR, "symlink: %s %s", e, link_from_mru)
                    self.fail(109)

    def cleanup_failed_transfer(self):
        try:
            os.unlink(self.pcache_dir + 'xfer')
        except:
            pass

    def empty_dir(self, d):
        status = None
        bytes_deleted = 0
        for name in os.listdir(d):
            size = 0
            fullname = os.path.join(d, name)
            if name == "data":
                try:
                    size = os.stat(fullname).st_size
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        self.log(WARN, "stat: %s", e)
            elif name == "guid":
                try:
                    guid = open(fullname).read().strip()
                    self.deleted_guids.append(guid)
                except:
                    pass  # XXXX
            elif name == "mru" and os.path.islink(fullname):
                try:
                    mru_file = os.readlink(fullname)
                    os.unlink(fullname)
                    self.delete_file_and_parents(mru_file)
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        self.log(WARN, "empty_dir: %s", e)
            try:
                if self.debug:
                    print(("UNLINK %s", fullname))
                os.unlink(fullname)
                bytes_deleted += size
            except OSError as e:
                if e.errno != errno.ENOENT:
                    self.log(WARN, "empty_dir2: %s", e)
                # self.fail()
        self.update_cache_size(-bytes_deleted)
        self.delete_parents_recursive(d)
        return status

    def chmod(self, path, mode):
        try:
            os.chmod(path, mode)
        except OSError as e:
            if e.errno != errno.EPERM:  # Cannot chmod files we don't own!
                self.log(ERROR, "chmod %s %s", path, e)

    def mkdir_p(self, d, mode=0o777):
        # Thread-safe
        try:
            os.makedirs(d, mode)
            return 0
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                # Don't use log here, log dir may not exist
                sys.stderr.write("%s\n" % str(e))
                return e.errno

    def log(self, level, msg, *args):

        # Disable all logging
        if (self.quiet):
            return

        if ((level == DEBUG) and (not self.debug)):
            return

        msg = "%s %s %s %s %s\n" % (time.strftime("%F %H:%M:%S"),
                                    sessid,
                                    self.hostname,
                                    level,
                                    str(msg) % args)

        try:
            f = open(self.log_file, "a+", 0o666)
            f.write(msg)
            f.close()

        except Exception as e:
            sys.stderr.write("%s\n" % str(e))
            sys.stderr.write(msg)
            sys.stderr.flush()

        if (self.debug or self.verbose or (level == ERROR)):
            sys.stderr.write(msg)
            sys.stderr.flush()

    def fail(self, errcode=1):
        self.unlock_all()
        sys.exit(errcode)

##################################################################################

# pCache exit_status will be
#
#    0 - File was transferred into cache and is ready
#    1 - File is cached and ready to use
#    2 - File was transferred but with a retry (copy_status has the retry count)
#    3 - Transfer command failed (copy_status has the transfer return code)
#    4 - Transfer command timed out
#
#  100 - Usage error
#  101 - Cache directory does not exist
#  102 - Cache hard link error
#  103 - Cache destination mkdir error
#  104 - Cache rename error
#  105 - Cache locking error
#  106 - Cache file locking error
#  107 - Cache cleanup error
#  108 - Cache MRU update error
#  109 - Cache MRU link error
#  500 - Is file in pcache? No other action


if (__name__ == "__main__"):

    # Load pCache
    p = Pcache()

    # Save the passed arguments
    args = sys.argv

    # Find the file
    exit_status, copy_status = p.main(args)

    # Take us home percy...
    sys.exit(exit_status)
