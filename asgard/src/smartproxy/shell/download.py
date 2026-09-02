import getopt

from twisted.python import compat, log
import treq

from cowrie.core.artifact import Artifact
from cowrie.core.config import CowrieConfig

class wget():
    """Download the artifacts by simulating `wget` command."""

    limit_size: int = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    downloadPath: str = CowrieConfig.get("honeypot", "download_path")
    quiet: bool = False

    def __init__(self, protocol, args):
        self.protocol = protocol
        self.args = args
        self.data: bytes = None  # output data
        self.outfile: str = None

    def start(self):
        url: str
        try:
            optlist, args = getopt.getopt(self.args, "cqO:P:", ["header="])
        except getopt.GetoptError:
            return

        if len(args):
            url = args[0].strip()
        else:
            return

        self.quiet = False
        for opt in optlist:
            if opt[0] == "-O":
                self.outfile = opt[1]
            if opt[0] == "-q":
                self.quiet = True

        # for some reason getopt doesn't recognize "-O -"
        # use try..except for the case if passed command is malformed
        try:
            if not self.outfile:
                if "-O" in args:
                    self.outfile = args[args.index("-O") + 1]
        except Exception:
            pass

        if "://" not in url:
            url = f"http://{url}"

        urldata = compat.urllib_parse.urlparse(url)

        self.url = url
        if self.outfile is None:
            self.outfile = urldata.path.split("/")[-1]
            if not len(self.outfile.strip()) or not urldata.path.count("/"):
                self.outfile = "index.html"

        self.artifactFile = Artifact(self.outfile)
        d = treq.get(self.url, unbuffered=True, headers={b'user-agent':b'Wget/1.20.1'})
        d.addCallback(treq.collect, self.artifactFile.write)
        d.addBoth(self.done)

        return d

    def done(self, status):
        if status is None:
            self.artifactFile.close()
            # log to cowrie.log
            log.msg(
                format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s - filename %(filename)s",
                url=self.url,
                outfile=self.artifactFile.shasumFilename,
                shasum=self.artifactFile.shasum,
                filename=self.outfile
            )

            try:
                # log to output modules
                self.protocol.logDispatch(
                    eventid="cowrie.session.file_download",
                    format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
                    url=self.url,
                    outfile=self.artifactFile.shasumFilename,
                    shasum=self.artifactFile.shasum,
                    filename=self.outfile
                )
            except Exception:
                pass
        else:
            # prevent cowrie from crashing if the terminal have been already destroyed
            try:
                self.protocol.logDispatch(
                    eventid="cowrie.session.file_download.failed",
                    format="Attempt to download file(s) from URL (%(self.url)s) failed",
                    url=self.url,
                    filename=self.outfile
                )
            except Exception:
                pass

class curl():
    """Download the artifacts by simulating `curl` command."""

    limit_size = CowrieConfig.getint("honeypot", "download_limit_size", fallback=0)
    download_path = CowrieConfig.get("honeypot", "download_path")

    def __init__(self, protocol, args):
        self.protocol = protocol
        self.args = args
        self.data: bytes = None  # output data
        self.outfile: str = None

    def start(self):
        try:
            optlist, args = getopt.getopt(
                self.args, "sho:O", ["help", "manual", "silent"]
            )
        except getopt.GetoptError as err:
            # TODO: should be 'unknown' instead of 'not recognized'
            return

        for opt in optlist:
            if opt[0] == "-h" or opt[0] == "--help":
                return
            elif opt[0] == "-s" or opt[0] == "--silent":
                self.silent = True

        if len(args):
            if args[0] is not None:
                url = str(args[0]).strip()
        else:
            return

        if "://" not in url:
            url = "http://" + url
        urldata = compat.urllib_parse.urlparse(url)

        outfile = "index.html"
        for opt in optlist:
            if opt[0] == "-o":
                outfile = opt[1]
            if opt[0] == "-O":
                outfile = urldata.path.split("/")[-1]
                if (
                    outfile is None
                    or not len(outfile.strip())
                    or not urldata.path.count("/")
                ):
                    return

        self.outfile = outfile
        url = url.encode("ascii")
        self.url = url

        self.artifactFile = Artifact(self.outfile)
        d = treq.get(self.url, headers={b'user-agent': b'curl/7.64.0'}, unbuffered=True, )
        d.addCallback(treq.collect, self.artifactFile.write)
        d.addBoth(self.done)

        return d

    def done(self, status):
        if status is None:
            self.artifactFile.close()
            # log to cowrie.log
            log.msg(
                format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s - filename %(filename)s",
                url=self.url,
                outfile=self.artifactFile.shasumFilename,
                shasum=self.artifactFile.shasum,
                filename=self.outfile
            )

            try:
                # log to output modules
                self.protocol.logDispatch(
                    eventid="cowrie.session.file_download",
                    format="Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
                    url=self.url,
                    outfile=self.artifactFile.shasumFilename,
                    shasum=self.artifactFile.shasum,
                    filename=self.outfile
                )
            except Exception:
                pass
        else:
            # prevent cowrie from crashing if the terminal have been already destroyed
            try:
                self.protocol.logDispatch(
                    eventid="cowrie.session.file_download.failed",
                    format="Attempt to download file(s) from URL (%(self.url)s) failed",
                    url=self.url,
                    filename=self.outfile
                )
            except Exception:
                pass