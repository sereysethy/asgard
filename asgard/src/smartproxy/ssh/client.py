from twisted.internet import reactor
from twisted.application import service
from cowrie.core.config import CowrieConfig
from smartproxy.ssh.factory import SSHClientFactory

class Client(service.Service):
    def __init__(self):
        self.username = CowrieConfig().get('proxy', 'backend_user')
        self.password = CowrieConfig().get('proxy', 'backend_pass')
        self.server = CowrieConfig().get('proxy', 'backend_ssh_host')
        self.port = CowrieConfig().getint('proxy', 'backend_ssh_port')
        
    def startService(self):
        sshClientfactory = SSHClientFactory(self.username, self.password)
        reactor.connectTCP(self.server, self.port, sshClientfactory)

    def stopService(self):
        return None