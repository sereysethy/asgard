# from twisted.internet.protocol import Protocol

# class MyProtocol(Protocol):
#     def dataReceived(data):
#         pass

class MyProtocol():
    def __init__(self, defer):
        self.defer = defer

    def exec(self, command):
        self.defer.callback(command)
