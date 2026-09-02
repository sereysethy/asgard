import requests
import treq
import json
from twisted.python import log
from twisted.internet import task, reactor, defer
from twisted.python.failure import Failure
from cowrie.core.config import CowrieConfig
from twisted.web import http
from twisted.internet import error

class Monitor:
    def __init__(self, container_name=None):
        self.cadvisor_url = CowrieConfig().get('cadvisor', 'url')
        self.last_timestamp = None
        self.last_stats = None
        self.container_name = container_name
        self.counter = 0
        self.debug = self.debug = CowrieConfig().getboolean('monitor',
                                                    'debug', fallback=False)

    def requestStats(self):
        if self.debug:
            response = {"memory": 0.0, "network_rcv": 0.0, "network_trx": 0.0}
        else:
            response = self._callcAdvisor()

        return response

    def _callcAdvisor(self):
        # api to call to get current statistic of this container
        api = self.cadvisor_url + self.container_name
        
        params = {
            'type': 'docker',
            'count': 1
        }
        d = treq.get(api, params=params)
        d.addCallback(self._cbDone)
        d.addErrback(self._cbError)
        return d

    @defer.inlineCallbacks
    def _cbDone(self, response):
        if response.code == http.OK:
            try:
                stats = yield response.json()
                key = "/docker/" + self.container_name
                stats = stats[key][0]
                # save last timestamp
                if self.last_timestamp is None:
                    self.last_timestamp = stats['timestamp']
                    self.last_stats = self._processStats(stats)
                else:
                    if self.last_timestamp != stats['timestamp']:
                        # save last timestamp
                        self.last_timestamp = stats['timestamp']
                        self.last_stats = self._processStats(stats)
                    else:
                        # we got the same data, backend did not return new stats
                        log.msg('same data return: ', self.last_timestamp)
            except json.decoder.JSONDecodeError as e:
                log.err(e)
                raise json.decoder.JSONDecodeError

        return self.last_stats

    def _cbError(self, failure):
        """Dont trap errors but propagate it"""
        #failure.trap(error.ConnectionRefusedError, Exception)
        log.err(str(failure))
        return failure

    def _processStats(self, stats):
        d = dict()
        d['timestamp'] = stats['timestamp']
        if stats['has_memory']:
            d['memory'] = stats['memory']['usage']
        if stats['has_network']:
            interfaces = stats['network']['interfaces']
            d['network_rcv'] = 0
            d['network_trx'] = 0
            for i in range(len(interfaces)):
                d['network_rcv'] += interfaces[i]['rx_bytes']
                d['network_trx'] += interfaces[i]['tx_bytes']

        return d
         
    def requestCPU(self):
        # get cpu usage
        payload = {
            'pretty': 'false',
            'db': self.influxdb_db,
            'q':'select derivative("value",1s) / 1000000000 \
                 from container_cpu_usage_seconds_total \
                 where "name"=\'debian-ssh\' and time > now() - 1m group by cpu;'
        }

        cpu = requests.get(self.influxdb_url, params=payload)
        log.msg(cpu.json())

    def requestMemory(self):
        # get memory
        payload = {
            'pretty': 'false',
            'db': 'prometheus',
            'q':'select value from container_memory_usage_bytes where \
                    \"name\"=\'debian-ssh\' and time > now() - 1m'

        }
        memory = requests.get(self.influxdb_url, params=payload)
        log.msg(memory.json())

    def requestNetworkRcv(self):
        # get network received
        payload = {
            'pretty': 'false',
            'db': self.influxdb_db,
            'q':'select derivative("value", 1s) from container_network_receive_bytes_total where \
                    \"name\"=\'debian-ssh\' and time > now() - 1m'

        }

        networkRcv = requests.get(self.influxdb_url, params=payload)
        log.msg(networkRcv.json())

    def requestNetworkTrx(self):
        # get network transmission
        payload = {
            'pretty': 'false',
            'db': self.influxdb_db,
            'q':'select derivative("value", 1s) from container_network_transmit_bytes_total where \
                    \"name\"=\'debian-ssh\' and time > now() - 1m'

        }

        networkTrx = requests.get(self.influxdb_url, params=payload)
        log.msg(networkTrx.json())
