from twisted.logger import Logger
from twisted.logger import textFileLogObserver
from twisted.logger import globalLogPublisher
from twisted.python.logfile import DailyLogFile

log = Logger()
logfile = None
tlog = None
processlog = None

# To bypass exceptions raised of "file does not exist" when generating sphinx-doc
try:
    logfile = DailyLogFile("octopus.log", "var/log/cowrie")
    globalLogPublisher.addObserver(textFileLogObserver(logfile))
except:
    pass

try:
    traininglogfile = DailyLogFile("training.log", "var/log/cowrie")
    tlog = Logger(observer=textFileLogObserver(traininglogfile))
except:
    pass

try:
    processlogfile = DailyLogFile("process.log", "var/train_process_data")
    processlog = Logger(observer=textFileLogObserver(processlogfile), namespace="process")
except:
    pass

# useful to debug third libraries that do not use twisted log
# import logging
# logger = logging.getLogger(__name__)
# logging.basicConfig(filename='var/log/cowrie/python_debug.log', encoding='utf-8', level=logging.DEBUG)