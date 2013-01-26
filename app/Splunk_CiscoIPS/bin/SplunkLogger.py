'''
Class for generating and rotating logs for Splunk app.
'''
import logging
import logging.handlers

class SplunkLogger:
    def __init__(self, logname, max_bytes, backup_count):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.handlers.RotatingFileHandler(
                    logname, maxBytes=int(max_bytes), backupCount=int(backup_count))
        self.logger.addHandler(handler)

    def info(self, msg):
        self.logger.info(msg)

def test():
    print 'SplunkLogger class testing:'
    logger = SplunkLogger('./test.log', 1024, 5)
    print 'outputting to logfile => ./test.log'
    for i in range(2000):
        logger.info('This is a test %d' % i)
    print 'Finished testing!'
    
if __name__ == '__main__':
    test()