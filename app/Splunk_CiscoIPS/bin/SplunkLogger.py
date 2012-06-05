'''
Class for generating and rotating logs for Splunk app.
'''
import logging
import logging.handlers

class SplunkLogger:
    def __init__(self, logname, max_bytes, backup_count, log_instance_name):
        self.logger = logging.getLogger(log_instance_name)
        self.logger.setLevel(logging.INFO)
        LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
        fmt = logging.Formatter(LOG_FORMAT)
        handler = logging.handlers.RotatingFileHandler(
                    logname, maxBytes=int(max_bytes), backupCount=int(backup_count))
        handler.setFormatter(fmt)
        self.logger.addHandler(handler)

    def info(self, msg):
        self.logger.info(msg)
        
    def error(self, msg):
        self.logger.error(msg)

def test():
    print("SplunkLogger class testing:")
    logger = SplunkLogger("./test.log", 102400, 5, "splunklogger")
    print("outputting to logfile => ./test.log")
    for i in range(2000):
        logger.info("This is INFO log %04d" % i)
        logger.error("This is ERROR log %04d" % i)
    print("Finished testing!")
    
if __name__ == '__main__':
    test()