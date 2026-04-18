#!/usr/local/CyberCP/bin/python
import socket
import sys
sys.path.append('/usr/local/CyberCP')
from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
import argparse
from plogical.mailUtilities import mailUtilities

class cacheClient:
    cleaningPath = '/home/nitpanel/purgeCache'

    @staticmethod
    def handleCachePurgeRequest(command):
        try:
            mailUtilities.checkHome()
            writeToFile = open(cacheClient.cleaningPath, 'w')
            writeToFile.write(command)
            writeToFile.close()

        except BaseException as msg:
            logging.writeToFile(str(msg) + ' [cacheClient.handleCachePurgeRequest]')


def main():

    parser = argparse.ArgumentParser(description='NitPanel Email Policy Cache Cleaner')
    parser.add_argument('function', help='Specific a function to call!')


    args = parser.parse_args()

    if args.function == "hourlyCleanup":
        command = 'nitpanelCleaner hourlyCleanup'
        cacheClient.handleCachePurgeRequest(command)
    elif args.function == 'monthlyCleanup':
        command = 'nitpanelCleaner monthlyCleanup'
        cacheClient.handleCachePurgeRequest(command)


if __name__ == "__main__":
    main()