# encoding=utf8
import logging
from server import DHCPServer


logging.basicConfig(level=logging.INFO)

__author__ = 'fireflyc'

if __name__ == "__main__":
    server = DHCPServer()
    server.start()
