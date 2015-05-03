# encoding=utf8

from server import DHCPServer

__author__ = 'fireflyc'

if __name__ == "__main__":
    server = DHCPServer()
    server.start()