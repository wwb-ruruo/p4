#!/usr/bin/env python3
import threading
from queue import Queue



msgq = Queue()

def getmsg():
    while True:
        msg = msgq.get()
        print("msg: ",msg,end='\n')

def sendmsg():
    while True:
        msg = input('input some: ')
        msgq.put(msg)


t1 = threading.Thread(target = getmsg)
t2 = threading.Thread(target = sendmsg)
t1.start()
t2.start()
t2.join()
t1.join()
