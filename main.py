import time
from utils import *
import multiprocessing
if __name__ == "__main__":
    logger.info("ICMP handler Start ...")
    proc1 = multiprocessing.Process(target=sniff, kwargs={"filter": 'icmp', "prn": client_icmp, "store": 0})
    proc1.start()
    logger.info("Main Functions Start ...")
    while True:
        time.sleep(1.5)
        print(menu_text)
        check_inp = input(">")
        if check_inp == 'q':
            break
        proc2 = multiprocessing.Process(target=DoAc, args=(int(check_inp),))
        proc2.start()
        proc2.join()
    proc1.join()

