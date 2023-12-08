import time


def print_log(msg, start):
    print("[", "{:.3f}".format((time.time()-start)*1000), "ms ]",
          msg)
