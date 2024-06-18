import subprocess
import time

if __name__ == "__main__":
    s1 = subprocess.Popen('python3 mycontroller.py 0 127.0.0.1:50051'.split())
    try:
        s1.wait()
    except KeyboardInterrupt:
        s1.terminate()