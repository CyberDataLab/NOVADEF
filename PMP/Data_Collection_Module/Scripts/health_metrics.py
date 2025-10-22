#!/usr/bin/env python3
import psutil

def main():
    # “Warm up” the CPU measurement using the value of the second call because it may give errors in the first call.
    psutil.cpu_percent(interval=None)  
    cpu_usage = psutil.cpu_percent(interval=1)  
    mem_info = psutil.virtual_memory().available / (1024*1024)  # in MB
    print(f'{{"cpu_usage":{cpu_usage},"memory_mb":{mem_info}}}')

if __name__ == "__main__":
    main()
