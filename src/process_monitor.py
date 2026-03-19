import psutil
import time
import pandas as pd
from datetime import datetime
import os
import subprocess
import cgroups

# Resolve absolute path to the logs directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_PATH = os.path.join(BASE_DIR, "logs", "system_log.csv")

def run_isolated_process(command, cpu_quota=None, memory_limit=None):
    """
    Run a command in an isolated environment using namespaces and cgroups.
    cpu_quota: CPU quota in microseconds per period (default period 100000us, so 50000 = 50%)
    memory_limit: Memory limit in bytes
    """
    def preexec():
        # Create new namespaces
        os.unshare(os.CLONE_NEWPID | os.CLONE_NEWNS | os.CLONE_NEWNET | os.CLONE_NEWUTS)
        # Set up cgroups if limits provided
        if cpu_quota or memory_limit:
            cg = cgroups.Cgroup('isolated_process')
            cg.create()
            if cpu_quota:
                cg.set_cpu_period(100000)
                cg.set_cpu_quota(cpu_quota)
            if memory_limit:
                cg.set_memory_limit(memory_limit)
            cg.add(os.getpid())

    # Run the command
    proc = subprocess.Popen(command, shell=True, preexec_fn=preexec)
    return proc

def log_metrics():
    while True:
        # gather system metrics
        counters = psutil.disk_io_counters()
        net     = psutil.net_io_counters()
        data = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'num_processes': len(psutil.pids()),
            'disk_read_bytes': counters.read_bytes,
            'disk_write_bytes': counters.write_bytes,
            'net_bytes_sent': net.bytes_sent,
            'net_bytes_recv': net.bytes_recv
        }
        # append to CSV
        df = pd.DataFrame([data])
        df.to_csv(LOG_PATH,
                  mode='a',
                  header=not os.path.exists(LOG_PATH),
                  index=False)
        time.sleep(5)

if __name__ == "__main__":
    log_metrics()
