import datetime
import socket
from apscheduler.scheduler import Scheduler


class MutexScheduler(Scheduler):
    def __init__(self, gconfig={}, **options):
        Scheduler.__init__(self, gconfig, **options)
        self.ip = socket.gethostbyname(socket.gethostname())

    def mutex(self, lock=None, heartbeat=None, lock_else=None,
              unactive_interval=datetime.timedelta(seconds=5)):

        def mutex_func_gen(func):
            def mtx_func():
                if lock:
                    lock_rec = lock()
                    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    now = datetime.datetime.strptime(now, "%Y-%m-%d %H:%M:%S")
                    # execute mutex job when the server is active, or the other server is timeout.
                    if not lock_rec or lock_rec['active_ip'] == self.ip or (
                        lock_rec['update_time'] and now - lock_rec['update_time'] >= unactive_interval):
                        heartbeat(self.ip, now)
                        if not lock_rec:
                            lock_rec = {}
                        func(**lock_rec)
                    else:
                        lock_else(lock_rec)
                else:
                    func()

            return mtx_func

        self.mtx_func_gen = mutex_func_gen

        def inner(func):
            return func

        return inner

    def cron_schedule(self, **options):
        def inner(func):
            if hasattr(self, 'mtx_func_gen'):
                func = self.mtx_func_gen(func)
            func.job = self.add_cron_job(func, **options)
            return func

        return inner