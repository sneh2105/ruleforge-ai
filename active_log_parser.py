"""
Active Log Parser
Continuously parses incoming logs and maintains a sliding window per source
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta


class ActiveLogParser:
    def __init__(self, window_seconds=120, max_logs=50):
        self.window = timedelta(seconds=window_seconds)
        self.buffers = defaultdict(
            lambda: deque(maxlen=max_logs)
        )

    def add_log(self, log_line, source):
        now = datetime.now()
        self.buffers[source].append((now, log_line))

    def get_window(self, source):
        now = datetime.now()
        window_logs = []

        for ts, log in list(self.buffers[source]):
            if now - ts <= self.window:
                window_logs.append(log)

        return window_logs

    def get_event_rate(self, source):
        return len(self.get_window(source))

    def get_duration(self, source):
        logs = self.buffers[source]
        if len(logs) < 2:
            return 0
        return (logs[-1][0] - logs[0][0]).seconds
