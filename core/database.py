"""core.database — lightweight SQLite manager with background writer.

Provides DatabaseManager for fast, non-blocking writes of packets and alerts.
Designed to be safe for high-throughput capture: uses a worker thread and
batched commits with WAL journaling to avoid blocking the UI thread.
"""
from pathlib import Path
import sqlite3
import threading
import queue
import json
import time

DB_PATH = Path("sentinel_data.db")


class DatabaseManager:
    def __init__(self, path: Path = DB_PATH, batch_size: int = 100, flush_interval: float = 0.5):
        self.path = Path(path)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._q = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True, name="db_writer")
        self._conn = None
        self._ensure_db()
        self._thread.start()

    def _ensure_db(self):
        first = not self.path.exists()
        # allow concurrent access; check_same_thread=False for background writer
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        # enable WAL for concurrent readers/writers
        try:
            self._conn.execute('PRAGMA journal_mode=WAL;')
            self._conn.execute('PRAGMA synchronous=NORMAL;')
        except Exception:
            pass
        if first:
            cur = self._conn.cursor()
            cur.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                src TEXT,
                dst TEXT,
                proto TEXT,
                app TEXT,
                size INTEGER,
                status TEXT,
                threats TEXT,
                vendor TEXT,
                pkt TEXT
            )''')
            cur.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                type TEXT,
                actor TEXT,
                severity TEXT,
                size INTEGER
            )''')
            self._conn.commit()

    # public API
    def insert_packet(self, pkt_rec: dict):
        """Queue a packet record for async insert. pkt_rec keys: time, src, dst, proto, app, size, status, threats(list), vendor, pkt
        """
        try:
            self._q.put_nowait(("pkt", pkt_rec))
        except queue.Full:
            # drop when queue full — keep app responsive
            return False
        return True

    def insert_alert(self, alert: dict):
        try:
            self._q.put_nowait(("alert", alert))
        except queue.Full:
            return False
        return True

    def query_recent_packets(self, limit: int = 200):
        cur = self._conn.cursor()
        cur.execute('SELECT ts,src,dst,proto,app,size,status,threats,vendor FROM packets ORDER BY id DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        return rows

    def query_alerts(self, limit: int = 200):
        cur = self._conn.cursor()
        cur.execute('SELECT ts,type,actor,severity,size FROM alerts ORDER BY id DESC LIMIT ?', (limit,))
        return cur.fetchall()

    def close(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)
        try:
            if self._conn:
                self._conn.close()
        except Exception:
            pass

    # internal worker
    def _worker(self):
        buffer = []
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                item = None
                try:
                    item = self._q.get(timeout=self.flush_interval)
                except queue.Empty:
                    pass
                if item:
                    buffer.append(item)
                # flush based on size or interval
                if (len(buffer) >= self.batch_size) or (time.time() - last_flush >= self.flush_interval and buffer):
                    self._flush(buffer)
                    buffer.clear()
                    last_flush = time.time()
            except Exception:
                # swallow exceptions to keep worker alive
                try:
                    time.sleep(0.1)
                except Exception:
                    pass
        # final flush
        if buffer:
            try:
                self._flush(buffer)
            except Exception:
                pass

    def _flush(self, items):
        cur = self._conn.cursor()
        try:
            cur.execute('BEGIN')
            for typ, payload in items:
                if typ == 'pkt':
                    p = payload
                    cur.execute('''INSERT INTO packets(ts,src,dst,proto,app,size,status,threats,vendor,pkt)
                                   VALUES(?,?,?,?,?,?,?,?,?,?)''', (
                        p.get('time'), p.get('src'), p.get('dst'), p.get('proto'), p.get('app'), int(p.get('size') or 0),
                        p.get('status'), json.dumps(p.get('threats') or []), p.get('vendor') or None,
                        (p.get('pkt_repr') if 'pkt_repr' in p else (p.get('pkt') and repr(p.get('pkt'))))))
                elif typ == 'alert':
                    a = payload
                    cur.execute('''INSERT INTO alerts(ts,type,actor,severity,size) VALUES(?,?,?,?,?)''', (
                        a.get('time'), a.get('type'), a.get('actor'), a.get('severity'), int(a.get('size') or 0)))
            cur.execute('COMMIT')
        except Exception:
            try:
                cur.execute('ROLLBACK')
            except Exception:
                pass


# module-level singleton access
_DB_INSTANCE = None


def get_db() -> DatabaseManager:
    global _DB_INSTANCE
    if _DB_INSTANCE is None:
        try:
            _DB_INSTANCE = DatabaseManager()
        except Exception:
            _DB_INSTANCE = None
    return _DB_INSTANCE
