"""
Common utilities: logging, simple shelve cache for API responses, env loader.
"""
import os
import logging
import shelve
from contextlib import contextmanager
from dotenv import load_dotenv

load_dotenv()

LOG_LEVEL = os.getenv('THREATINTELAI_LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=LOG_LEVEL, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('ThreatIntelAI')

CACHE_DB = os.getenv('THREATINTELAI_CACHE_DB', 'cache/enrich_cache.db')
USE_CACHE = os.getenv('THREATINTELAI_USE_CACHE', '1') == '1'

@contextmanager
def open_cache(writeback=False):
    """
    Context manager that yields a shelve DB-like object when caching enabled,
    otherwise yields a minimal no-op dict-like object.
    """
    if not USE_CACHE:
        class _NoCache:
            def __getitem__(self, key): raise KeyError
            def __setitem__(self, key, value): pass
            def get(self, k, default=None): return default
            def close(self): pass
        yield _NoCache()
    else:
        os.makedirs(os.path.dirname(CACHE_DB) or '.', exist_ok=True)
        with shelve.open(CACHE_DB, writeback=writeback) as db:
            yield db
