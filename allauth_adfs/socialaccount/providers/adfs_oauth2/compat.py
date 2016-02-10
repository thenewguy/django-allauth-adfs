from django.core.cache import DEFAULT_CACHE_ALIAS
try:
    from django.core.cache import caches
except ImportError:
    from django.core.cache import get_cache
    
    class CacheFallback(object):
        def __getitem__(self, alias):
            return get_cache(alias)
    
    caches = CacheFallback()