import os
from ioc_enricher import enrich_batch

def test_enrich_minimal():
    recs = [{"ioc":"1.2.3.4","type":"ip"}]
    out = enrich_batch(recs)
    assert isinstance(out, list)
    assert 'ioc' in out[0]
