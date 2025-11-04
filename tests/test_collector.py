from ioc_collector import collect_from_file
import pathlib

def test_collect_sample(tmp_path):
    p = tmp_path / "sample.txt"
    p.write_text("1.2.3.4\nexample.com\n")
    recs = collect_from_file(str(p))
    assert any(r['ioc'] == '1.2.3.4' for r in recs)
    assert any(r['ioc'] == 'example.com' for r in recs)
