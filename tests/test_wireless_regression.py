from pathlib import Path

def test_applied_wireless_state_is_loaded():
    src = (Path(__file__).resolve().parents[1] / "app.py").read_text()
    assert 'result["wireless"]' in src
    assert '"pending_changes": staged is not None' in src

def test_ap_service_health_check():
    src = (Path(__file__).resolve().parents[1] / "wireless_manager.py").read_text()
    assert "'is-active'" in src
