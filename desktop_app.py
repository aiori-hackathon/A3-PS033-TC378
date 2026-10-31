"""DiagDiscover Windows application; owns a private local backend per window."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
import traceback

import webview

from dashboard import DemoServer
from logging_config import configure_logging


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke-test", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    configure_logging()
    server = DemoServer(("127.0.0.1", 0))
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    loaded = threading.Event()
    report = {"passed": False}
    webview.settings["ALLOW_DOWNLOADS"] = True
    webview.settings["ALLOW_FILE_URLS"] = False
    window = webview.create_window("DiagDiscover | AIORI-3 · PS-033",
        f"http://127.0.0.1:{server.server_port}/", width=1400, height=960,
        min_size=(900, 650), background_color="#2c2824", text_select=True,
        hidden=bool(args.smoke_test))
    window.events.loaded += loaded.set

    def smoke_test():
        try:
            if not loaded.wait(30):
                raise RuntimeError("Native WebView did not load in time")
            def wait_for(expression, timeout=20):
                until = time.monotonic()+timeout
                while time.monotonic() < until:
                    if window.evaluate_js(expression):
                        return
                    time.sleep(.1)
                raise RuntimeError(f"Native UI check timed out: {expression}")

            wait_for("document.getElementById('run') && !document.getElementById('run').disabled")
            report["title"] = window.evaluate_js("document.title")
            assert report["title"] == "DiagDiscover · Discovery Lab"
            assert window.evaluate_js("!document.getElementById('welcome').hidden")
            window.evaluate_js("location.hash='#lab'; document.getElementById('run').click(); true")
            wait_for("!document.getElementById('run').disabled")
            report["success"] = window.evaluate_js("document.getElementById('notice').textContent")
            assert "3 of 3" in report["success"], report
            assert window.evaluate_js("document.querySelectorAll('#trace .passed').length") == 6
            window.evaluate_js("document.querySelectorAll('#services .service')[2].click(); true")
            report["live_health"] = window.evaluate_js("JSON.parse(document.getElementById('evidence-output').textContent).data")
            assert report["live_health"]["mock"] is False
            assert report["live_health"]["result"]["memory_total_bytes"] > 0
            window.evaluate_js("document.getElementById('browse-services').click(); true")
            wait_for("!document.getElementById('browse-services').disabled")
            report["inventory"] = window.evaluate_js("JSON.parse(document.getElementById('inventory-evidence-output').textContent).inventory")
            assert report["inventory"]["status"] == "VERIFIED"
            assert len(report["inventory"]["entries"]) == 3
            assert report["inventory"]["invocation_attempted"] is False
            window.evaluate_js("document.getElementById('scenario').value='bogus'; document.getElementById('run').click(); true")
            wait_for("!document.getElementById('run').disabled")
            report["tampered"] = window.evaluate_js("document.getElementById('notice').textContent")
            assert "Expected failure" in report["tampered"], report
            assert window.evaluate_js("document.querySelectorAll('#trace .not_run').length") == 5
            report["passed"] = True
        except Exception:
            report["error"] = traceback.format_exc()
        finally:
            args.smoke_test.parent.mkdir(parents=True, exist_ok=True)
            args.smoke_test.write_text(json.dumps(report, indent=2), encoding="utf-8")
            window.destroy()

    try:
        icon = Path(__file__).parent / "assets" / "app.ico"
        webview.start(smoke_test if args.smoke_test else None, gui="edgechromium",
            private_mode=True, icon=str(icon) if icon.exists() else None)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=3)
    if args.smoke_test and not report["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        error = traceback.format_exc()
        log_dir = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "DiagDiscover"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "startup-error.log").write_text(error, encoding="utf-8")
        if "--smoke-test" in sys.argv:
            index = sys.argv.index("--smoke-test")
            Path(sys.argv[index+1]).write_text(json.dumps({"passed":False,"error":error}), encoding="utf-8")
        else:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0,
                "DiagDiscover could not start. Check that Microsoft Edge WebView2 Runtime is installed.\n"
                f"Details: {log_dir / 'startup-error.log'}", "DiagDiscover", 16)
        sys.exit(1)
