#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PyPKI Contributors
"""
Unit tests for service_manager.py

Covers:
  - ServiceDef lifecycle (start / stop / restart / patch_config)
  - ServiceDef state machine (stopped → starting → running → stopped)
  - ServiceDef error handling (factory exceptions, unmanaged services)
  - ServiceManager registration, individual control, bulk operations
  - ServiceManager.update_global_config (webui vs file source)
  - ServiceManager.patch_service_config
  - ServiceManager config-file watcher (start / stop)
  - _deep_merge helper
"""

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

from service_manager import (
    ServiceDef,
    ServiceManager,
    _deep_merge,
    STATE_STOPPED,
    STATE_RUNNING,
    STATE_STARTING,
    STATE_ERROR,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_factory(server=None, raises=None):
    """Return a factory callable. If raises is set, the factory raises it."""
    srv = server or MagicMock()
    srv.shutdown = MagicMock()

    def factory(**kwargs):
        if raises:
            raise raises
        return srv

    factory._server = srv
    return factory


# ---------------------------------------------------------------------------
# _deep_merge
# ---------------------------------------------------------------------------

class TestDeepMerge(unittest.TestCase):

    def test_flat_merge(self):
        base = {"a": 1, "b": 2}
        _deep_merge(base, {"b": 99, "c": 3})
        self.assertEqual(base, {"a": 1, "b": 99, "c": 3})

    def test_nested_merge(self):
        base = {"outer": {"a": 1, "b": 2}, "x": 10}
        _deep_merge(base, {"outer": {"b": 20, "c": 30}})
        self.assertEqual(base, {"outer": {"a": 1, "b": 20, "c": 30}, "x": 10})

    def test_deep_nested(self):
        base = {"l1": {"l2": {"l3": "orig"}}}
        _deep_merge(base, {"l1": {"l2": {"l3": "new", "l3b": "added"}}})
        self.assertEqual(base["l1"]["l2"], {"l3": "new", "l3b": "added"})

    def test_override_dict_with_scalar(self):
        base = {"key": {"nested": 1}}
        _deep_merge(base, {"key": "flat"})
        self.assertEqual(base["key"], "flat")

    def test_empty_override(self):
        base = {"a": 1}
        _deep_merge(base, {})
        self.assertEqual(base, {"a": 1})

    def test_adds_new_top_level_key(self):
        base = {}
        _deep_merge(base, {"new": 42})
        self.assertEqual(base["new"], 42)


# ---------------------------------------------------------------------------
# ServiceDef — initial state
# ---------------------------------------------------------------------------

class TestServiceDefInitialState(unittest.TestCase):

    def test_managed_service_starts_stopped(self):
        svc = ServiceDef("acme", "ACME", _mock_factory(), {}, enabled=False)
        self.assertEqual(svc.state, STATE_STOPPED)
        self.assertFalse(svc.is_running)
        self.assertIsNone(svc.error)

    def test_unmanaged_enabled_service_starts_running(self):
        svc = ServiceDef("cmp", "CMP", None, {}, enabled=True)
        self.assertEqual(svc.state, STATE_RUNNING)
        self.assertTrue(svc.is_running)

    def test_unmanaged_disabled_service_starts_stopped(self):
        svc = ServiceDef("cmp", "CMP", None, {}, enabled=False)
        self.assertEqual(svc.state, STATE_STOPPED)

    def test_status_dict_keys(self):
        svc = ServiceDef("acme", "ACME Server", _mock_factory(), {"port": 8080})
        d = svc.status_dict()
        for key in ("name", "label", "state", "enabled", "error", "config", "unmanaged"):
            self.assertIn(key, d)
        self.assertEqual(d["name"], "acme")
        self.assertEqual(d["label"], "ACME Server")
        self.assertFalse(d["unmanaged"])
        self.assertEqual(d["config"]["port"], 8080)

    def test_status_dict_config_is_deep_copy(self):
        config = {"port": 8080}
        svc = ServiceDef("acme", "ACME", _mock_factory(), config)
        d = svc.status_dict()
        d["config"]["port"] = 9999
        self.assertEqual(svc.config["port"], 8080)  # original unchanged


# ---------------------------------------------------------------------------
# ServiceDef — start
# ---------------------------------------------------------------------------

class TestServiceDefStart(unittest.TestCase):

    def test_start_success(self):
        factory = _mock_factory()
        svc = ServiceDef("acme", "ACME", factory, {"port": 8080}, enabled=False)
        result = svc.start()
        self.assertTrue(result)
        self.assertEqual(svc.state, STATE_RUNNING)
        self.assertTrue(svc.is_running)
        self.assertTrue(svc.enabled)
        self.assertIsNone(svc.error)

    def test_start_idempotent_when_already_running(self):
        factory = _mock_factory()
        svc = ServiceDef("acme", "ACME", factory, {}, enabled=False)
        svc.start()
        result = svc.start()  # second start
        self.assertTrue(result)
        self.assertEqual(svc.state, STATE_RUNNING)

    def test_start_factory_called_with_config(self):
        mock_factory = MagicMock(return_value=MagicMock())
        svc = ServiceDef("acme", "ACME", mock_factory, {"port": 8080, "host": "0.0.0.0"})
        svc.start()
        mock_factory.assert_called_once_with(port=8080, host="0.0.0.0")

    def test_start_factory_exception_sets_error_state(self):
        factory = _mock_factory(raises=RuntimeError("port in use"))
        svc = ServiceDef("acme", "ACME", factory, {})
        result = svc.start()
        self.assertFalse(result)
        self.assertEqual(svc.state, STATE_ERROR)
        self.assertIn("port in use", svc.error)
        self.assertFalse(svc.is_running)

    def test_start_unmanaged_service_fails(self):
        svc = ServiceDef("cmp", "CMP", None, {}, enabled=True)
        # Reset to stopped to test the path
        svc._state = STATE_STOPPED
        result = svc.start()
        self.assertFalse(result)
        self.assertEqual(svc.state, STATE_ERROR)
        self.assertIn("cannot be started", svc.error)


# ---------------------------------------------------------------------------
# ServiceDef — stop
# ---------------------------------------------------------------------------

class TestServiceDefStop(unittest.TestCase):

    def test_stop_running_service(self):
        factory = _mock_factory()
        svc = ServiceDef("acme", "ACME", factory, {})
        svc.start()
        srv = factory._server
        result = svc.stop()
        self.assertTrue(result)
        self.assertEqual(svc.state, STATE_STOPPED)
        self.assertFalse(svc.enabled)
        srv.shutdown.assert_called_once()

    def test_stop_already_stopped_returns_true(self):
        svc = ServiceDef("acme", "ACME", _mock_factory(), {})
        result = svc.stop()
        self.assertTrue(result)
        self.assertEqual(svc.state, STATE_STOPPED)

    def test_stop_unmanaged_service_fails(self):
        svc = ServiceDef("cmp", "CMP", None, {}, enabled=True)
        result = svc.stop()
        self.assertFalse(result)
        self.assertIn("cannot be stopped", svc.error)

    def test_stop_handles_shutdown_exception_gracefully(self):
        srv = MagicMock()
        srv.shutdown.side_effect = Exception("crash on shutdown")
        factory = MagicMock(return_value=srv)
        svc = ServiceDef("acme", "ACME", factory, {})
        svc.start()
        # Should not raise
        result = svc.stop()
        self.assertTrue(result)
        self.assertEqual(svc.state, STATE_STOPPED)

    def test_stop_error_state_service(self):
        factory = _mock_factory(raises=RuntimeError("fail"))
        svc = ServiceDef("acme", "ACME", factory, {})
        svc.start()  # puts it in ERROR
        result = svc.stop()
        self.assertTrue(result)
        self.assertEqual(svc.state, STATE_STOPPED)


# ---------------------------------------------------------------------------
# ServiceDef — restart
# ---------------------------------------------------------------------------

class TestServiceDefRestart(unittest.TestCase):

    def test_restart_running_service(self):
        call_count = {"n": 0}
        servers = [MagicMock(), MagicMock()]
        servers[0].shutdown = MagicMock()
        servers[1].shutdown = MagicMock()

        def factory(**kwargs):
            srv = servers[call_count["n"]]
            call_count["n"] += 1
            return srv

        svc = ServiceDef("acme", "ACME", factory, {})
        svc.start()
        result = svc.restart()
        self.assertTrue(result)
        self.assertEqual(svc.state, STATE_RUNNING)
        servers[0].shutdown.assert_called_once()
        self.assertEqual(call_count["n"], 2)

    def test_restart_unmanaged_returns_false(self):
        svc = ServiceDef("cmp", "CMP", None, {}, enabled=True)
        result = svc.restart()
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# ServiceDef — patch_config
# ---------------------------------------------------------------------------

class TestServiceDefPatchConfig(unittest.TestCase):

    def test_patch_config_merges_and_restarts(self):
        started = {"n": 0}

        def factory(**kwargs):
            started["n"] += 1
            return MagicMock()

        svc = ServiceDef("acme", "ACME", factory, {"port": 8080, "host": "0.0.0.0"})
        svc.start()
        svc.patch_config({"port": 9090})
        self.assertEqual(svc.config["port"], 9090)
        self.assertEqual(svc.config["host"], "0.0.0.0")  # unchanged key preserved
        self.assertEqual(started["n"], 2)  # start + restart

    def test_patch_config_nested_merge(self):
        def factory(**kwargs):
            return MagicMock()

        svc = ServiceDef("est", "EST", factory, {"tls": {"cert": "old.pem", "key": "old.key"}})
        svc.patch_config({"tls": {"cert": "new.pem"}})
        self.assertEqual(svc.config["tls"]["cert"], "new.pem")
        self.assertEqual(svc.config["tls"]["key"], "old.key")


# ---------------------------------------------------------------------------
# ServiceManager — registration and lookup
# ---------------------------------------------------------------------------

class TestServiceManagerRegistration(unittest.TestCase):

    def setUp(self):
        self.sm = ServiceManager()

    def test_register_and_get(self):
        svc = self.sm.register("acme", "ACME", _mock_factory(), {"port": 8080})
        self.assertIsNotNone(svc)
        self.assertIs(self.sm.get("acme"), svc)

    def test_get_unknown_returns_none(self):
        self.assertIsNone(self.sm.get("nonexistent"))

    def test_register_overwrites_existing(self):
        self.sm.register("acme", "ACME v1", _mock_factory(), {})
        svc2 = self.sm.register("acme", "ACME v2", _mock_factory(), {})
        self.assertEqual(self.sm.get("acme").label, "ACME v2")

    def test_status_all_returns_all_services(self):
        self.sm.register("acme", "ACME", _mock_factory(), {})
        self.sm.register("scep", "SCEP", _mock_factory(), {})
        statuses = self.sm.status_all()
        self.assertIn("acme", statuses)
        self.assertIn("scep", statuses)

    def test_status_one_known(self):
        self.sm.register("acme", "ACME", _mock_factory(), {"port": 8080})
        s = self.sm.status_one("acme")
        self.assertIsNotNone(s)
        self.assertEqual(s["name"], "acme")

    def test_status_one_unknown_returns_none(self):
        self.assertIsNone(self.sm.status_one("ghost"))


# ---------------------------------------------------------------------------
# ServiceManager — individual control
# ---------------------------------------------------------------------------

class TestServiceManagerIndividualControl(unittest.TestCase):

    def setUp(self):
        self.sm = ServiceManager()
        self.sm.register("acme", "ACME", _mock_factory(), {})

    def test_start_known_service(self):
        ok, msg = self.sm.start("acme")
        self.assertTrue(ok)
        self.assertEqual(msg, "")

    def test_start_unknown_service(self):
        ok, msg = self.sm.start("ghost")
        self.assertFalse(ok)
        self.assertIn("Unknown service", msg)

    def test_stop_known_service(self):
        self.sm.start("acme")
        ok, msg = self.sm.stop("acme")
        self.assertTrue(ok)

    def test_stop_unknown_service(self):
        ok, msg = self.sm.stop("ghost")
        self.assertFalse(ok)
        self.assertIn("Unknown service", msg)

    def test_restart_known_service(self):
        self.sm.start("acme")
        ok, msg = self.sm.restart("acme")
        self.assertTrue(ok)

    def test_restart_unknown_service(self):
        ok, msg = self.sm.restart("ghost")
        self.assertFalse(ok)
        self.assertIn("Unknown service", msg)

    def test_start_returns_error_message_on_failure(self):
        self.sm.register("bad", "Bad", _mock_factory(raises=RuntimeError("boom")), {})
        ok, msg = self.sm.start("bad")
        self.assertFalse(ok)
        self.assertIn("boom", msg)


# ---------------------------------------------------------------------------
# ServiceManager — bulk operations
# ---------------------------------------------------------------------------

class TestServiceManagerBulkOps(unittest.TestCase):

    def _make_sm(self):
        sm = ServiceManager()
        sm.register("acme", "ACME", _mock_factory(), {}, enabled=True)
        sm.register("scep", "SCEP", _mock_factory(), {}, enabled=True)
        sm.register("cmp",  "CMP",  None,            {}, enabled=True)  # unmanaged
        sm.register("est",  "EST",  _mock_factory(), {}, enabled=False)  # disabled
        return sm

    def test_start_all_enabled_starts_only_enabled_managed(self):
        sm = self._make_sm()
        sm.start_all_enabled()
        self.assertTrue(sm.get("acme").is_running)
        self.assertTrue(sm.get("scep").is_running)
        self.assertFalse(sm.get("est").is_running)   # disabled
        # CMP is unmanaged but enabled — state set at init
        self.assertTrue(sm.get("cmp").is_running)

    def test_stop_all_stops_running_managed(self):
        sm = self._make_sm()
        sm.start_all_enabled()
        sm.stop_all()
        self.assertFalse(sm.get("acme").is_running)
        self.assertFalse(sm.get("scep").is_running)

    def test_restart_all(self):
        call_counts = {"acme": 0, "scep": 0}

        def make_factory(name):
            def factory(**kwargs):
                call_counts[name] += 1
                return MagicMock()
            return factory

        sm = ServiceManager()
        sm.register("acme", "ACME", make_factory("acme"), {}, enabled=True)
        sm.register("scep", "SCEP", make_factory("scep"), {}, enabled=True)
        sm.start_all_enabled()
        sm.restart_all()
        self.assertEqual(call_counts["acme"], 2)
        self.assertEqual(call_counts["scep"], 2)


# ---------------------------------------------------------------------------
# ServiceManager — config management
# ---------------------------------------------------------------------------

class TestServiceManagerConfigManagement(unittest.TestCase):

    def _make_sm_with_acme(self, enabled=True):
        sm = ServiceManager()
        sm.register("acme", "ACME", _mock_factory(), {"port": 8080}, enabled=enabled)
        if enabled:
            sm.start("acme")
        return sm

    def test_patch_service_config_known(self):
        sm = self._make_sm_with_acme()
        ok, msg = sm.patch_service_config("acme", {"port": 9090})
        self.assertTrue(ok)
        self.assertEqual(sm.get("acme").config["port"], 9090)

    def test_patch_service_config_unknown(self):
        sm = self._make_sm_with_acme()
        ok, msg = sm.patch_service_config("ghost", {"port": 9090})
        self.assertFalse(ok)
        self.assertIn("Unknown service", msg)

    def test_update_global_config_known_key_restarts_only_affected(self):
        restarted = []

        def make_factory(name):
            def factory(**kwargs):
                restarted.append(name)
                return MagicMock()
            return factory

        sm = ServiceManager()
        sm.register("acme", "ACME", make_factory("acme"), {}, enabled=True)
        sm.register("scep", "SCEP", make_factory("scep"), {}, enabled=True)
        sm.start_all_enabled()
        restarted.clear()

        sm.update_global_config({"acme": {"port": 9090}}, source="webui")
        self.assertIn("acme", restarted)
        self.assertNotIn("scep", restarted)

    def test_update_global_config_unknown_key_restarts_all(self):
        restarted = []

        def make_factory(name):
            def factory(**kwargs):
                restarted.append(name)
                return MagicMock()
            return factory

        sm = ServiceManager()
        sm.register("acme", "ACME", make_factory("acme"), {}, enabled=True)
        sm.register("scep", "SCEP", make_factory("scep"), {}, enabled=True)
        sm.start_all_enabled()
        restarted.clear()

        sm.update_global_config({"mystery_key": "value"}, source="webui")
        self.assertIn("acme", restarted)
        self.assertIn("scep", restarted)

    def test_update_global_config_file_source_restarts_all(self):
        restarted = []

        def make_factory(name):
            def factory(**kwargs):
                restarted.append(name)
                return MagicMock()
            return factory

        sm = ServiceManager()
        sm.register("acme", "ACME", make_factory("acme"), {}, enabled=True)
        sm.register("scep", "SCEP", make_factory("scep"), {}, enabled=True)
        sm.start_all_enabled()
        restarted.clear()

        sm.update_global_config({}, source="file")
        self.assertIn("acme", restarted)
        self.assertIn("scep", restarted)

    def test_update_global_config_validity_key_no_restart(self):
        restarted = []

        def factory(**kwargs):
            restarted.append("acme")
            return MagicMock()

        sm = ServiceManager()
        sm.register("acme", "ACME", factory, {}, enabled=True)
        sm.start("acme")
        restarted.clear()

        result = sm.update_global_config({"validity": {"days": 365}}, source="webui")
        # "validity" maps to [] — no services should restart
        self.assertEqual(result, [])
        self.assertEqual(restarted, [])


# ---------------------------------------------------------------------------
# ServiceManager — config file watcher
# ---------------------------------------------------------------------------

class TestServiceManagerConfigWatcher(unittest.TestCase):

    def test_watcher_detects_file_change_and_restarts(self):
        restarted = threading.Event()

        def factory(**kwargs):
            restarted.set()
            return MagicMock()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            config_path = Path(f.name)
            f.write(b"{}")

        try:
            sm = ServiceManager(config_path=config_path)
            sm.register("acme", "ACME", factory, {}, enabled=True)
            sm.start("acme")
            restarted.clear()

            sm.start_config_watcher(poll_interval=0.1)

            # Touch the file to change its mtime
            time.sleep(0.05)
            config_path.write_text('{"changed": true}')

            triggered = restarted.wait(timeout=2.0)
            sm.stop_config_watcher()
            self.assertTrue(triggered, "Config watcher did not trigger restart after file change")
        finally:
            config_path.unlink(missing_ok=True)

    def test_watcher_no_config_path_is_noop(self):
        sm = ServiceManager(config_path=None)
        sm.start_config_watcher()
        self.assertIsNone(sm._watcher_thread)

    def test_watcher_not_started_twice(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            config_path = Path(f.name)
            f.write(b"{}")
        try:
            sm = ServiceManager(config_path=config_path)
            sm.start_config_watcher(poll_interval=0.5)
            first_thread = sm._watcher_thread
            sm.start_config_watcher(poll_interval=0.5)
            self.assertIs(sm._watcher_thread, first_thread)
            sm.stop_config_watcher()
        finally:
            config_path.unlink(missing_ok=True)

    def test_stop_watcher_signals_thread_to_stop(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            config_path = Path(f.name)
            f.write(b"{}")
        try:
            sm = ServiceManager(config_path=config_path)
            sm.start_config_watcher(poll_interval=0.05)
            sm.stop_config_watcher()
            # Give thread time to see the stop signal
            time.sleep(0.2)
            self.assertTrue(sm._stop_watcher.is_set())
        finally:
            config_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Thread safety — concurrent start/stop
# ---------------------------------------------------------------------------

class TestServiceDefThreadSafety(unittest.TestCase):

    def test_concurrent_starts_end_in_running(self):
        """Multiple concurrent starts must leave the service in RUNNING state."""
        def factory(**kwargs):
            time.sleep(0.01)
            return MagicMock()

        svc = ServiceDef("acme", "ACME", factory, {})
        threads = [threading.Thread(target=svc.start) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(svc.state, STATE_RUNNING)


if __name__ == "__main__":
    unittest.main()
