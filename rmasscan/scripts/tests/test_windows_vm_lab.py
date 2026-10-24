import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("wvl", os.path.join(HERE, "..", "windows-vm-lab.py"))
wvl = importlib.util.module_from_spec(_s)
_s.loader.exec_module(wvl)

D = wvl.derive("t1")


class FakeHost:
    """In-memory host: ENO1 is the user's real LAN and must never change."""

    def __init__(self):
        self.l = {"eno1": dict(kind="", master=None, alias="", physical=True, mac="c8:7f:54:6c:e4:33",
                               addrs=["192.168.1.148/24"])}
        self.ns = set()
        self.rt = ["192.168.1.0/24"]
        self.deleted = []
        self.rogue = None  # callable run after bridge creation (simulates a physical uplink)

    def links(self):
        return {k: dict(v) for k, v in self.l.items()}

    def routes(self):
        return list(self.rt)

    def netns_list(self):
        return set(self.ns)

    def _add(self, n, kind, alias, mac=""):
        self.l[n] = dict(kind=kind, master=None, alias=alias, physical=False, mac=mac, addrs=[])

    def create_bridge(self, n, alias):
        self._add(n, "bridge", alias)
        if self.rogue:
            self.rogue(self)

    def create_tap(self, n, alias, user):
        self._add(n, "tun", alias)

    def create_veth(self, h, p, ns, alias, hm, pm):
        self._add(h, "veth", alias, hm)

    def enslave(self, n, br):
        self.l[n]["master"] = br

    def netns_add(self, ns):
        self.ns.add(ns)

    def peer_config(self, ns, ifn, ip):
        pass

    def link_del(self, n):
        self.deleted.append(n)
        del self.l[n]

    def netns_del(self, ns):
        self.deleted.append(ns)
        self.ns.discard(ns)


def run(host, cmd, d=tempfile.gettempdir(), name="m.json", extra=()):
    path = os.path.join(d, name)
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        rc = wvl.main([cmd, "--run-id", "t1", "--manifest", path, "--tap-user", "u"] + list(extra), host=host)
    return rc, err.getvalue()


class T(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.h = FakeHost()
        self.eno1 = dict(self.h.l["eno1"])

    def r(self, cmd, **k):
        return run(self.h, cmd, d=self.td.name, **k)

    def test_names_fit_ifnamsiz_and_macs_unique(self):
        d = wvl.derive("abcdefgh")
        self.assertTrue(all(len(d[k]) <= 15 for k in ("bridge", "tap", "veth_host", "peer_if")))
        self.assertNotEqual(wvl.derive("a")["windows_mac"], wvl.derive("b")["windows_mac"])
        with self.assertRaises(wvl.LabError):
            wvl.derive("../x")

    def _busy(self, setup):
        setup()
        before = (self.h.links(), set(self.h.ns))
        rc, err = self.r("up")
        self.assertEqual(rc, 3, err)
        self.assertIn("busy", err)
        self.assertEqual((self.h.links(), set(self.h.ns)), before)  # nothing created
        self.assertEqual(self.h.deleted, [])                        # nothing removed
        self.assertFalse(os.path.exists(os.path.join(self.td.name, "m.json")))

    def test_busy_bridge_name(self):
        self._busy(lambda: self.h._add(D["bridge"], "bridge", ""))

    def test_busy_tap_name(self):
        self._busy(lambda: self.h._add(D["tap"], "tun", ""))

    def test_busy_netns_name(self):
        self._busy(lambda: self.h.ns.add(D["netns"]))

    def test_address_conflict_refused(self):
        self.h.rt.append("198.18.0.0/24")
        self.assertEqual(self.r("plan")[0], 3)

    def test_plan_changes_nothing(self):
        before = self.h.links()
        self.assertEqual(self.r("plan")[0], 0)
        self.assertEqual(self.h.links(), before)
        self.assertFalse(self.h.ns)

    def test_foreign_ownership_not_deleted_by_down(self):
        self.assertEqual(self.r("up")[0], 0)
        self.h.l[D["tap"]]["alias"] = "someone-else"
        rc, err = self.r("down")
        self.assertEqual(rc, 5)
        self.assertIn(D["tap"], self.h.l)            # foreign object kept
        self.assertNotIn(D["tap"], self.h.deleted)
        self.assertNotIn(D["bridge"], self.h.l)      # own objects removed
        self.assertEqual(self.h.l["eno1"], self.eno1)

    def test_physical_uplink_rejected_and_rolled_back(self):
        def rogue(h):
            h.l["eno1"]["master"] = D["bridge"]
        self.h.rogue = rogue
        rc, err = self.r("up")
        self.assertEqual(rc, 4)
        self.assertIn("physical uplink eno1", err)
        self.assertNotIn(D["bridge"], self.h.l)
        self.assertIn("eno1", self.h.l)
        self.assertNotIn("eno1", self.h.deleted)
        self.assertFalse(self.h.ns)

    def test_status_flags_uplink(self):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.r("status")[0], 0)
        self.h.l["eno1"]["master"] = D["bridge"]
        self.assertEqual(self.r("status")[0], 1)

    def test_ambiguous_nic(self):
        ad = [{"MacAddress": "52-54-00-AA-BB-CC", "InterfaceGuid": "{1}"},
              {"MacAddress": "52-54-00-aa-bb-cc", "InterfaceGuid": "{2}"}]
        with self.assertRaises(wvl.LabError):
            wvl.select_adapter(ad, "52:54:00:aa:bb:cc")
        with self.assertRaises(wvl.LabError):
            wvl.select_adapter(ad[:1], "52:54:00:00:00:01")
        self.assertEqual(wvl.select_adapter(ad[:1], "52:54:00:aa:bb:cc")["InterfaceGuid"], "{1}")

    def test_repeated_down_is_noop(self):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.r("down")[0], 0)
        n = len(self.h.deleted)
        self.assertEqual(self.r("down")[0], 0)
        self.assertEqual(len(self.h.deleted), n)
        self.assertEqual(self.h.l.keys(), {"eno1"})
        self.assertFalse(self.h.ns)

    def test_down_without_manifest_is_noop(self):
        self.h._add(D["bridge"], "bridge", D["alias"])  # not recorded -> not ours to delete
        self.assertEqual(self.r("down")[0], 0)
        self.assertIn(D["bridge"], self.h.l)

    def test_incomplete_up_refused_then_down_cleans_own_only(self):
        # simulate crash: manifest 'creating' with bridge + tap recorded, tap created, netns of someone else
        m = {"run_id": "t1", "state": "creating", "names": D,
             "created": [{"kind": "link", "name": D["bridge"]}, {"kind": "link", "name": D["tap"]}]}
        self.h._add(D["bridge"], "bridge", D["alias"])
        self.h._add(D["tap"], "tun", D["alias"])
        self.h.ns.add("foreign-ns")
        wvl.write_manifest(os.path.join(self.td.name, "m.json"), m)
        rc, err = self.r("up")
        self.assertEqual(rc, 3)
        self.assertIn("state=creating", err)
        self.assertEqual(self.r("status")[0], 1)
        self.assertEqual(self.r("down")[0], 0)
        self.assertEqual(self.h.l.keys(), {"eno1"})
        self.assertIn("foreign-ns", self.h.ns)

    def test_reup_after_clean_down(self):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.r("down")[0], 0)
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.r("status")[0], 0)

    def test_up_status_down_roundtrip(self):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.r("status")[0], 0)
        with open(os.path.join(self.td.name, "m.json")) as f:
            m = json.load(f)
        self.assertEqual(m["state"], "up")
        self.assertEqual(m["lab"]["windows_ip"], "198.18.0.1")
        self.assertIsNone(m["lab"]["gateway"])
        self.assertEqual(self.h.l["eno1"], self.eno1)
        self.assertEqual(self.r("down")[0], 0)

    def test_ps1_is_guarded(self):
        s = open(os.path.join(HERE, "..", "windows-vm-lab.ps1")).read()
        for needle in ("Inventory", "Configure", "Verify", "ambiguous", "DefaultGateway"):
            self.assertIn(needle, s)


if __name__ == "__main__":
    unittest.main()
