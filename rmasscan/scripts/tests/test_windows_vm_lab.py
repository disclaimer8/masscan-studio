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
TOK = "tok-A"


class FakeHost:
    """In-memory host: eno1 is the user's real LAN and must never change."""

    def __init__(self):
        self.l = {"eno1": dict(kind="", master=None, alias="", physical=True, mac="c8:7f:54:6c:e4:33",
                               addrs=["192.168.1.148/24"], noarp=False, lower_up=True, vlan_filtering=False)}
        self.ns = set()
        self.marks = {}
        self.rt = ["192.168.1.0/24"]
        self.sc = {"net.ipv4.ip_forward": "0"}
        self.self_vlans = {}
        self.fw = []
        self.deleted = []
        self.rogue = None
        self.vm = {"pid": None, "cmdline_ok": False, "fd_iff": False, "start": 0}

    def links(self):
        return {k: dict(v) for k, v in self.l.items()}

    def routes(self):
        return list(self.rt)

    def netns_list(self):
        return set(self.ns)

    def sysctl(self, k):
        return self.sc.get(k)

    def bridge_self_vlans(self, br):
        return list(self.self_vlans.get(br, []))

    def fw_refs(self, names):
        return [r for r in self.fw if any(n in r for n in names)]

    def netns_mark_read(self, ns):
        return self.marks.get(ns)

    def netns_mark_write(self, ns, tok):
        if ns in self.marks:
            raise wvl.LabError("marker exists")
        self.marks[ns] = tok

    def netns_mark_remove(self, ns):
        self.marks.pop(ns, None)

    def vm_facts(self, d):
        return dict(self.vm)

    def _add(self, n, kind, alias, mac=""):
        self.l[n] = dict(kind=kind, master=None, alias=alias, physical=False, mac=mac, addrs=[],
                         noarp=True, lower_up=False, vlan_filtering=kind == "bridge")
        for k, v in (("arp_ignore", "8"), ("rp_filter", "1"), ("forwarding", "0")):
            self.sc["net.ipv4.conf.%s.%s" % (n, k)] = v
        self.sc["net.ipv6.conf.%s.disable_ipv6" % n] = "1"

    def create_bridge(self, n, alias):
        self._add(n, "bridge", alias)
        self.self_vlans[n] = []
        if self.rogue:
            self.rogue(self)

    def create_tap(self, n, alias, user):
        self._add(n, "tun", alias)

    def create_veth(self, h, p, ns, alias, hm, pm):
        self._add(h, "veth", alias, hm)

    def enslave(self, n, br):
        self.l[n]["master"] = br

    def netns_add(self, ns):
        if ns in self.ns:
            raise wvl.LabError("exists")
        self.ns.add(ns)

    def peer_config(self, ns, ifn, ip):
        pass

    def link_del(self, n):
        self.deleted.append(n)
        del self.l[n]

    def netns_del(self, ns):
        self.deleted.append(ns)
        self.ns.discard(ns)


def mk_alias(tok=TOK):
    return wvl.alias_of(D, tok)


class T(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.h = FakeHost()
        self.eno1 = dict(self.h.l["eno1"])
        self.path = os.path.join(self.td.name, "m.json")

    def r(self, cmd, extra=()):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(err):
            rc = wvl.main([cmd, "--run-id", "t1", "--manifest", self.path, "--tap-user", "u"] + list(extra), host=self.h)
        self.out = out.getvalue()
        return rc, err.getvalue()

    def manifest(self):
        with open(self.path) as f:
            return json.load(f)

    def host_status(self):
        return self.r("status", ["--host-only"])[0]

    def attach_and_verify(self, **over):
        """Make the fake VM really attached and record a fresh guest Verify."""
        self.h.vm = {"pid": 42, "cmdline_ok": True, "fd_iff": True, "start": 1.0}
        self.h.l[D["tap"]]["lower_up"] = True
        g = os.path.join(self.td.name, "g.json")
        v = os.path.join(self.td.name, "v.json")
        lab = {"Status": "Up", "MacAddress": D["windows_mac"].replace(":", "-").upper(), "InterfaceGuid": "{G}"}
        lab.update(over)
        with open(g, "w") as f:
            json.dump({"adapters": [dict(lab, Name="Ethernet 2")]}, f)
        with open(v, "w") as f:
            json.dump({"ok": True, "lab": lab}, f)
        self.assertEqual(self.r("record-guest", ["--guest-json", g, "--verify-json", v])[0], 0)

    # ---- names / macs
    def test_names_fit_ifnamsiz_and_macs_distinct(self):
        d = wvl.derive("abcdefgh")
        self.assertTrue(all(len(d[k]) <= 15 for k in ("bridge", "tap", "veth_host", "peer_if")))
        self.assertNotEqual(wvl.derive("a")["windows_mac"], wvl.derive("b")["windows_mac"])
        for rid in ("rg", "yr", "6p", "80", "n2", "t1"):  # M1: old derivation collided for these
            d = wvl.derive(rid)
            self.assertEqual(len({d["windows_mac"], d["peer_mac"], d["veth_host_mac"]}), 3)
        with self.assertRaises(wvl.LabError):
            wvl.derive("../x")

    # ---- busy names
    def _busy(self, setup):
        setup()
        before = (self.h.links(), set(self.h.ns))
        rc, err = self.r("up")
        self.assertEqual(rc, 3, err)
        self.assertIn("busy", err)
        self.assertEqual((self.h.links(), set(self.h.ns)), before)
        self.assertEqual(self.h.deleted, [])
        self.assertFalse(os.path.exists(self.path))

    def test_busy_bridge_name(self):
        self._busy(lambda: self.h._add(D["bridge"], "bridge", ""))

    def test_busy_tap_name(self):
        self._busy(lambda: self.h._add(D["tap"], "tun", ""))

    def test_busy_netns_name_and_not_deleted_by_later_down(self):
        self._busy(lambda: self.h.ns.add(D["netns"]))
        # I3: a foreign netns of the same name has no marker; a stale manifest of ours must not delete it
        wvl.write_manifest(self.path, {"run_id": "t1", "token": TOK, "state": "creating", "names": D,
                                       "created": [{"kind": "netns", "name": D["netns"]}]})
        rc, err = self.r("down")
        self.assertEqual(rc, 5)
        self.assertIn(D["netns"], self.h.ns)
        self.assertNotIn(D["netns"], self.h.deleted)

    def test_netns_with_other_manifest_token_not_deleted(self):
        self.assertEqual(self.r("up")[0], 0)
        self.h.marks[D["netns"]] = "someone-elses-token"
        rc, _ = self.r("down")
        self.assertEqual(rc, 5)
        self.assertIn(D["netns"], self.h.ns)

    def test_same_runid_other_manifest_cannot_delete_ours(self):
        self.assertEqual(self.r("up")[0], 0)
        other = os.path.join(self.td.name, "other.json")
        wvl.write_manifest(other, {"run_id": "t1", "token": "other-token", "state": "up", "names": D, "created": []})
        self.path, mine = other, self.path
        rc, _ = self.r("down")
        self.assertEqual(rc, 5)
        self.assertIn(D["bridge"], self.h.l)
        self.assertIn(D["tap"], self.h.l)
        self.assertIn(D["veth_host"], self.h.l)
        self.path = mine
        self.assertEqual(self.r("down")[0], 0)
        self.assertEqual(self.h.l.keys(), {"eno1"})
        self.assertFalse(self.h.ns)

    def test_failed_netns_add_is_not_recorded_or_deleted(self):
        self.h.netns_add = lambda ns: (_ for _ in ()).throw(wvl.LabError("add failed"))
        self.assertEqual(self.r("up")[0], 4)
        self.assertEqual(self.h.l.keys(), {"eno1"})
        self.assertNotIn(D["netns"], self.h.deleted)
        self.assertNotIn(D["netns"], [e["name"] for e in self.manifest()["created"]])

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
        rc, _ = self.r("down")
        self.assertEqual(rc, 5)
        self.assertIn(D["tap"], self.h.l)
        self.assertNotIn(D["bridge"], self.h.l)
        self.assertEqual(self.h.l["eno1"], self.eno1)

    # ---- physical uplink
    def test_physical_uplink_rejected_and_rolled_back(self):
        self.h.rogue = lambda h: h.l["eno1"].update(master=D["bridge"])
        rc, err = self.r("up")
        self.assertEqual(rc, 4)
        self.assertIn("physical uplink eno1", err)
        self.assertNotIn(D["bridge"], self.h.l)
        self.assertNotIn("eno1", self.h.deleted)
        self.assertFalse(self.h.ns)
        self.assertEqual(self.manifest()["state"], "down")  # M2: rollback leaves a re-upable manifest

    def test_status_flags_uplink(self):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.host_status(), 0)
        self.h.l["eno1"]["master"] = D["bridge"]
        self.assertEqual(self.host_status(), 1)

    # ---- I1: bridge must stay out of the host IP stack
    def _break(self, fn, needle):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.host_status(), 0)
        fn()
        self.assertEqual(self.host_status(), 1)
        self.assertIn(needle, self.out)
        self.assertIn('"raw_run_allowed": false', self.out)

    def test_bridge_self_vlan_present_is_violation(self):
        self._break(lambda: self.h.self_vlans.update({D["bridge"]: [1]}), "self vlan")

    def test_vlan_filtering_off_is_violation(self):
        self._break(lambda: self.h.l[D["bridge"]].update(vlan_filtering=False), "vlan_filtering")

    def test_arp_on_is_violation(self):
        self._break(lambda: self.h.l[D["bridge"]].update(noarp=False), "NOARP")

    def test_arp_ignore_rpfilter_forwarding_violations(self):
        self._break(lambda: self.h.sc.update({"net.ipv4.conf.%s.arp_ignore" % D["bridge"]: "0"}), "arp_ignore")
        self.h.sc["net.ipv4.conf.%s.arp_ignore" % D["bridge"]] = "8"
        self.h.sc["net.ipv4.conf.%s.rp_filter" % D["tap"]] = "2"
        self.assertEqual(self.host_status(), 1)
        self.assertIn("rp_filter", self.out)
        self.h.sc["net.ipv4.conf.%s.rp_filter" % D["tap"]] = "1"
        self.h.sc["net.ipv4.conf.%s.forwarding" % D["veth_host"]] = "1"
        self.assertEqual(self.host_status(), 1)
        self.assertIn("forwarding", self.out)

    def test_ip_forward_enabled_later_is_violation(self):
        self._break(lambda: self.h.sc.update({"net.ipv4.ip_forward": "1"}), "ip_forward")

    def test_ip_forward_enabled_blocks_plan_and_up(self):
        self.h.sc["net.ipv4.ip_forward"] = "1"
        self.assertEqual(self.r("up")[0], 3)
        self.assertEqual(self.h.l.keys(), {"eno1"})

    def test_host_ip_on_bridge_or_tap_is_violation(self):
        self._break(lambda: self.h.l[D["tap"]]["addrs"].append("198.18.0.9/30"), "host IP")

    def test_firewall_reference_is_violation(self):
        self._break(lambda: self.h.fw.append('iifname "%s" accept' % D["bridge"]), "firewall")

    def test_firewall_reference_blocks_plan(self):
        self.h.fw.append('iifname "%s" accept' % D["bridge"])
        self.assertEqual(self.r("plan")[0], 3)

    # ---- I2: attachment from facts
    def test_host_only_status_never_allows_raw_run(self):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.host_status(), 0)
        self.assertIn('"raw_run_allowed": false', self.out)

    def test_status_not_ok_without_vm_attachment(self):
        self.assertEqual(self.r("up")[0], 0)
        rc, _ = self.r("status")
        self.assertEqual(rc, 1)
        self.assertIn('"raw_run_allowed": false', self.out)
        self.assertFalse(self.manifest()["vm"]["attached"])

    def test_status_ok_needs_all_three_facts_and_fresh_guest(self):
        self.assertEqual(self.r("up")[0], 0)
        self.attach_and_verify()
        self.h.vm["start"] = 0.5
        self.assertEqual(self.r("status")[0], 0, self.out)
        self.assertTrue(self.manifest()["vm"]["attached"])
        for k, bad in (("cmdline_ok", False), ("fd_iff", False), ("pid", None)):
            good = self.h.vm[k]
            self.h.vm[k] = bad
            self.assertEqual(self.r("status")[0], 1, k)
            self.assertFalse(self.manifest()["vm"]["attached"])
            self.h.vm[k] = good
        self.h.l[D["tap"]]["lower_up"] = False   # stale/detached TAP: no carrier
        self.assertEqual(self.r("status")[0], 1)
        self.h.l[D["tap"]]["lower_up"] = True
        self.h.vm["start"] = 1e12                 # VM restarted after the guest record -> stale record
        self.assertEqual(self.r("status")[0], 1)

    def test_guest_verify_must_be_up_and_same_mac(self):
        self.assertEqual(self.r("up")[0], 0)
        self.attach_and_verify(Status="Disconnected")
        self.h.vm["start"] = 0.5
        self.assertEqual(self.r("status")[0], 1)
        g = os.path.join(self.td.name, "g.json")
        with open(g, "w") as f:
            json.dump({"adapters": [{"MacAddress": "52-54-00-AA-AA-AA", "InterfaceGuid": "{X}"}]}, f)
        self.assertEqual(self.r("record-guest", ["--guest-json", g])[0], 3)  # MAC absent in guest inventory

    def test_record_guest_malformed_is_clean_error(self):
        self.assertEqual(self.r("up")[0], 0)
        g = os.path.join(self.td.name, "bad.json")
        with open(g, "w") as f:
            f.write("{}")
        rc, err = self.r("record-guest", ["--guest-json", g])
        self.assertEqual(rc, 3)
        self.assertIn("malformed", err)

    # ---- misc lifecycle
    def test_ambiguous_nic_and_management_mac(self):
        ad = [{"MacAddress": "52-54-00-AA-BB-CC", "InterfaceGuid": "{1}"},
              {"MacAddress": "52-54-00-aa-bb-cc", "InterfaceGuid": "{2}"}]
        with self.assertRaises(wvl.LabError):
            wvl.select_adapter(ad, "52:54:00:aa:bb:cc")
        with self.assertRaises(wvl.LabError):
            wvl.select_adapter(ad[:1], "52:54:00:00:00:01")
        with self.assertRaises(wvl.LabError):
            wvl.select_adapter([{"MacAddress": "52-54-00-12-34-56"}], wvl.MGMT_MAC)
        self.assertEqual(wvl.select_adapter(ad[:1], "52:54:00:aa:bb:cc")["InterfaceGuid"], "{1}")

    def test_repeated_down_is_noop(self):
        self.assertEqual(self.r("up")[0], 0)
        self.assertEqual(self.r("down")[0], 0)
        n = len(self.h.deleted)
        self.assertEqual(self.r("down")[0], 0)
        self.assertEqual(len(self.h.deleted), n)
        self.assertEqual(self.h.l.keys(), {"eno1"})
        self.assertFalse(self.h.ns)
        self.assertFalse(self.h.marks)

    def test_down_without_manifest_is_noop(self):
        self.h._add(D["bridge"], "bridge", mk_alias())
        self.assertEqual(self.r("down")[0], 0)
        self.assertIn(D["bridge"], self.h.l)

    def test_incomplete_up_refused_then_down_cleans_own_only(self):
        wvl.write_manifest(self.path, {"run_id": "t1", "token": TOK, "state": "creating", "names": D,
                                       "created": [{"kind": "link", "name": D["bridge"]}]})
        self.h._add(D["bridge"], "bridge", mk_alias())
        self.h._add(D["tap"], "tun", mk_alias())   # created but never recorded: still ours by live mark
        self.h.ns.add("foreign-ns")
        rc, err = self.r("up")
        self.assertEqual(rc, 3)
        self.assertIn("state=creating", err)
        self.assertEqual(self.host_status(), 1)
        self.assertEqual(self.r("down")[0], 0)
        self.assertEqual(self.h.l.keys(), {"eno1"})
        self.assertIn("foreign-ns", self.h.ns)

    def test_reup_after_clean_down(self):
        self.assertEqual(self.r("up")[0], 0)
        tok1 = self.manifest()["token"]
        self.assertEqual(self.r("down")[0], 0)
        self.assertEqual(self.r("up")[0], 0)
        self.assertNotEqual(self.manifest()["token"], tok1)
        self.assertEqual(self.host_status(), 0)

    def test_lab_env_of_other_run_not_overwritten(self):
        env = os.path.join(self.td.name, "lab.env")
        with open(env, "w") as f:
            f.write("LAB_RUN_ID=other\nLAB_TAP=wvt-other\n")
        rc, err = self.r("up", ["--lab-env", env])
        self.assertEqual(rc, 3)
        self.assertIn("another run-id", err)
        self.assertEqual(self.h.l.keys(), {"eno1"})

    def test_up_status_down_roundtrip(self):
        self.assertEqual(self.r("up")[0], 0)
        m = self.manifest()
        self.assertEqual(m["state"], "up")
        self.assertEqual(m["lab"]["windows_ip"], "198.18.0.1")
        self.assertIsNone(m["lab"]["gateway"])
        self.assertEqual(self.h.l["eno1"], self.eno1)
        self.assertEqual(self.r("down")[0], 0)

    def test_ps1_is_guarded(self):
        with open(os.path.join(HERE, "..", "windows-vm-lab.ps1")) as f:
            s = f.read()
        for needle in ("Inventory", "Configure", "Verify", "ambiguous", "DefaultGateway", "'Up'", "52-54-00-12-34-56"):
            self.assertIn(needle, s)


if __name__ == "__main__":
    unittest.main()
