"""Tests for the ``symlink-aware-tree-reconcile`` semantic core.

These exercise the family-local primary path only: the four decoders,
cross-format equivalence, the leaf model and safe-link rule, the five policies,
the union ancestor invariant, and byte-exact ``operations.tsv`` serialization.
No identity, oracle, workspace, or coverage artifact is exercised here.
"""

from __future__ import annotations

import unittest

from cbds.executable_symlink_aware_tree_reconcile import (
    DESIRED_STATE_FORMATS,
    RECONCILIATION_POLICIES,
    SYMLINK_TREE_RECONCILE_ALLOWED_TOOLS,
    BlueprintEntry,
    FileLeaf,
    SymlinkLeaf,
    SymlinkTreeReconcileError,
    decode_actual_state,
    decode_desired_state,
    is_safe_link_alias,
    leaves_match,
    reconcile,
    serialize_operations_tsv,
)


def _blueprint(entries):
    return decode_desired_state("directory-blueprint", blueprint_entries=tuple(entries))


class LeafModelTests(unittest.TestCase):
    def test_owner_readable_invariant(self):
        FileLeaf(0o000, b"")  # empty mode-000 leaf is allowed
        FileLeaf(0o644, b"data")
        with self.assertRaises(SymlinkTreeReconcileError):
            FileLeaf(0o044, b"data")  # non-empty but not owner-readable
        with self.assertRaises(SymlinkTreeReconcileError):
            FileLeaf(0o1000, b"")  # out of range

    def test_exact_match_equality(self):
        self.assertTrue(leaves_match(FileLeaf(0o644, b"x"), FileLeaf(0o644, b"x")))
        self.assertFalse(leaves_match(FileLeaf(0o644, b"x"), FileLeaf(0o600, b"x")))
        self.assertFalse(leaves_match(FileLeaf(0o644, b"x"), FileLeaf(0o644, b"y")))
        self.assertTrue(leaves_match(SymlinkLeaf("a/b"), SymlinkLeaf("a/b")))
        self.assertFalse(leaves_match(SymlinkLeaf("a/b"), SymlinkLeaf("a/c")))
        self.assertFalse(leaves_match(FileLeaf(0o644, b"x"), SymlinkLeaf("x")))

    def test_symlink_target_rejects_parent_component(self):
        SymlinkLeaf("docs/a.txt")
        with self.assertRaises(SymlinkTreeReconcileError):
            SymlinkLeaf("../escape")


class CrossFormatEquivalenceTests(unittest.TestCase):
    def _expected(self):
        return {
            "docs/a.txt": FileLeaf(0o644, b"alpha"),
            "cur": SymlinkLeaf("docs/a.txt"),
        }

    def test_four_formats_decode_to_one_map(self):
        payloads = {"p1": b"alpha"}
        jsonl = (
            b'{"kind":"file","mode":"0644","path":"docs/a.txt","value":"p1"}\n'
            b'{"kind":"symlink","mode":null,"path":"cur","value":"docs/a.txt"}\n'
        )
        csv_bytes = (
            b"kind,mode,path,value\n"
            b"file,0644,docs/a.txt,p1\n"
            b"symlink,,cur,docs/a.txt\n"
        )
        nul = (
            b"file\x000644\x00docs/a.txt\x00p1\x00"
            b"symlink\x00\x00cur\x00docs/a.txt\x00"
        )
        blueprint = (
            BlueprintEntry("docs/a.txt", "file", mode=0o644, content=b"alpha"),
            BlueprintEntry("cur", "symlink", target="docs/a.txt"),
        )
        maps = [
            decode_desired_state("jsonl", payload_bytes=jsonl, payloads=payloads),
            decode_desired_state("csv", payload_bytes=csv_bytes, payloads=payloads),
            decode_desired_state("nul-records", payload_bytes=nul, payloads=payloads),
            decode_desired_state("directory-blueprint", blueprint_entries=blueprint),
        ]
        for decoded in maps:
            self.assertEqual(decoded, self._expected())

    def test_empty_state_per_format(self):
        self.assertEqual(decode_desired_state("jsonl", payload_bytes=b""), {})
        self.assertEqual(
            decode_desired_state("csv", payload_bytes=b"kind,mode,path,value\n"), {}
        )
        self.assertEqual(decode_desired_state("nul-records", payload_bytes=b""), {})
        self.assertEqual(
            decode_desired_state("directory-blueprint", blueprint_entries=()), {}
        )

    def test_exact_duplicate_collapses_and_conflict_rejects(self):
        payloads = {"p1": b"alpha"}
        dup = (
            b'{"kind":"file","mode":"0644","path":"a.txt","value":"p1"}\n'
            b'{"kind":"file","mode":"0644","path":"a.txt","value":"p1"}\n'
        )
        self.assertEqual(
            decode_desired_state("jsonl", payload_bytes=dup, payloads=payloads),
            {"a.txt": FileLeaf(0o644, b"alpha")},
        )
        conflict = (
            b'{"kind":"file","mode":"0644","path":"a.txt","value":"p1"}\n'
            b'{"kind":"file","mode":"0600","path":"a.txt","value":"p1"}\n'
        )
        with self.assertRaises(SymlinkTreeReconcileError):
            decode_desired_state("jsonl", payload_bytes=conflict, payloads=payloads)


class MalformedInputTests(unittest.TestCase):
    payloads = {"p1": b"alpha"}

    def _jsonl(self, payload):
        return decode_desired_state("jsonl", payload_bytes=payload, payloads=self.payloads)

    def test_jsonl_rejections(self):
        cases = [
            b"\n",  # blank row
            b'{"kind":"file","mode":"0644","path":"a","value":"p1"}',  # no final LF
            b'{"kind":"file","mode":"0644","path":"a","value":"p1"}\r\n',  # CR
            b'{"kind":"file","kind":"file","mode":"0644","path":"a","value":"p1"}\n',  # dup member
            b'{"kind":"file","mode":"0644","path":"a"}\n',  # missing member
            b'{"kind":NaN,"mode":"0644","path":"a","value":"p1"}\n',  # extension token
            b'{"kind":"file","mode":644,"path":"a","value":"p1"}\n',  # numeric mode
            b'{"kind":"file","mode":"0999","path":"a","value":"p1"}\n',  # non-octal mode
            b'{"kind":"file","mode":"1000","path":"a","value":"p1"}\n',  # mode > 0777
            b'{"kind":"file","mode":"0644","path":"a","value":"missing"}\n',  # bad payload
            b'{"kind":"file","mode":"0644","path":"/abs","value":"p1"}\n',  # absolute
            b'{"kind":"file","mode":"0644","path":"a/../b","value":"p1"}\n',  # noncanonical
            b'{"kind":"symlink","mode":"0644","path":"s","value":"a"}\n',  # symlink w/ mode
            b'{"kind":"symlink","mode":null,"path":"s","value":"../x"}\n',  # parent target
            '{"kind":"file","mode":"0644","path":"a,b","value":"p1"}\n'.encode(),  # comma path
        ]
        for payload in cases:
            with self.assertRaises(SymlinkTreeReconcileError, msg=repr(payload)):
                self._jsonl(payload)

    def test_csv_rejections(self):
        cases = [
            b"path,sha256\nfile,0644,a,p1\n",  # wrong header
            b"kind,mode,path,value\nfile,0644,a,p1\r\n",  # CR
            b'kind,mode,path,value\nfile,0644,"a",p1\n',  # quoting
            b"kind,mode,path,value\nfile,0644,a\n",  # too few fields
            b"kind,mode,path,value\nfile,0644,a,p1",  # no final LF
            b"kind,mode,path,value\nsymlink,0644,s,a\n",  # symlink w/ mode
        ]
        for payload in cases:
            with self.assertRaises(SymlinkTreeReconcileError, msg=repr(payload)):
                decode_desired_state("csv", payload_bytes=payload, payloads=self.payloads)

    def test_nul_rejections(self):
        cases = [
            b"file\x000644\x00a\x00p1",  # unterminated
            b"file\x000644\x00a\x00",  # 3 fields only (not x4)... actually 4? -> use 5
            b"file\x000644\x00a\x00p1\x00extra\x00",  # 5 fields not multiple of 4
            b"symlink\x000644\x00s\x00a\x00",  # symlink w/ mode
        ]
        for payload in cases:
            with self.assertRaises(SymlinkTreeReconcileError, msg=repr(payload)):
                decode_desired_state("nul-records", payload_bytes=payload, payloads=self.payloads)

    def test_within_state_ancestor_conflict(self):
        payload = (
            b'{"kind":"file","mode":"0644","path":"a/b","value":"p1"}\n'
            b'{"kind":"file","mode":"0644","path":"a/b/c","value":"p1"}\n'
        )
        with self.assertRaises(SymlinkTreeReconcileError):
            self._jsonl(payload)


class SafeLinkAliasTests(unittest.TestCase):
    def _state(self, actual_alias_target, desired_alias=None, desired_target=None,
               actual_target_leaf=None):
        desired = {
            "alias.txt": desired_alias or FileLeaf(0o644, b"shared"),
            "target.txt": desired_target or FileLeaf(0o644, b"shared"),
        }
        actual = {"alias.txt": SymlinkLeaf(actual_alias_target)}
        if actual_target_leaf is not None:
            actual["target.txt"] = actual_target_leaf
        return actual, desired

    def test_positive_safe_alias(self):
        actual, desired = self._state(
            "target.txt", actual_target_leaf=FileLeaf(0o644, b"shared")
        )
        self.assertTrue(is_safe_link_alias("alias.txt", actual, desired))

    def test_self_link_not_safe(self):
        actual = {"s": SymlinkLeaf("s")}
        desired = {"s": FileLeaf(0o644, b"x")}
        self.assertFalse(is_safe_link_alias("s", actual, desired))

    def test_mutual_cycle_not_safe(self):
        actual = {"p": SymlinkLeaf("q"), "q": SymlinkLeaf("p")}
        desired = {"p": FileLeaf(0o644, b"x"), "q": FileLeaf(0o644, b"x")}
        self.assertFalse(is_safe_link_alias("p", actual, desired))
        self.assertFalse(is_safe_link_alias("q", actual, desired))

    def test_chain_not_safe(self):
        actual = {"p": SymlinkLeaf("q"), "q": SymlinkLeaf("r")}
        desired = {"p": FileLeaf(0o644, b"x"), "q": FileLeaf(0o644, b"x")}
        self.assertFalse(is_safe_link_alias("p", actual, desired))

    def test_dangling_not_safe(self):
        actual, desired = self._state("nowhere.txt")
        self.assertFalse(is_safe_link_alias("alias.txt", actual, desired))

    def test_directory_target_not_safe(self):
        actual = {"alias.txt": SymlinkLeaf("d")}
        desired = {"alias.txt": FileLeaf(0o644, b"x"), "d/f.txt": FileLeaf(0o644, b"x")}
        self.assertFalse(is_safe_link_alias("alias.txt", actual, desired))

    def test_unequal_content_not_safe(self):
        actual, desired = self._state(
            "target.txt",
            desired_target=FileLeaf(0o644, b"different"),
            actual_target_leaf=FileLeaf(0o644, b"different"),
        )
        self.assertFalse(is_safe_link_alias("alias.txt", actual, desired))


class PolicyDiscriminationTests(unittest.TestCase):
    def _common_state(self):
        # One common state carrying the M, X, E, A, and exact-match probes.
        desired = {
            "exact.txt": FileLeaf(0o644, b"same"),
            "missing.txt": FileLeaf(0o644, b"new"),
            "mismatch.txt": FileLeaf(0o644, b"new"),
            "alias.txt": FileLeaf(0o644, b"shared"),
            "target.txt": FileLeaf(0o644, b"shared"),
        }
        actual = {
            "exact.txt": FileLeaf(0o644, b"same"),
            "mismatch.txt": FileLeaf(0o644, b"old"),
            "extra.txt": FileLeaf(0o644, b"extra"),
            "alias.txt": SymlinkLeaf("target.txt"),
            "target.txt": FileLeaf(0o644, b"shared"),
        }
        return actual, desired

    def test_five_policies_pairwise_distinct(self):
        actual, desired = self._common_state()
        signatures = set()
        finals = {}
        for policy in RECONCILIATION_POLICIES:
            state = reconcile(policy, actual, desired)
            tsv = serialize_operations_tsv(state.rows)
            signatures.add(tsv)
            finals[policy] = state.final_map()
        self.assertEqual(len(signatures), 5)

    def test_complete_policies_reconcile_fully(self):
        actual, desired = self._common_state()
        strict = reconcile("strict-exact-state", actual, desired)
        self.assertEqual(strict.final_map(), desired)
        preserve = reconcile("preserve-safe-links", actual, desired)
        # Same as desired except the safe alias stays a symlink.
        self.assertEqual(preserve.final_map()["alias.txt"], SymlinkLeaf("target.txt"))
        self.assertNotEqual(preserve.final_map(), desired)

    def test_partial_policy_decisions(self):
        actual, desired = self._common_state()
        rows = {r.path: r for r in reconcile("create-missing", actual, desired).rows}
        self.assertEqual(rows["missing.txt"].decision, "create")
        self.assertEqual(rows["mismatch.txt"].decision, "defer-mismatch")
        self.assertEqual(rows["extra.txt"].decision, "retain-extra")
        self.assertEqual(rows["alias.txt"].decision, "defer-mismatch")
        self.assertEqual(rows["exact.txt"].decision, "keep")

    def test_cross_tree_ancestor_conflict_rejected(self):
        actual = {"a/b": FileLeaf(0o644, b"x")}
        desired = {"a/b/c": FileLeaf(0o644, b"y")}
        with self.assertRaises(SymlinkTreeReconcileError):
            reconcile("strict-exact-state", actual, desired)


class OperationsLogTests(unittest.TestCase):
    def test_empty_union_header_only(self):
        state = reconcile("strict-exact-state", {}, {})
        self.assertEqual(
            serialize_operations_tsv(state.rows),
            b"path\tdecision\tactual_kind\tdesired_kind\tfinal_kind\n",
        )

    def test_rows_are_raw_byte_sorted(self):
        desired = {"b.txt": FileLeaf(0o644, b"x"), "a.txt": FileLeaf(0o644, b"y")}
        state = reconcile("strict-exact-state", {}, desired)
        tsv = serialize_operations_tsv(state.rows).decode("utf-8").splitlines()
        self.assertEqual(tsv[0], "path\tdecision\tactual_kind\tdesired_kind\tfinal_kind")
        self.assertEqual([line.split("\t")[0] for line in tsv[1:]], ["a.txt", "b.txt"])
        self.assertEqual(tsv[1], "a.txt\tcreate\tabsent\tfile\tfile")


class BoundsTests(unittest.TestCase):
    def test_oversized_file_rejected(self):
        with self.assertRaises(SymlinkTreeReconcileError):
            FileLeaf(0o644, b"x" * (16 * 1024 + 1))

    def test_too_many_desired_leaves_rejected(self):
        entries = tuple(
            BlueprintEntry(f"f{i}.txt", "file", mode=0o644, content=b"x")
            for i in range(97)
        )
        with self.assertRaises(SymlinkTreeReconcileError):
            _blueprint(entries)


class InvariantTests(unittest.TestCase):
    def test_axes_and_tool_tuple(self):
        self.assertEqual(
            DESIRED_STATE_FORMATS, ("jsonl", "csv", "nul-records", "directory-blueprint")
        )
        self.assertEqual(
            RECONCILIATION_POLICIES,
            (
                "create-missing",
                "replace-mismatch",
                "remove-extra",
                "preserve-safe-links",
                "strict-exact-state",
            ),
        )
        self.assertEqual(
            SYMLINK_TREE_RECONCILE_ALLOWED_TOOLS,
            ("awk", "chmod", "cp", "find", "jq", "ln", "mkdir", "mv", "sha256sum", "sort", "stat"),
        )
        self.assertEqual(
            tuple(sorted(set(SYMLINK_TREE_RECONCILE_ALLOWED_TOOLS))),
            SYMLINK_TREE_RECONCILE_ALLOWED_TOOLS,
        )

    def test_actual_state_absent_root_is_empty(self):
        self.assertEqual(decode_actual_state(()), {})


if __name__ == "__main__":
    unittest.main()
