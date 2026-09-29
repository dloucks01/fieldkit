#!/usr/bin/env python3
"""Enumerator adapters: native tool output -> the normalized cloud/k8s graph.

Pinned:
  * AWS `get-account-authorization-details` -> cloud graph: effective Allow actions
    resolved from inline + attached-managed + group policies; sts:AssumeRole edges
    from role trust policies; `--owned` selection; `*` marks admin;
  * `kubectl auth can-i --list` -> k8s graph: verbs expanded per resource, API-group
    suffix stripped, non-resource rows skipped, one owned subject;
  * bad input raises AdapterError;
  * end-to-end: adapted graph flows through apply_iam / apply_rbac to escalation paths.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fieldkit import adapters, cloud_iam, k8s, saas  # noqa: E402
from fieldkit.state import Store  # noqa: E402

# `aws iam get-account-authorization-details` (trimmed to the fields adapters read).
AWS = {
    "UserDetailList": [{
        "UserName": "dev",
        "Arn": "arn:aws:iam::111122223333:user/dev",
        "UserPolicyList": [{
            "PolicyName": "inline",
            "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": "iam:CreatePolicyVersion",
                 "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]}}],
        "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnly"}],
        "GroupList": ["builders"],
    }],
    "GroupDetailList": [{
        "GroupName": "builders",
        "Arn": "arn:aws:iam::111122223333:group/builders",
        "GroupPolicyList": [{
            "PolicyName": "g",
            "PolicyDocument": {"Statement": [
                {"Effect": "Allow", "Action": ["ec2:RunInstances"], "Resource": "*"}]}}],
        "AttachedManagedPolicies": [],
    }],
    "RoleDetailList": [{
        "RoleName": "admin",
        "Arn": "arn:aws:iam::111122223333:role/admin",
        "RolePolicyList": [],
        "AttachedManagedPolicies": [{"PolicyArn":
                                     "arn:aws:iam::aws:policy/AdministratorAccess"}],
        "AssumeRolePolicyDocument": {"Statement": [{
            "Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"AWS": "arn:aws:iam::111122223333:user/dev"}}]},
    }],
    "Policies": [
        {"Arn": "arn:aws:iam::aws:policy/ReadOnly", "PolicyVersionList": [
            {"IsDefaultVersion": True, "Document": {"Statement": [
                {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}}]},
        {"Arn": "arn:aws:iam::aws:policy/AdministratorAccess", "PolicyVersionList": [
            {"IsDefaultVersion": True, "Document": {"Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}]}}]},
    ],
}


class AwsAdapterTest(unittest.TestCase):
    def test_resolves_effective_actions_and_flags(self):
        g = adapters.aws_authorization_details(json.dumps(AWS),
                                               owned=["arn:aws:iam::111122223333:user/dev"])
        self.assertEqual(g["provider"], "aws")
        by = {p["name"]: p for p in g["principals"]}
        # groups are not principals
        self.assertEqual(set(by), {"dev", "admin"})
        dev = by["dev"]
        self.assertTrue(dev["owned"])
        self.assertFalse(dev["admin"])
        # inline + managed(ReadOnly) + group(ec2:RunInstances)
        self.assertIn("iam:CreatePolicyVersion", dev["permissions"])
        self.assertIn("ec2:Describe*", dev["permissions"])
        self.assertIn("ec2:RunInstances", dev["permissions"])
        # Deny actions are NOT collected (candidate-permission view is Allow-only)
        self.assertNotIn("s3:DeleteBucket", dev["permissions"])
        self.assertTrue(by["admin"]["admin"])          # AdministratorAccess "*"

    def test_owned_matches_by_name_too(self):
        g = adapters.aws_authorization_details(json.dumps(AWS), owned=["dev"])
        self.assertTrue({p["name"]: p for p in g["principals"]}["dev"]["owned"])

    def test_assume_role_edge_from_trust_policy(self):
        g = adapters.aws_authorization_details(json.dumps(AWS))
        self.assertIn({"src": "arn:aws:iam::111122223333:user/dev",
                       "dst": "arn:aws:iam::111122223333:role/admin",
                       "kind": "sts:AssumeRole"}, g["edges"])

    def test_bad_shape_raises(self):
        with self.assertRaises(adapters.AdapterError):
            adapters.aws_authorization_details("{not json")
        with self.assertRaises(adapters.AdapterError):
            adapters.aws_authorization_details('{"unrelated": 1}')

    def test_end_to_end_reaches_admin(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = Store.create(os.path.join(tmp.name, "e.db"))
        self.addCleanup(store.close)
        store.init_engagement("AWS")
        g = adapters.aws_authorization_details(json.dumps(AWS), owned=["dev"])
        cloud_iam.apply_iam(store, json.dumps(g))
        paths = cloud_iam.escalation_paths(store)
        self.assertTrue(paths)                          # dev reaches admin-equivalent
        self.assertEqual(paths[0]["start"], "dev")


CAN_I = """\
Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []               [get]
pods                                            []                  []               [get list create]
secrets.rbac.authorization.k8s.io               []                  []               [get]
                                                [/healthz]          []               [get]
"""


class KubectlAdapterTest(unittest.TestCase):
    def test_expands_verbs_and_strips_group(self):
        g = adapters.kubectl_can_i(CAN_I, subject="app")
        self.assertEqual(g["cluster"], "cluster")
        subj = g["subjects"][0]
        self.assertEqual(subj["id"], "sa:app")
        self.assertTrue(subj["owned"])
        perms = set(subj["permissions"])
        self.assertIn("create pods", perms)
        self.assertIn("list pods", perms)
        self.assertIn("get secrets", perms)     # API-group suffix stripped
        self.assertIn("get *", perms)            # *.* -> *

    def test_non_resource_url_row_skipped(self):
        g = adapters.kubectl_can_i(CAN_I, subject="app")
        self.assertNotIn("get /healthz",
                         g["subjects"][0]["permissions"])

    def test_empty_raises(self):
        with self.assertRaises(adapters.AdapterError):
            adapters.kubectl_can_i("Resources   Verbs\n")   # header only, no rows

    def test_end_to_end_create_pods_reaches_admin(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = Store.create(os.path.join(tmp.name, "e.db"))
        self.addCleanup(store.close)
        store.init_engagement("K8S")
        g = adapters.kubectl_can_i(CAN_I, subject="app")
        k8s.apply_rbac(store, json.dumps(g))
        paths = k8s.escalation_paths(store)
        self.assertTrue(paths)                          # create pods -> cluster-admin
        self.assertEqual(paths[0]["start"], "app")


ENTRA = {"value": [
    {"principal": {"@odata.type": "#microsoft.graph.user", "id": "u1",
                   "displayName": "Helga", "userPrincipalName": "helga@contoso.com"},
     "roleDefinition": {"displayName": "Application Administrator"}},
    {"principal": {"@odata.type": "#microsoft.graph.user", "id": "u1",
                   "displayName": "Helga", "userPrincipalName": "helga@contoso.com"},
     "roleDefinition": {"displayName": "Reports Reader"}},
    {"principal": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp1",
                   "displayName": "ci-app"},
     "roleDefinition": {"displayName": "Global Administrator"}},
]}


class EntraAdapterTest(unittest.TestCase):
    def test_groups_roles_per_principal(self):
        g = adapters.entra_role_assignments(json.dumps(ENTRA), owned=["helga@contoso.com"])
        self.assertEqual(g["tenant"], "entra")
        by = {p["name"]: p for p in g["principals"]}
        self.assertEqual(set(by), {"Helga", "ci-app"})
        self.assertEqual(set(by["Helga"]["permissions"]),
                         {"Application Administrator", "Reports Reader"})
        self.assertTrue(by["Helga"]["owned"])          # matched by UPN
        self.assertFalse(by["Helga"]["admin"])
        self.assertEqual(by["ci-app"]["type"], "serviceprincipal")
        self.assertTrue(by["ci-app"]["admin"])         # Global Administrator

    def test_bad_shape_raises(self):
        with self.assertRaises(adapters.AdapterError):
            adapters.entra_role_assignments('{"no":"value"}')

    def test_end_to_end_reaches_admin(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = Store.create(os.path.join(tmp.name, "e.db"))
        self.addCleanup(store.close)
        store.init_engagement("ENTRA")
        g = adapters.entra_role_assignments(json.dumps(ENTRA), owned=["Helga"])
        saas.apply_saas(store, json.dumps(g))
        paths = saas.escalation_paths(store)
        self.assertTrue(paths)                          # Application Administrator → admin
        self.assertEqual(paths[0]["start"], "Helga")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
