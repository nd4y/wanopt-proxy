import unittest

from host_profile import replace_profile_branch


SOURCE = """if act=='setup':
 effect='setup'
elif act=='profile':
 if mode=='old':effect='old profile'
 else:effect='other profile'
elif act=='config':
 effect='configuration written'
elif act=='mtu':
 effect='MTU changed'
else:
 effect='unknown'
"""


class HostProfileReplacement(unittest.TestCase):
    def test_replacement_preserves_configuration_and_other_actions(self):
        updated = replace_profile_branch(SOURCE, "elif act=='profile':\n effect='capped profile'\n")
        for action, expected in [("setup", "setup"), ("profile", "capped profile"),
                                 ("config", "configuration written"), ("mtu", "MTU changed"),
                                 ("missing", "unknown")]:
            with self.subTest(action=action):
                state = {"act": action}
                exec(updated, state)
                self.assertEqual(state["effect"], expected)

    def test_missing_or_ambiguous_profile_is_rejected(self):
        for source in [SOURCE.replace("elif act=='profile':", "elif act=='another':"),
                       SOURCE.replace("elif act=='config':", "elif act=='profile':")]:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    replace_profile_branch(source, "elif act=='profile':\n pass\n")
