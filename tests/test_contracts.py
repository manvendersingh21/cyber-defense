import copy
import json
import unittest
from pathlib import Path
from src.contracts import validate, paths

EXAMPLE = json.loads((Path(__file__).parents[1] / "examples/inventory-v1.json").read_text())

class ContractTests(unittest.TestCase):
    def test_example_is_valid(self):
        self.assertEqual(validate(EXAMPLE)["environment_id"], "lab-demo")
    def test_potential_path(self):
        p = paths(EXAMPLE)["paths"]
        self.assertEqual(p[0]["nodes"], ["external", "frontend", "canary"])
    def test_reject_unknown_asset(self):
        bad = copy.deepcopy(EXAMPLE)
        bad["relationships"][0]["target"] = "absent"
        with self.assertRaises(ValueError):
            validate(bad)
    def test_identity_permission_is_not_network_step(self):
        altered = copy.deepcopy(EXAMPLE)
        altered["relationships"][1]["relation"] = "CAN_ASSUME_ROLE"
        self.assertEqual(paths(altered)["paths"], [])
    def test_reject_duplicate(self):
        bad = copy.deepcopy(EXAMPLE)
        bad["assets"].append(dict(bad["assets"][0]))
        with self.assertRaises(ValueError):
            validate(bad)

if __name__ == "__main__":
    unittest.main()
