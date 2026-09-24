import unittest

from core.metasploit_mapper import MSF_DATABASE


class MetasploitMappingTests(unittest.TestCase):
    def test_documented_module_and_service_mapping_counts(self):
        unique_modules = {
            item["module"]
            for suggestions in MSF_DATABASE.values()
            for item in suggestions
        }

        self.assertEqual(len(unique_modules), 48)
        self.assertEqual(len(MSF_DATABASE), 20)


if __name__ == "__main__":
    unittest.main()
