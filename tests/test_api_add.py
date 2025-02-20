import unittest
import requests


class TestAPIAdd(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"
        self.headers = {"Content-Type": "application/json"}

    def test_get_all_rules(self):
        route = "/api/add"
        url = self.base_url + route
        json_data = {
            "version": 2,
            "yara_file_id" : 24,
            "yara_file": {
                "modules": ["pe"],
                "rules": [{
                    "name": "test_rule_13",
                    "private": True,
                    "global": False,
                    "tags": ["tag1", "tag2"],
                    "meta": [
                        {
                            "key": "is_production",
                            "value": {"Boolean": False}
                        },
                        {
                            "key": "verification",
                            "value": {"Boolean": True}
                        },
                        {
                            "key": "source",
                            "value": {"String": 'official'}
                        },
                        {
                            "key": "sharing",
                            "value": {"String": 'TLP:Red'}
                        },
                        {
                            "key": "grayscale",
                            "value": {"Boolean": False}
                        },
                        {
                            "key": "attribute",
                            "value": {"String": "white"}
                        },
                        {
                            "key": "auth",
                            "value": {"String": "auth_content"}
                        },
                        {
                            "key": "description",
                            "value": {"String": "Test rule description"}
                        },
                    ],
                    "strings": [
                        {"key": "$a", "value": "\"hello\""},
                        {"key": "$b", "value": "/world/"}
                    ],
                    "condition": "any of them",
                }]
            }
        }
        
        response = requests.post(url, headers=self.headers, json=json_data)
        print(response.status_code)
        print(response.text)
        print(response.json())


if __name__ == '__main__':
    unittest.main()
