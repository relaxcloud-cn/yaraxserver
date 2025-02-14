import unittest
import requests


class TestFlow1(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"
        self.headers = {"Content-Type": "application/json"}

    def test_get_all_rules(self):
        route = "/api/create"
        url = self.base_url + route
        # json_data = {
        #     "category": "test",
        #     "name": "test_yara_file",
        #     "version": 1,
        #     "description": "testing",
        #     "yara_file": {
        #         "modules": ["pe"],
        #         "rules": [{
        #             "name": "test_rule",
        #             "private": True,
        #             "global": False,
        #             "auth": "auth_content",
        #             "description": "Test rule description",
        #             "tags": ["tag1", "tag2"],
        #             "strings": [
        #                 {"key": "$a", "value": "hello"},
        #                 {"key": "$b", "value": "/world/"}
        #             ],
        #             "condition": "any of them",
        #             "belonging": "",
        #             "verification": True,
        #             "source": "official",
        #             "version": 1,
        #             "sharing": "TLP:Red",
        #             "grayscale": False,
        #             "attribute": "white"
        #         }]
        #     }
        # }
        json_data = {
            "category": "test",
            "name": "test_yara_file",
            "version": 1,
            "description": "testing",
            "yara_file": {
                "modules": ["pe"],
                "rules": [{
                    "name": "test_rule",
                    "private": True,
                    "global": False,
                    "meta": {
                        "key": "is_production",
                        "value": {"Boolean": False}
                    },
                    "auth": "auth_content",
                    "description": "Test rule description",
                    "tags": ["tag1", "tag2"],
                    "strings": [
                        {"key": "$a", "value": "hello"},
                        {"key": "$b", "value": "/world/"}
                    ],
                    "condition": "any of them",
                    "belonging": "",
                    "verification": True,
                    "source": "official",
                    "version": 1,
                    "sharing": "TLP:Red",
                    "grayscale": False,
                    "attribute": "white"
                }]
            }
        }
        response = requests.post(url, headers=self.headers, json=json_data)
        print(response.status_code)
        print(response.text)
        print(response.json())


if __name__ == '__main__':
    unittest.main()
