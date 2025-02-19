import unittest
import requests
import base64
import os

class TestAPIAdd(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"
        self.headers = {"Content-Type": "application/json"}

    def test_crud_rules(self):
        created_rule_id = 10
        # 4. 更新规则
        update_rule_route = f"/api/update/{created_rule_id}"
        update_rule_url = self.base_url + update_rule_route
        update_data = {
            "name": "updated_test_rule",
            "private": False,
            "global": True,
            "auth": "updated_auth_content",
            "description": "Updated test rule description",
            "tag": ["tag3"],
            "strings": ["$c = \"updated\"", "$d = /example/"],
            "condition": "all of them",
            "verification": False,
            "source": "local",       
            "version": 2,
            "sharing": "TLP:Green",     # 根据实际枚举值调整
            "grayscale": True,
            "attribute": "black"       # 根据实际枚举值调整
        }

        response = requests.put(update_rule_url, json=update_data, headers=self.headers)
        print(response.text)
        self.assertEqual(response.status_code, 200, msg="PUT /api/update/{id} should return 200")
        updated_rule = response.json()
        self.assertEqual(updated_rule['name'], "updated_test_rule", msg="Rule name should be updated")
        self.assertEqual(updated_rule['private'], False, msg="Rule private field should be updated")
        self.assertEqual(updated_rule['global'], True, msg="Rule global field should be updated")
        self.assertEqual(updated_rule['auth'], "updated_auth_content", msg="Rule auth field should be updated")
        self.assertEqual(updated_rule['description'], "Updated test rule description", msg="Rule description should be updated")
        self.assertEqual(updated_rule['tag'], ["tag3"], msg="Rule tag should be updated")
        self.assertEqual(updated_rule['strings'], ["$c = \"updated\"", "$d = /example/"], msg="Rule strings should be updated")
        self.assertEqual(updated_rule['condition'], "all of them", msg="Rule condition should be updated")
        self.assertEqual(updated_rule['verification'], False, msg="Rule verification should be updated")
        self.assertEqual(updated_rule['source'], "local", msg="Rule source should be updated")
        self.assertEqual(updated_rule['version'], 2, msg="Rule version should be updated")
        self.assertEqual(updated_rule['sharing'], "TLP:Green", msg="Rule sharing should be updated")
        self.assertEqual(updated_rule['grayscale'], True, msg="Rule grayscale should be updated")
        self.assertEqual(updated_rule['attribute'], "black", msg="Rule attribute should be updated")


if __name__ == '__main__':
    unittest.main()