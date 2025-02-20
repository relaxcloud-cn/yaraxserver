import unittest
import requests
import base64
import os

class TestAPIAdd(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"
        self.headers = {"Content-Type": "application/json"}

    def test_crud_rules(self):
        created_rule_id = 9
        # 4. 更新规则
        rule_route = f"/api/rule/delete/{created_rule_id}"
        rule_url = self.base_url + rule_route
        response = requests.delete(rule_url, headers=self.headers)
        self.assertEqual(response.status_code, 204, msg="DELETE /rules/delete/{id} should return 204")

if __name__ == '__main__':
    unittest.main()
