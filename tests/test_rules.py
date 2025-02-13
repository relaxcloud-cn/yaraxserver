import unittest
import requests
import base64
import os

class TestRules(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"
        self.headers = {"Content-Type": "application/json"}

        # 创建一个 Yara 文件，以便在创建规则时使用
        create_yara_file_route = "/yara_file/create"
        create_yara_file_url = self.base_url + create_yara_file_route

        compiled_data = base64.b64encode(b"test compiled data").decode('utf-8')
        self.yarafile_data = {
            "name": "test_yarafile",
            "version": 1,
            "compiled_data": compiled_data,
            "description": "Test yara file for rules testing"
        }

        response = requests.post(create_yara_file_url, json=self.yarafile_data, headers=self.headers)
        self.assertEqual(response.status_code, 201, msg="Failed to create yara_file in setUp")
        created_yarafile = response.json()
        self.yarafile_id = created_yarafile.get('id')
        self.assertIsNotNone(self.yarafile_id, msg="Yara file ID should not be None")

    def tearDown(self):
        # 删除在 setUp 中创建的 Yara 文件
        delete_yarafile_route = f"/yara_file/delete/{self.yarafile_id}"
        delete_yarafile_url = self.base_url + delete_yarafile_route
        response = requests.delete(delete_yarafile_url, headers=self.headers)
        self.assertIn(response.status_code, [204, 404], msg="Failed to delete yara_file in tearDown")

    def test_crud_rules(self):
        # 1. 获取所有规则，初始应为空
        get_all_rules_route = "/rules/all"
        get_all_rules_url = self.base_url + get_all_rules_route
        response = requests.get(get_all_rules_url, headers=self.headers)
        self.assertEqual(response.status_code, 200, msg="GET /rules/all should return 200")
        self.assertIsInstance(response.json(), list, msg="GET /rules/all should return a list")
        initial_rules = response.json()
        initial_count = len(initial_rules)

        # 2. 创建一个新的规则
        create_rule_route = "/rules/create"
        create_rule_url = self.base_url + create_rule_route

        # 请根据 `sea_orm_active_enums` 中的枚举类型，调整以下字段的值
        # 假设 Source 有 'User', 'System'，Sharing 有 'Public', 'Private'，Attribute 有 'Binary', 'Text'
        rule_data = {
            "name": "test_rule",
            "private": True,
            "global": False,
            "auth": "auth_content",
            "description": "Test rule description",
            "tag": ["tag1", "tag2"],
            "strings": ["$a = \"hello\"", "$b = /world/"],
            "condition": "any of them",
            "belonging": self.yarafile_id,
            "verification": True,
            "source": "official",       # 根据实际枚举值调整
            "version": 1,
            "sharing": "TLP:Red",    # 根据实际枚举值调整
            "grayscale": False,
            "attribute": "white" 
        }

        response = requests.post(create_rule_url, json=rule_data, headers=self.headers)
        self.assertEqual(response.status_code, 201, msg="POST /rules/create should return 201")
        created_rule = response.json()
        created_rule_id = created_rule.get('id')
        self.assertIsNotNone(created_rule_id, msg="Created rule ID should not be None")

        # 3. 获取所有规则，确认新规则存在
        response = requests.get(get_all_rules_url, headers=self.headers)
        self.assertEqual(response.status_code, 200, msg="GET /rules/all should return 200 after creation")
        rules = response.json()
        self.assertEqual(len(rules), initial_count + 1, msg="Rule count should have incremented by 1")
        created_rule_in_list = next((rule for rule in rules if rule['id'] == created_rule_id), None)
        self.assertIsNotNone(created_rule_in_list, msg="Created rule should exist in the list")
        self.assertEqual(created_rule_in_list['name'], "test_rule", msg="Rule name should match")

        # 4. 查询单个规则
        get_single_rule_route = f"/rules/one/{created_rule_id}"
        get_single_rule_url = self.base_url + get_single_rule_route
        response = requests.get(get_single_rule_url, headers=self.headers)
        self.assertEqual(response.status_code, 200, msg="GET /rules/one/{id} should return 200")
        single_rule = response.json()
        self.assertEqual(single_rule['id'], created_rule_id, msg="Fetched rule ID should match")
        self.assertEqual(single_rule['name'], "test_rule", msg="Fetched rule name should match")
        self.assertEqual(single_rule['private'], True, msg="Fetched rule private field should match")
        self.assertEqual(single_rule['global'], False, msg="Fetched rule global field should match")
        self.assertEqual(single_rule['auth'], "auth_content", msg="Fetched rule auth field should match")
        self.assertEqual(single_rule['description'], "Test rule description", msg="Fetched rule description should match")
        self.assertEqual(single_rule['tag'], ["tag1", "tag2"], msg="Fetched rule tags should match")
        self.assertEqual(single_rule['strings'], ["$a = \"hello\"", "$b = /world/"], msg="Fetched rule strings should match")
        self.assertEqual(single_rule['condition'], "any of them", msg="Fetched rule condition should match")
        self.assertEqual(single_rule['belonging'], self.yarafile_id, msg="Fetched rule belonging should match")
        self.assertEqual(single_rule['verification'], True, msg="Fetched rule verification should match")
        self.assertEqual(single_rule['source'], "official", msg="Fetched rule source should match")
        self.assertEqual(single_rule['version'], 1, msg="Fetched rule version should match")
        self.assertEqual(single_rule['sharing'], "TLP:Red", msg="Fetched rule sharing should match")
        self.assertEqual(single_rule['grayscale'], False, msg="Fetched rule grayscale should match")
        self.assertEqual(single_rule['attribute'], "white", msg="Fetched rule attribute should match")

        # 4. 更新规则
        update_rule_route = f"/rules/update/{created_rule_id}"
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
        self.assertEqual(response.status_code, 200, msg="PUT /rules/update/{id} should return 200")
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

        # 5. 删除规则
        delete_rule_route = f"/rules/delete/{created_rule_id}"
        delete_rule_url = self.base_url + delete_rule_route
        response = requests.delete(delete_rule_url, headers=self.headers)
        self.assertEqual(response.status_code, 204, msg="DELETE /rules/delete/{id} should return 204")

        # 6. 验证删除：获取所有规则，确保已删除
        response = requests.get(get_all_rules_url, headers=self.headers)
        self.assertEqual(response.status_code, 200, msg="GET /rules/all should return 200 after deletion")
        rules_after_deletion = response.json()
        self.assertEqual(len(rules_after_deletion), initial_count, msg="Rule count should be back to initial after deletion")
        deleted_rule = next((rule for rule in rules_after_deletion if rule['id'] == created_rule_id), None)
        self.assertIsNone(deleted_rule, msg="Deleted rule should not exist in the list")

    # 可选：添加更多测试用例，例如测试无效输入、权限验证等

if __name__ == '__main__':
    unittest.main()