import unittest
import requests
import base64

class TestFlow1(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"
        self.headers = {"Content-Type": "application/json"}
        pass
    
    def tearDown(self):
        # 在每个测试方法后运行
        pass
    
    def test_get_all_rules(self):
        route = "/rules/all"
        url = self.base_url + route
        response = requests.get(url, headers=self.headers)
        print(response.status_code)
        print(response.json())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_crud_yara_file(self):
        # 1. First create a yara file
        route = "/yara_file/create"
        url = self.base_url + route

        compiled_data = base64.b64encode(b"compiled yara rule data").decode('utf-8')
        data = {
            "name": "test_rule",
            "version": 1,
            "compiled_data": compiled_data,
            "description": "Test yara rule description"
        }

        response = requests.post(url, json=data, headers=self.headers)
        self.assertEqual(response.status_code, 201)
        created_file = response.json()
        yara_file_id = created_file['id']

        # 2. Get the specific yara file
        route = f"/yara_file/one/{yara_file_id}"
        url = self.base_url + route
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['name'], "test_rule")

        # 3. Update the yara file
        route = f"/yara_file/update/{yara_file_id}"
        url = self.base_url + route
        update_data = {
            "name": "updated_test_rule",
            "version": 2,
            "compiled_data": base64.b64encode(b"updated compiled data").decode('utf-8'),
            "description": "Updated test description",
            "category": "new_type"
        }
        response = requests.put(url, json=update_data, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        updated_file = response.json()
        self.assertEqual(updated_file['name'], "updated_test_rule")
        self.assertEqual(updated_file['version'], 2)
        self.assertEqual(updated_file['description'], "Updated test description")
        self.assertEqual(updated_file['category'], "new_type")

        # 4. Get all yara files
        route = "/yara_file/all"
        url = self.base_url + route
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)

        # 5. Delete the yara file
        route = f"/yara_file/delete/{yara_file_id}"
        url = self.base_url + route
        response = requests.delete(url)
        self.assertEqual(response.status_code, 204)

        # 6. Verify deletion by trying to get the file
        route = f"/yara_file/one/{yara_file_id}"
        url = self.base_url + route
        response = requests.get(url)
        self.assertEqual(response.status_code, 404)



    # @unittest.skip("demonstrating skipping")
    # def test_nothing(self):
    #     self.fail("shouldn't happen")

if __name__ == '__main__':
    unittest.main()