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
    

    def test_crud_yara_file(self):
        yara_file_id = 24

        # 5. Delete the yara file
        route = f"/api/yara_file/delete/{yara_file_id}"
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