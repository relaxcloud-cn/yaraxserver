import unittest
import requests

class TestApiReload(unittest.TestCase):
    BASE_URL = "http://localhost:8080"

    def test_api_reload_success(self):
        """测试触发热更新成功的场景"""
        url = f"{self.BASE_URL}/api/reload"
        response = requests.post(url)
        # 检查返回状态码是否为200
        self.assertEqual(response.status_code, 200)
        # 检查返回内容中是否包含成功信息
        self.assertIn("Hot update triggered successfully!", response.text)


if __name__ == '__main__':
    unittest.main()