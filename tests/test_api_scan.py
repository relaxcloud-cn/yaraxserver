import unittest
import requests
import io

class TestScanApi(unittest.TestCase):
    def setUp(self):
        self.url = 'http://localhost:8080/api/scan'
        self.malicious_content = """
        X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

        world

        
        """
        self.file_obj = io.BytesIO(self.malicious_content.encode('utf-8'))
        self.files = {
            'file': ('malware_sample.txt', self.file_obj, 'text/plain')
        }
        self.data = {
            'category': 'test', 
            'strelka_style': 'true'
        }

    def test_scan_endpoint(self):
        try:
            response = requests.post(self.url, files=self.files, data=self.data)
            print(response.text)
            # self.assertEqual(response.status_code, 200, "HTTP status code should be 200")
            
            # response_json = response.json()
            # self.assertIn('log', response_json, "Response should contain 'log' field")
            
        except Exception as e:
            self.fail(f"Test failed with error: {str(e)}")

    def tearDown(self):
        self.file_obj.close()

if __name__ == '__main__':
    unittest.main()