import unittest
import requests
import json
import os


class TestYaraAPI(unittest.TestCase):
    # Adjust if your server runs on a different host/port
    BASE_URL = "http://localhost:8080"

    def test_version_endpoint(self):
        """Test the GET / endpoint to retrieve the version."""
        url = f"{self.BASE_URL}/"
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "0.13.0")

    def test_json_convert_to_text(self):
        """Test the POST /json/convert_to_text endpoint."""
        url = f"{self.BASE_URL}/json/convert_to_text"
        yara_json = {
            "modules": [],
            "rules": [
                {
                    "name": "ExampleRule",
                    "private": False,
                    "global": False,
                    "tags": ["example"],
                    "meta": [
                        {"key": "author", "value": {"String": "John Doe"}},
                        {"key": "threshold", "value": {"Number": 10}}
                    ],
                    "strings": [
                        {"key": "$a", "value": "\"malware\""}
                    ],
                    "condition": "any of them"
                }
            ]
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers,
                                 json=yara_json)
        
        self.assertEqual(response.status_code, 200)

        response_json = response.json()
        self.assertIn("text", response_json)
        # You can add more detailed checks based on the expected YARA text output
        self.assertIsInstance(response_json["text"], str)
        self.assertGreater(len(response_json["text"]), 0)

    def test_text_convert_to_json(self):
        """Test the POST /text/convert_to_json endpoint."""
        url = f"{self.BASE_URL}/text/convert_to_json"
        yara_text = """
        rule ExampleRule : example{
            meta:
                author = "John Doe"
                threshold = 10
            strings:
                $a = "malware"
            condition:
                any of them
        }
        """
        payload = {"yara": yara_text.strip()}
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        self.assertEqual(response.status_code, 200)

        response_json = response.json()
        # Assuming the response JSON matches the YaraFile structure
        self.assertIn("name", response_json["rules"][0])
        self.assertEqual(response_json["rules"][0]["name"], "ExampleRule")
        self.assertIn("meta", response_json["rules"][0])
        self.assertIn("author", [meta['key'] for meta in response_json["rules"][0]["meta"]])
        self.assertIn("threshold", [meta['key'] for meta in response_json["rules"][0]["meta"]])
        self.assertIn("strings", response_json["rules"][0])
        self.assertIn("$a", [s['key'] for s in response_json["rules"][0]["strings"]])
        self.assertEqual(response_json["rules"][0]["strings"][0]["value"], "\"malware\"")

    def test_file_convert_to_json(self):
        """Test the POST /file/convert_to_json endpoint."""
        url = f"{self.BASE_URL}/file/convert_to_json"
        yara_text = """
        rule ExampleRule : example{
            meta:
                author = "John Doe"
                threshold = 10
            strings:
                $a = "malware"
            condition:
                any of them
        }
        """
        # Write the YARA text to a temporary file
        file_path = "temp_test_rule.yar"
        with open(file_path, "w") as f:
            f.write(yara_text.strip())

        # Open and send the file, ensuring it's properly closed
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file, 'application/octet-stream')}
            response = requests.post(url, files=files)

        # Clean up the temporary file
        os.remove(file_path)

        self.assertEqual(response.status_code, 200)

        response_json = response.json()
        # Assuming the response JSON matches the YaraFile structure
        self.assertIn("name", response_json["rules"][0])
        self.assertEqual(response_json["rules"][0]["name"], "ExampleRule")
        self.assertIn("meta", response_json["rules"][0])
        self.assertIn("author", [meta['key'] for meta in response_json["rules"][0]["meta"]])
        self.assertIn("threshold", [meta['key'] for meta in response_json["rules"][0]["meta"]])
        self.assertIn("strings", response_json["rules"][0])
        self.assertIn("$a", [s['key'] for s in response_json["rules"][0]["strings"]])
        self.assertEqual(response_json["rules"][0]["strings"][0]["value"], "\"malware\"")


if __name__ == "__main__":
    unittest.main()