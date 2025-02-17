# 创建规则接口

## POST /api/create

### 参数

#### 输入示例

```json
{
    "category": "test",
    "name": "test_yara_file",
    "version": 1,
    "description": "testing",
    "yara_file": {
        "modules": [
            "pe"
        ],
        "rules": [
            {
                "name": "test_rule",
                "private": true,
                "global": false,
                "tags": [
                    "tag1",
                    "tag2"
                ],
                "meta": [
                    {
                        "key": "is_production",
                        "value": {
                            "Boolean": false
                        }
                    },
                    {
                        "key": "verification",
                        "value": {
                            "Boolean": true
                        }
                    },
                    {
                        "key": "source",
                        "value": {
                            "String": "official"
                        }
                    },
                    {
                        "key": "sharing",
                        "value": {
                            "String": "TLP:Red"
                        }
                    },
                    {
                        "key": "grayscale",
                        "value": {
                            "Boolean": false
                        }
                    },
                    {
                        "key": "attribute",
                        "value": {
                            "String": "white"
                        }
                    },
                    {
                        "key": "auth",
                        "value": {
                            "String": "auth_content"
                        }
                    },
                    {
                        "key": "description",
                        "value": {
                            "String": "Test rule description"
                        }
                    }
                ],
                "strings": [
                    {
                        "key": "$a",
                        "value": "\"hello\""
                    },
                    {
                        "key": "$b",
                        "value": "/world/"
                    }
                ],
                "condition": "any of them"
            }
        ]
    }
}
```

#### 输出示例

```json
{
    "yara_file_id": 24,
    "rules_id": [
        8
    ]
}
```