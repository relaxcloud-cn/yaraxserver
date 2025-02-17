use pest::Parser;
use pest_derive::Parser;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Parser)]
#[grammar = "yara.pest"]
struct YaraParser;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum MetaValue {
    String(String),
    Number(i64),
    Boolean(bool),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    key: String,
    value: MetaValue,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Strings {
    key: String,
    value: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub private: bool,
    pub global: bool,
    pub tags: Vec<String>,
    pub meta: Vec<Meta>,
    pub strings: Vec<Strings>,
    pub condition: String,
}

impl YaraRule {
    fn new() -> Self {
        YaraRule {
            name: String::new(),
            private: false,
            global: false,
            tags: Vec::new(),
            meta: Vec::new(),
            strings: Vec::new(),
            condition: String::new(),
        }
    }

    pub fn get_meta_string(&self, key: &str) -> String {
        let mut final_string = String::new();
        for i in &self.meta {
            if i.key == key {
                match &i.value {
                    MetaValue::String(v) => final_string += &v,
                    _ => {}
                }
            }
        }
        final_string
    }

    pub fn get_meta_number(&self, key: &str) -> i64 {
        let mut final_number = 0;
        for i in &self.meta {
            if i.key == key {
                match &i.value {
                    MetaValue::Number(v) => {
                        final_number = *v;
                        break;
                    }
                    _ => {}
                }
            }
        }
        final_number
    }

    pub fn get_meta_bool(&self, key: &str) -> bool {
        let mut final_bool = false;
        for i in &self.meta {
            if i.key == key {
                match &i.value {
                    MetaValue::Boolean(v) => {
                        final_bool = *v;
                        break;
                    }
                    _ => {}
                }
            }
        }
        final_bool
    }

    pub fn get_strings_vec(&self) -> Vec<String> {
        let mut v = vec![];
        for i in &self.strings {
            let string = format!("{} = {}", i.key, i.value);
            v.push(string);
        }
        v
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct YaraFile {
    pub modules: Vec<String>,
    pub rules: Vec<YaraRule>,
}

impl YaraFile {
    pub fn from_json(json: serde_json::Value) -> anyhow::Result<Self> {
        Ok(serde_json::from_value(json)?)
    }

    pub fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }
}

#[cfg(test)]
mod test_yara_file_json {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_json_serialization() -> anyhow::Result<()> {
        let yara_file = YaraFile {
            modules: vec!["pe".to_string()],
            rules: vec![YaraRule {
                name: "test_rule".to_string(),
                private: true,
                global: false,
                tags: vec!["tag1".to_string(), "tag2".to_string()],
                meta: vec![
                    Meta {
                        key: "description".to_string(),
                        value: MetaValue::String("Test description".to_string()),
                    },
                    Meta {
                        key: "author".to_string(),
                        value: MetaValue::String("Test Author".to_string()),
                    },
                    Meta {
                        key: "version".to_string(),
                        value: MetaValue::Number(1),
                    },
                    Meta {
                        key: "is_production".to_string(),
                        value: MetaValue::Boolean(false),
                    },
                ],
                strings: vec![
                    Strings {
                        key: "$a".to_string(),
                        value: "\"test string 1\"".to_string(),
                    },
                    Strings {
                        key: "$b".to_string(),
                        value: "\"test string 2\"".to_string(),
                    },
                ],
                condition: "any of them".to_string(),
            }],
        };

        let json_value = yara_file.to_json()?;
        let parsed_yara = YaraFile::from_json(json_value).unwrap();

        assert_eq!(yara_file, parsed_yara);

        Ok(())
    }

    #[test]
    fn test_json_deserialization() -> anyhow::Result<()> {
        let json_value = json!({
            "modules": ["pe"],
            "rules": [{
                "name": "test_rule",
                "private": true,
                "global": false,
                "tags": ["tag1", "tag2"],
                "meta": [
                    {
                        "key": "description",
                        "value": {"String": "Test description"}
                    },
                    {
                        "key": "version",
                        "value": {"Number": 1}
                    },
                    {
                        "key": "is_production",
                        "value": {"Boolean": false}
                    }
                ],
                "strings": [
                    {
                        "key": "$a",
                        "value": "\"test string\""
                    }
                ],
                "condition": "any of them"
            }]
        });

        let yara_file = YaraFile::from_json(json_value).unwrap();

        assert_eq!(yara_file.modules, vec!["pe"]);
        assert_eq!(yara_file.rules.len(), 1);

        let rule = &yara_file.rules[0];
        assert_eq!(rule.name, "test_rule");
        assert!(rule.private);
        assert!(!rule.global);
        assert_eq!(rule.tags, vec!["tag1", "tag2"]);
        assert_eq!(rule.meta.len(), 3);
        assert_eq!(rule.strings.len(), 1);
        assert_eq!(rule.condition, "any of them");

        let json_output = yara_file.to_json()?;
        let reparsed_yara = YaraFile::from_json(json_output).unwrap();

        assert_eq!(yara_file, reparsed_yara);

        Ok(())
    }

    #[test]
    fn test_rule_conversion_roundtrip() -> anyhow::Result<()> {
        let yara_str = r#"
import "pe"

private rule test_rule : tag1 tag2 {
    meta:
        description = "Test description"
        version = 1
        is_production = false
    strings:
        $a = "test string"
    condition:
        any of them
}
"#;

        let yara_file = YaraFile::from_str(yara_str).unwrap();
        let json_value = yara_file.to_json()?;
        let parsed_from_json = YaraFile::from_json(json_value).unwrap();
        let yara_str_final = parsed_from_json.to_string();
        let final_yara_file = YaraFile::from_str(&yara_str_final).unwrap();

        assert_eq!(yara_file, final_yara_file);

        Ok(())
    }
}

impl YaraFile {
    fn new() -> Self {
        YaraFile {
            modules: Vec::new(),
            rules: Vec::new(),
        }
    }
}

use std::fmt;
use std::str::FromStr;

impl FromStr for YaraFile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_yara_rule(s)
    }
}

impl fmt::Display for YaraFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Import modules
        for module in &self.modules {
            writeln!(f, "import \"{}\"", module)?;
        }
        if !self.modules.is_empty() {
            writeln!(f)?;
        }

        // Rules
        for rule in &self.rules {
            // Write restrictions
            if rule.private {
                write!(f, "private ")?;
            }
            if rule.global {
                write!(f, "global ")?;
            }

            // Write rule name and tags
            write!(f, "rule {}", rule.name)?;
            if !rule.tags.is_empty() {
                write!(f, " : {}", rule.tags.join(" "))?;
            }
            writeln!(f, " {{")?;

            // Meta section
            if !rule.meta.is_empty() {
                writeln!(f, "    meta:")?;
                for meta in &rule.meta {
                    match &meta.value {
                        MetaValue::String(s) => writeln!(f, "        {} = \"{}\"", meta.key, s)?,
                        MetaValue::Number(n) => writeln!(f, "        {} = {}", meta.key, n)?,
                        MetaValue::Boolean(b) => writeln!(f, "        {} = {}", meta.key, b)?,
                    }
                }
            }

            // Strings section
            if !rule.strings.is_empty() {
                writeln!(f, "    strings:")?;
                for string in &rule.strings {
                    writeln!(f, "        {} = {}", string.key, string.value)?;
                }
            }

            // Condition section
            writeln!(f, "    condition:")?;
            writeln!(f, "        {}", rule.condition)?;

            writeln!(f, "}}\n")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test_yara_file_methods {
    use super::*;

    #[test]
    fn yara_file_from_str() -> anyhow::Result<()> {
        let yara_str = r#"
        rule test {
            meta:
                description = "Test rule"
                author = "Test Author"
            strings:
                $a = "test string"
            condition:
                $a
        }"#;

        let yara_file = YaraFile::from_str(yara_str).unwrap();

        let expected_yara_file = YaraFile {
            modules: vec![],
            rules: vec![YaraRule {
                name: "test".to_string(),
                private: false,
                global: false,
                tags: vec![],
                meta: vec![
                    Meta {
                        key: "description".to_string(),
                        value: MetaValue::String("Test rule".to_string()),
                    },
                    Meta {
                        key: "author".to_string(),
                        value: MetaValue::String("Test Author".to_string()),
                    },
                ],
                strings: vec![Strings {
                    key: "$a".to_string(),
                    value: "\"test string\"".to_string(),
                }],
                condition: "$a".to_string(),
            }],
        };

        assert_eq!(yara_file, expected_yara_file);
        Ok(())
    }

    #[test]
    fn yara_file_to_string() -> anyhow::Result<()> {
        let yara_file = YaraFile {
            modules: vec![],
            rules: vec![YaraRule {
                name: "test".to_string(),
                private: false,
                global: false,
                tags: vec![],
                meta: vec![
                    Meta {
                        key: "description".to_string(),
                        value: MetaValue::String("Test rule".to_string()),
                    },
                    Meta {
                        key: "author".to_string(),
                        value: MetaValue::String("Test Author".to_string()),
                    },
                ],
                strings: vec![Strings {
                    key: "$a".to_string(),
                    value: "\"test string\"".to_string(),
                }],
                condition: "$a".to_string(),
            }],
        };

        let expected_string = r#"rule test {
    meta:
        description = "Test rule"
        author = "Test Author"
    strings:
        $a = "test string"
    condition:
        $a
}

"#;

        assert_eq!(yara_file.to_string(), expected_string.to_string());

        Ok(())
    }

    #[test]
    fn complex_yara_file_from_str() -> anyhow::Result<()> {
        let yara_str = r#"
        import "pe"
        import "something"

        private global rule test : my_test {
            meta:
                description = "Test rule"
                author = "Test Author"
                number = 1
            strings:
                $a = "test string"
            condition:
                $a
        }"#;

        let yara_file = YaraFile::from_str(yara_str).unwrap();

        let expected_yara_file = YaraFile {
            modules: vec!["pe".to_string(), "something".to_string()],
            rules: vec![YaraRule {
                name: "test".to_string(),
                private: true,
                global: true,
                tags: vec!["my_test".to_string()],
                meta: vec![
                    Meta {
                        key: "description".to_string(),
                        value: MetaValue::String("Test rule".to_string()),
                    },
                    Meta {
                        key: "author".to_string(),
                        value: MetaValue::String("Test Author".to_string()),
                    },
                    Meta {
                        key: "number".to_string(),
                        value: MetaValue::Number(1),
                    },
                ],
                strings: vec![Strings {
                    key: "$a".to_string(),
                    value: "\"test string\"".to_string(),
                }],
                condition: "$a".to_string(),
            }],
        };

        assert_eq!(yara_file, expected_yara_file);
        Ok(())
    }

    #[test]
    fn complex_yara_file_to_string() -> anyhow::Result<()> {
        let yara_file = YaraFile {
            modules: vec!["pe".to_string(), "something".to_string()],
            rules: vec![YaraRule {
                name: "test".to_string(),
                private: true,
                global: true,
                tags: vec!["my_test".to_string()],
                meta: vec![
                    Meta {
                        key: "description".to_string(),
                        value: MetaValue::String("Test rule".to_string()),
                    },
                    Meta {
                        key: "author".to_string(),
                        value: MetaValue::String("Test Author".to_string()),
                    },
                    Meta {
                        key: "number".to_string(),
                        value: MetaValue::Number(1),
                    },
                ],
                strings: vec![Strings {
                    key: "$a".to_string(),
                    value: "\"test string\"".to_string(),
                }],
                condition: "$a".to_string(),
            }],
        };

        let expected_string = r#"import "pe"
import "something"

private global rule test : my_test {
    meta:
        description = "Test rule"
        author = "Test Author"
        number = 1
    strings:
        $a = "test string"
    condition:
        $a
}

"#;

        assert_eq!(yara_file.to_string(), expected_string.to_string());

        Ok(())
    }
}

fn parse_yara_rule(input: &str) -> anyhow::Result<YaraFile> {
    let mut yara_file = YaraFile::new();

    let pairs = YaraParser::parse(Rule::file, input)?;

    for pair in pairs {
        match pair.as_rule() {
            Rule::file => {
                for rule_pair in pair.into_inner() {
                    match rule_pair.as_rule() {
                        Rule::module => {
                            // string --> inner --> .tosting
                            yara_file.modules.push(
                                rule_pair
                                    .into_inner()
                                    .next() // string
                                    .unwrap()
                                    .into_inner()
                                    .next() // inner
                                    .unwrap()
                                    .as_str()
                                    .to_string(),
                            );
                        }
                        Rule::rule => {
                            let mut yara_rule = YaraRule::new();

                            for inner_pair in rule_pair.into_inner() {
                                match inner_pair.as_rule() {
                                    Rule::restriction => match inner_pair.as_str() {
                                        "global" => {
                                            yara_rule.global = true;
                                        }
                                        "private" => {
                                            yara_rule.private = true;
                                        }
                                        &_ => todo!(),
                                    },
                                    Rule::rule_name => {
                                        yara_rule.name = inner_pair.as_str().to_string();
                                    }
                                    Rule::tags => {
                                        yara_rule.tags = inner_pair
                                            .into_inner()
                                            .map(|tag| tag.as_str().to_string())
                                            .collect();
                                    }
                                    Rule::meta_block => {
                                        for meta_pair in inner_pair.into_inner() {
                                            if meta_pair.as_rule() == Rule::meta_pair {
                                                let mut meta_iter = meta_pair.into_inner();
                                                let key =
                                                    meta_iter.next().unwrap().as_str().to_string();
                                                let value = meta_iter.next().unwrap().as_str();
                                                yara_rule.meta.push(Meta {
                                                    key: key,
                                                    value: parse_meta_value(value),
                                                });
                                            }
                                        }
                                    }
                                    Rule::strings_block => {
                                        for string_def in inner_pair.into_inner() {
                                            if string_def.as_rule() == Rule::string_definition {
                                                let mut string_iter = string_def.into_inner();
                                                let id = string_iter
                                                    .next()
                                                    .unwrap()
                                                    .as_str()
                                                    .to_string();
                                                let value = string_iter
                                                    .next()
                                                    .unwrap()
                                                    .as_str()
                                                    .to_string();
                                                yara_rule.strings.push(Strings {
                                                    key: id,
                                                    value: value,
                                                });
                                            }
                                        }
                                    }
                                    Rule::condition_block => {
                                        yara_rule.condition = inner_pair
                                            .into_inner()
                                            .next()
                                            .unwrap()
                                            .as_str()
                                            .trim()
                                            .to_string();
                                    }
                                    _ => {}
                                }
                            }
                            yara_file.rules.push(yara_rule);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Ok(yara_file)
}

fn parse_meta_value(value: &str) -> MetaValue {
    if value.starts_with('"') && value.ends_with('"') {
        MetaValue::String(value[1..value.len() - 1].to_string())
    } else if value == "true" {
        MetaValue::Boolean(true)
    } else if value == "false" {
        MetaValue::Boolean(false)
    } else {
        MetaValue::Number(value.parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_string() -> anyhow::Result<()> {
        let input = "{ 4D 5A 90 00 } trailing \n";
        let pairs = YaraParser::parse(Rule::hex_string, input)?;
        println!("{}", pairs.as_str());
        Ok(())
    }

    // #[test]
    // fn test_hex_string_with_newline() -> anyhow::Result<()> {
    //     let input = "{ 4D 5A 90 00 } trailing \n";
    //     let pairs = YaraParser::parse(Rule::hex_string_with_newline, input)?;
    //     println!("{}", pairs.as_str());
    //     Ok(())
    // }

    #[test]
    fn test_literal_string() -> anyhow::Result<()> {
        let input = "\"something\" \n";
        let pairs = YaraParser::parse(Rule::text_string, input)?;
        println!("{}", pairs);
        Ok(())
    }

    // #[test]
    // fn test_string_literal_with_newline() -> anyhow::Result<()> {
    //     let input = "\"something\" xor wide \n";
    //     let pairs = YaraParser::parse(Rule::string_literal_with_newline, input)?;
    //     println!("{}", pairs);
    //     println!("{}", pairs.as_str());
    //     Ok(())
    // }

    #[test]
    fn test_regular_string() -> anyhow::Result<()> {
        let input = "/md5: [0-9a-fA-F]{32}/ \n";
        let pairs = YaraParser::parse(Rule::regular_string, input)?;
        println!("{}", pairs);
        println!("{}", pairs.as_str());
        Ok(())
    }

    #[test]
    fn test_3_categories_string() -> anyhow::Result<()> {
        let input = r#"strings:
            $text = "foobar\n"
            $hex = { E2 34 ?? C8 A? FB }
            $ = /md5: [0-9a-fA-F]{32}/
            $re2 = /state: (on|off)/
            "#;
        let pairs = YaraParser::parse(Rule::strings_block, input)?;
        println!("{}", pairs);
        println!("{}", pairs.as_str());
        Ok(())
    }

    #[test]
    fn test_rule() -> anyhow::Result<()> {
        let input = r#"rule ExampleRule : Tag1 Tag2 {
                meta:
                    description = "Example rule"
                    author = "Example Author"
                
                strings:
                    $string1 = "test string"
                    $hex1 = { 4D 5A 90 00 }
                
                condition:
                    $string1 and $hex1
            }"#;
        let pairs = YaraParser::parse(Rule::rule, input)?;
        println!("{}", pairs);
        println!("{}", pairs.as_str());
        Ok(())
    }

    #[test]
    fn test_basic_rule() {
        let yara_rule = r#"rule ExampleRule : Tag1  Tag2 {
                meta:
                    description = "Example rule"
                    author = "Example Author"
                
                strings:
                    $string1 = "test string"
                    $hex1 = { 4D 5A 90 00 }
                
                condition:
                    $string1 and $hex1
            }"#;

        let yara_file = parse_yara_rule(yara_rule).unwrap();
        let rules = yara_file.rules;
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.name, "ExampleRule");
        assert_eq!(rule.tags, vec!["Tag1", "Tag2"]);
        assert_eq!(
            rule.meta[0].value,
            MetaValue::String("Example rule".to_string())
        );
        assert_eq!(
            rule.meta[1].value,
            MetaValue::String("Example Author".to_string())
        );
        assert_eq!(rule.strings[0].key, "$string1");
        assert_eq!(rule.strings[0].value, "\"test string\"");
        // println!("{}", rule.condition);
    }

    #[test]
    fn test_module() {
        let input = r#"import "pe" "#;
        let r = YaraParser::parse(Rule::module, input).unwrap();
        println!("{}", r.as_str());
    }

    #[test]
    fn test_advance_rule() {
        let yara_rule = r#"
        import "pe"

        private global rule ExampleRule : Tag1 Tag2 {
                meta:
                    description = "Example rule"
                    author = "Example Author"
                
                strings:
                    $string1 = "test string"
                    $hex1 = { 4D 5A 90 00 }
                
                condition:
                    $string1 and $hex1
            }"#;

        let yara_file = parse_yara_rule(yara_rule).unwrap();
        let rules = yara_file.rules;
        assert_eq!(rules.len(), 1);

        assert_eq!(yara_file.modules[0], "pe");
        let rule = &rules[0];
        assert_eq!(rule.private, true);
        assert_eq!(rule.global, true);
        assert_eq!(rule.name, "ExampleRule");
        assert_eq!(rule.tags, vec!["Tag1", "Tag2"]);
        assert_eq!(
            rule.meta[0].value,
            MetaValue::String("Example rule".to_string())
        );
        assert_eq!(
            rule.meta[1].value,
            MetaValue::String("Example Author".to_string())
        );
        assert_eq!(rule.strings[0].key, "$string1");
        assert_eq!(rule.strings[0].value, "\"test string\"");
    }

    #[test]
    fn test_rule_without_tags() {
        let yara_rule = r#"
            rule NoTags {
                meta:
                    description = "Rule without tags"
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let yara_file = parse_yara_rule(yara_rule).unwrap();
        let rules = yara_file.rules;
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.name, "NoTags");
        assert!(rule.tags.is_empty());
        assert_eq!(
            rule.meta[0].value,
            MetaValue::String("Rule without tags".to_string())
        );
    }

    #[test]
    fn test_rule_without_meta() {
        let yara_rule = r#"
            rule NoMeta {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#;

        let yara_file = parse_yara_rule(yara_rule).unwrap();
        let rules = yara_file.rules;
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.name, "NoMeta");
        assert!(rule.meta.is_empty());
    }

    #[test]
    fn test_rule_without_strings() {
        let yara_rule = r#"
            rule NoStrings {
                meta:
                    description = "Rule without strings"
                condition:
                    true
            }
        "#;

        let yara_file = parse_yara_rule(yara_rule).unwrap();
        let rules = yara_file.rules;
        assert_eq!(rules.len(), 1);

        let rule = &rules[0];
        assert_eq!(rule.name, "NoStrings");
        assert!(rule.strings.is_empty());
        assert_eq!(rule.condition.trim(), "true");
    }

    #[test]
    fn test_multiple_rules() {
        let yara_rule = r#"
            rule Rule1 {
                condition:
                    true
            }

            rule Rule2 {
                condition:
                    false
            }
        "#;

        let yara_file = parse_yara_rule(yara_rule).unwrap();
        let rules = yara_file.rules;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "Rule1");
        assert_eq!(rules[1].name, "Rule2");
    }

    #[test]
    fn test_invalid_rule() {
        let invalid_rule = r#"
            rule InvalidRule {
                // Missing condition block
            }
        "#;

        assert!(parse_yara_rule(invalid_rule).is_err());
    }

    #[test]
    fn test_complex_meta_values() {
        let yara_rule = r#"
            rule ComplexMeta {
                meta:
                    description = "Complex rule"
                    score = 100
                    is_active = true
                condition:
                    true
            }
        "#;

        let yara_file = parse_yara_rule(yara_rule).unwrap();
        let rules = yara_file.rules;
        let rule = &rules[0];
        assert_eq!(
            rule.meta[0].value,
            MetaValue::String("Complex rule".to_string())
        );
        assert_eq!(rule.meta[1].value, MetaValue::Number(100));
        assert_eq!(rule.meta[2].value, MetaValue::Boolean(true));
    }
}
