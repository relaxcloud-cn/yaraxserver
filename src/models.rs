// src/models.rs

use crate::entity::sea_orm_active_enums::{Attribute, Sharing, Source};
use crate::tokenizer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRule {
    pub name: String,
    pub private: bool,
    pub global: bool,
    pub auth: Option<String>,
    pub description: Option<String>,
    pub tag: Option<Vec<String>>,
    pub strings: Option<Vec<String>>,
    pub condition: Option<String>,
    pub belonging: i32,
    pub verification: bool,
    pub source: Source,
    pub version: i32,
    pub sharing: Sharing,
    pub grayscale: bool,
    pub attribute: Attribute,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRule {
    pub name: Option<String>,
    pub private: Option<bool>,
    pub global: Option<bool>,
    pub auth: Option<String>,
    pub description: Option<String>,
    pub tag: Option<Vec<String>>,
    pub strings: Option<Vec<String>>,
    pub condition: Option<String>,
    pub belonging: Option<i32>,
    pub verification: Option<bool>,
    pub source: Option<Source>,
    pub version: Option<i32>,
    pub sharing: Option<Sharing>,
    pub grayscale: Option<bool>,
    pub attribute: Option<Attribute>,
}

#[derive(Deserialize, Serialize)]
pub struct UpdateYaraFile {
    pub name: Option<String>,
    pub last_modified_time: Option<chrono::DateTime<chrono::Utc>>,
    pub version: Option<i32>,
    #[serde(with = "base64_serde")]
    pub compiled_data: Option<Vec<u8>>,
    pub description: Option<String>,
    pub category: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct YaraFileWeb {
    pub name: String,
    pub last_modified_time: Option<chrono::DateTime<chrono::Utc>>,
    pub version: Option<i32>,
    #[serde(with = "base64_serde")]
    pub compiled_data: Option<Vec<u8>>,
    pub description: Option<String>,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub category: Option<String>,
}

mod base64_serde {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_str(&BASE64.encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => BASE64.decode(s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[derive(Deserialize)]
pub struct ApiCreate {
    pub category: String,
    pub name: String,
    pub version: i32,
    pub description: String,
    pub yara_file: tokenizer::YaraFile,
}

#[derive(Deserialize)]
pub struct ApiAdd {
    pub version: i32,
    pub yara_file_id: i32,
    pub yara_file: tokenizer::YaraFile,
}
