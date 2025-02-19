mod tokenizer;
mod yara;
use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use mimalloc::MiMalloc;
use sea_orm::ActiveValue::NotSet;
use serde_json::json;
use std::{io::Read, str::FromStr};
mod entity;
mod models;
use crate::entity::{prelude::*, yara_file, yara_rules};
use crate::models::{CreateRule, UpdateRule, UpdateYaraFile, YaraFileWeb};
use chrono::Utc;
use dotenvy::dotenv;
use entity::prelude::*;
use sea_orm::IntoActiveModel;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, ModelTrait,
    QueryFilter, Set,
};
use tokenizer::Meta;

use std::env;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};

#[derive(Debug, serde::Deserialize)]
struct ConvertToJSONRequestBody {
    yara: String,
    // field2: i32,
}

#[get("/")]
async fn version() -> impl Responder {
    HttpResponse::Ok().body("0.13.0")
}

#[post("/json/convert_to_text")]
async fn json_convert_to_text(req_body: web::Json<tokenizer::YaraFile>) -> impl Responder {
    let request_body = req_body.into_inner();
    HttpResponse::Ok().json(json!({"text": request_body.to_string()}))
}

#[post("/text/convert_to_json")]
async fn convert_to_json(req_body: web::Json<ConvertToJSONRequestBody>) -> impl Responder {
    let request_body = req_body.into_inner();
    let yara_str = request_body.yara;
    let response_str;
    match tokenizer::YaraFile::from_str(&yara_str) {
        Ok(yara_file) => match yara_file.to_json() {
            Ok(o) => response_str = o,
            Err(e) => return HttpResponse::Ok().json(json!({"message": e.to_string()})),
        },
        Err(e) => return HttpResponse::Ok().json(json!({"message": e.to_string()})),
    }
    HttpResponse::Ok().json(response_str)
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    #[multipart(limit = "100MB")]
    file: TempFile,
}

#[post("/file/convert_to_json")]
pub async fn file_convert_to_json(
    MultipartForm(mut form): MultipartForm<UploadForm>,
) -> impl Responder {
    let mut buffer = vec![];
    let response_str;
    let _ = form.file.file.read_to_end(&mut buffer);
    let s = String::from_utf8(buffer);
    match s {
        Ok(str) => match tokenizer::YaraFile::from_str(&str) {
            Ok(yara_file) => match yara_file.to_json() {
                Ok(o) => response_str = o,
                Err(e) => return HttpResponse::Ok().json(json!({"message": e.to_string()})),
            },
            Err(e) => return HttpResponse::Ok().json(json!({"message": e.to_string()})),
        },
        Err(e) => return HttpResponse::Ok().json(json!({"message": e.to_string()})),
    }
    HttpResponse::Ok().json(response_str)
}

#[get("/rules/all")]
async fn get_all_rules(db: web::Data<DatabaseConnection>) -> impl Responder {
    let rules: Vec<yara_rules::Model> = YaraRules::find().all(db.get_ref()).await.unwrap();
    HttpResponse::Ok().json(rules)
}

#[get("/rules/one/{id}")]
async fn get_rule_by_id(db: web::Data<DatabaseConnection>, path: web::Path<i32>) -> impl Responder {
    let rule_id = path.into_inner();
    match YaraRules::find_by_id(rule_id).one(db.get_ref()).await {
        Ok(Some(rule)) => HttpResponse::Ok().json(rule),
        Ok(None) => HttpResponse::NotFound().json(json!({"message": "Rule not found"})),
        Err(e) => {
            eprintln!("Error fetching rule: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

#[post("/rules/create")]
async fn create_rule(
    db: web::Data<DatabaseConnection>,
    item: web::Json<CreateRule>,
) -> impl Responder {
    let new_rule = yara_rules::ActiveModel {
        id: NotSet,
        name: Set(item.name.clone()),
        private: Set(Some(item.private)),
        global: Set(Some(item.global)),
        auth: Set(item.auth.clone()),
        description: Set(item.description.clone()),
        tag: Set(item.tag.clone()),
        strings: Set(item.strings.clone()),
        condition: Set(item.condition.clone()),
        last_modified_time: Set(chrono::Utc::now().into()),
        loading_time: Set(None),
        belonging: Set(item.belonging),
        verification: Set(Some(item.verification)),
        source: Set(Some(item.source.clone())),
        version: Set(Some(item.version)),
        sharing: Set(Some(item.sharing.clone())),
        grayscale: Set(Some(item.grayscale)),
        attribute: Set(Some(item.attribute.clone())),
        created_at: NotSet,
        updated_at: NotSet,
    };

    let res = YaraRules::insert(new_rule).exec(db.get_ref()).await;

    match res {
        Ok(inserted) => HttpResponse::Created().json(json!({"id":inserted.last_insert_id})),
        Err(e) => HttpResponse::InternalServerError().json(json!({"message": e.to_string()})),
    }
}

#[put("/rules/update/{id}")]
async fn update_rule(
    db: web::Data<DatabaseConnection>,
    path: web::Path<i32>,
    item: web::Json<UpdateRule>,
) -> impl Responder {
    let rule_id = path.into_inner();

    let rule: Option<yara_rules::Model> = YaraRules::find_by_id(rule_id)
        .one(db.get_ref())
        .await
        .unwrap();

    if rule.is_none() {
        return HttpResponse::NotFound().body("Rule not found");
    }

    let mut active_rule: yara_rules::ActiveModel = rule.unwrap().into();

    if let Some(name) = &item.name {
        active_rule.name = Set(name.clone());
    }
    if let Some(private) = item.private {
        active_rule.private = Set(Some(private));
    }
    if let Some(global) = item.global {
        active_rule.global = Set(Some(global));
    }
    if let Some(auth) = &item.auth {
        active_rule.auth = Set(Some(auth.clone()));
    }
    if let Some(description) = &item.description {
        active_rule.description = Set(Some(description.clone()));
    }
    if let Some(tag) = &item.tag {
        active_rule.tag = Set(Some(tag.clone()));
    }
    if let Some(strings) = &item.strings {
        active_rule.strings = Set(Some(strings.clone()));
    }
    if let Some(condition) = &item.condition {
        active_rule.condition = Set(Some(condition.clone()));
    }
    if let Some(belonging) = item.belonging {
        active_rule.belonging = Set(belonging);
    }
    if let Some(verification) = item.verification {
        active_rule.verification = Set(Some(verification));
    }
    if let Some(source) = &item.source {
        active_rule.source = Set(Some(source.clone()));
    }
    if let Some(version_) = item.version {
        active_rule.version = Set(Some(version_));
    }
    if let Some(sharing) = &item.sharing {
        active_rule.sharing = Set(Some(sharing.clone()));
    }
    if let Some(grayscale) = item.grayscale {
        active_rule.grayscale = Set(Some(grayscale));
    }
    if let Some(attribute) = &item.attribute {
        active_rule.attribute = Set(Some(attribute.clone()));
    }

    active_rule.updated_at = Set(Some(chrono::Utc::now().into()));

    let res = active_rule.update(db.get_ref()).await;

    match res {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(json!({"message": e.to_string()})),
    }
}

#[delete("/rules/delete/{id}")]
async fn delete_rule(db: web::Data<DatabaseConnection>, path: web::Path<i32>) -> impl Responder {
    let rule_id = path.into_inner();

    let res = YaraRules::delete_by_id(rule_id).exec(db.get_ref()).await;

    match res {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(json!({"message": e.to_string()})),
    }
}

#[post("/yara_file/create")]
// Create a new Yara File
async fn create_yara_file(
    db: web::Data<DatabaseConnection>,
    item: web::Json<YaraFileWeb>,
) -> impl Responder {
    let new_yara_file = yara_file::ActiveModel {
        name: Set(item.name.clone()),
        last_modified_time: Set(chrono::Utc::now().into()),
        version: Set(item.version),
        compiled_data: Set(item.compiled_data.clone()),
        description: Set(item.description.clone()),
        created_at: NotSet,
        updated_at: NotSet,
        category: Set(item.category.clone()),
        ..Default::default()
    };
    let res = YaraFile::insert(new_yara_file).exec(db.get_ref()).await;
    println!("Database operation result: {:?}", res);
    match res {
        Ok(inserted) => HttpResponse::Created().json(json!({"id": inserted.last_insert_id})),
        Err(e) => HttpResponse::InternalServerError().json(json!({"message": e.to_string()})),
    }
}

#[get("/yara_file/one/{id}")]
// Get a single Yara File by ID
async fn get_yara_file(db: web::Data<DatabaseConnection>, path: web::Path<i32>) -> impl Responder {
    let yara_file_id = path.into_inner();
    match YaraFile::find_by_id(yara_file_id).one(db.get_ref()).await {
        Ok(Some(yara_file)) => HttpResponse::Ok().json(yara_file),
        Ok(None) => HttpResponse::NotFound().body("Yara file not found"),
        Err(e) => {
            eprintln!("Error fetching Yara file: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

#[get("/yara_file/all")]
// Get all Yara Files
async fn get_all_yara_files(db: web::Data<DatabaseConnection>) -> impl Responder {
    match YaraFile::find().all(db.get_ref()).await {
        Ok(yara_files) => HttpResponse::Ok().json(yara_files),
        Err(e) => {
            eprintln!("Error fetching Yara files: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

#[put("/yara_file/update/{id}")]
// Update a Yara File by ID
async fn update_yara_file(
    db: web::Data<DatabaseConnection>,
    path: web::Path<i32>,
    item: web::Json<UpdateYaraFile>,
) -> impl Responder {
    let yara_file_id = path.into_inner();
    match YaraFile::find_by_id(yara_file_id).one(db.get_ref()).await {
        Ok(Some(existing)) => {
            let mut active_model: yara_file::ActiveModel = existing.into();
            if let Some(name) = &item.name {
                active_model.name = Set(name.clone());
            }
            active_model.last_modified_time = Set(chrono::Utc::now().into());
            if let Some(version_) = item.version {
                active_model.version = Set(Some(version_));
            }
            if let Some(compiled_data) = &item.compiled_data {
                active_model.compiled_data = Set(Some(compiled_data.clone()));
            }
            if let Some(description) = &item.description {
                active_model.description = Set(Some(description.clone()));
            }
            active_model.updated_at = Set(Some(chrono::Utc::now().into()));
            if let Some(c) = &item.category {
                active_model.category = Set(Some(c.clone()))
            }

            match active_model.update(db.get_ref()).await {
                Ok(updated) => HttpResponse::Ok().json(updated),
                Err(e) => {
                    eprintln!("Error updating Yara file: {:?}", e);
                    HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(json!({"message": "Yara file not found"})),
        Err(e) => {
            eprintln!("Error fetching Yara file: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

#[delete("/yara_file/delete/{id}")]
// Delete a Yara File by ID
async fn delete_yara_file(
    db: web::Data<DatabaseConnection>,
    path: web::Path<i32>,
) -> impl Responder {
    let yara_file_id = path.into_inner();
    match YaraFile::find_by_id(yara_file_id).one(db.get_ref()).await {
        Ok(Some(yara_file)) => {
            let active_model: yara_file::ActiveModel = yara_file.into();
            match active_model.delete(db.get_ref()).await {
                Ok(_) => HttpResponse::NoContent().finish(),
                Err(e) => {
                    eprintln!("Error deleting Yara file: {:?}", e);
                    HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
                }
            }
        }
        Ok(None) => HttpResponse::NotFound().json(json!({"message": "Yara file not found"})),
        Err(e) => {
            eprintln!("Error fetching Yara file: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

#[post("/api/create")]
async fn api_create(
    db: web::Data<DatabaseConnection>,
    req_body: web::Json<models::ApiCreate>,
) -> impl Responder {
    let api_create_json = req_body.into_inner();
    let yara_file = api_create_json.yara_file;

    // compile yara
    let text_yara = yara_file.to_string();
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(text_yara.as_str()).unwrap();
    let rules = compiler.build();
    let compiled_yara = rules.serialize().unwrap();
    let imports = yara_file.modules.clone();

    let new_yara_file = yara_file::ActiveModel {
        name: Set(api_create_json.name),
        last_modified_time: Set(chrono::Utc::now().into()),
        version: Set(Some(api_create_json.version)),
        compiled_data: Set(Some(compiled_yara)),
        description: Set(Some(api_create_json.description)),
        created_at: NotSet,
        updated_at: NotSet,
        category: Set(Some(api_create_json.category)),
        imports: Set(Some(imports)),
        ..Default::default()
    };

    let res = YaraFile::insert(new_yara_file).exec(db.get_ref()).await;
    let yara_file_id = match res {
        Ok(inserted) => inserted.last_insert_id,
        Err(e) => {
            return HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    };

    let rules_id = create_or_update_rules_via_id(&db, yara_file.rules, yara_file_id)
        .await
        .unwrap();

    HttpResponse::Ok().json(json!({"yara_file_id": yara_file_id, "rules_id" : rules_id}))
}

#[post("/api/add")]
async fn api_add(
    db: web::Data<DatabaseConnection>,
    req_body: web::Json<models::ApiAdd>,
) -> impl Responder {
    let api_create_json = req_body.into_inner();

    // 调用抽离出的函数，对传入的基础 yara_file 做 merge 处理
    let full_yara_file = match build_tokenizer_yara_file_from_db(
        db.get_ref(),
        api_create_json.yara_file_id,
        api_create_json.yara_file,
    )
    .await
    {
        Ok(file) => file,
        Err(resp) => return resp,
    };

    // compile yara
    let text_yara = full_yara_file.to_string();
    let mut compiler = yara_x::Compiler::new();
    if let Err(e) = compiler.add_source(text_yara.as_str()) {
        eprintln!("Compiler add_source error: {:?}", e);
        return HttpResponse::InternalServerError()
            .json(json!({"message": format!("Compiler error: {:?}", e)}));
    }
    let rules = compiler.build();
    let compiled_yara = match rules.serialize() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Serialize rules error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Serialize error: {:?}", e)}));
        }
    };
    let imports = full_yara_file.modules.clone();

    // 为了更新数据库，这里需要获取现有的 ActiveModel（例如通过从已有 YaraFile 转换）
    let existing_file = match YaraFile::find_by_id(api_create_json.yara_file_id)
        .one(db.get_ref())
        .await
    {
        Ok(Some(file)) => file,
        _ => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": "Failed to retrieve existing Yara file for update"}))
        }
    };

    let mut active_model: yara_file::ActiveModel = existing_file.into();
    active_model.last_modified_time = Set(chrono::Utc::now().into());
    active_model.compiled_data = Set(Some(compiled_yara.clone()));
    active_model.updated_at = Set(Some(chrono::Utc::now().into()));
    active_model.imports = Set(Some(imports));
    active_model.version = Set(Some(api_create_json.version));

    match active_model.update(db.get_ref()).await {
        Ok(_) => {
            // 假定 create_or_update_rules_via_id 函数负责处理 rules 的更新操作
            let rules_id = create_or_update_rules_via_id(
                &db,
                full_yara_file.rules,
                api_create_json.yara_file_id,
            )
            .await
            .unwrap();
            HttpResponse::Ok().json(json!({
                "yara_file_id": api_create_json.yara_file_id,
                "rules_id": rules_id
            }))
        }
        Err(e) => {
            eprintln!("Error updating Yara file: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

/// 用来创建规则，或者修改已有规则的加载时间
pub async fn create_or_update_rules_via_id(
    db: &DatabaseConnection,
    rules: Vec<tokenizer::YaraRule>,
    yara_file_id: i32,
) -> anyhow::Result<Vec<i64>> {
    let mut rules_ids = Vec::new();

    for item in rules {
        // 尝试从 rule 中获取 meta 的 "id"
        if let Some(existing_id) = item.get_meta_number("id") {
            // 已存在记录，则进行更新操作：更新 loading_time 字段
            // 注意：这里假设 YaraRules 实体有 find_by_id 方法，
            // 如果查不到记录，也可以视为出错或跳过
            if let Some(model) = yara_rules::Entity::find_by_id(existing_id as i32)
                .one(db)
                .await?
            {
                // 将模型转换为 ActiveModel 以进行更新
                let mut active_model = model.into_active_model();
                active_model.loading_time = Set(Some(Utc::now().into()));

                // 执行更新操作
                let _ = yara_rules::Entity::update(active_model).exec(db).await?;

                rules_ids.push(existing_id);
            } else {
                // 如果根据 id 无法查找到记录，根据业务需求决定是报错还是进行插入操作
                // 这里选择报错
                anyhow::bail!("找不到 id 为 {} 的规则记录", existing_id);
            }
        } else {
            // 没有 id，则认为是新的规则记录，执行插入操作
            let new_rule = yara_rules::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                name: Set(item.name.clone()),
                private: Set(Some(item.private)),
                global: Set(Some(item.global)),
                auth: Set(item.get_meta_string("auth")),
                description: Set(item.get_meta_string("description")),
                tag: Set(Some(item.tags.clone())),
                strings: Set(Some(item.get_strings_vec())),
                condition: Set(Some(item.condition.clone())),
                last_modified_time: Set(Utc::now().into()),
                loading_time: Set(None),
                belonging: Set(yara_file_id as i32),
                verification: Set(item.get_meta_bool("verification")),
                source: Set(Some(
                    sea_orm_active_enums::Source::try_from(
                        item.get_meta_string("source")
                            .unwrap_or_else(|| "".to_string())
                            .as_str(),
                    )
                    .unwrap(),
                )),
                version: Set(Some(1)),
                sharing: Set(Some(
                    sea_orm_active_enums::Sharing::try_from(
                        item.get_meta_string("sharing")
                            .unwrap_or_else(|| "".to_string())
                            .as_str(),
                    )
                    .unwrap(),
                )),
                grayscale: Set(item.get_meta_bool("grayscale")),
                attribute: Set(Some(
                    sea_orm_active_enums::Attribute::try_from(
                        item.get_meta_string("attribute")
                            .unwrap_or_else(|| "".to_string())
                            .as_str(),
                    )
                    .unwrap(),
                )),
                created_at: sea_orm::ActiveValue::NotSet,
                updated_at: sea_orm::ActiveValue::NotSet,
            };

            let insert_result = yara_rules::Entity::insert(new_rule).exec(db).await?;
            rules_ids.push(insert_result.last_insert_id.into());
        }
    }
    Ok(rules_ids)
}

async fn build_tokenizer_yara_file_from_db(
    db: &DatabaseConnection,
    yara_file_id: i32,
    mut base_yara_file: tokenizer::YaraFile,
) -> Result<tokenizer::YaraFile, HttpResponse> {
    // 先根据 id 查找 YaraFile
    let existing = match YaraFile::find_by_id(yara_file_id).one(db).await {
        Ok(Some(file)) => file,
        Ok(None) => {
            return Err(HttpResponse::NotFound().json(json!({"message": "Yara File not found"})))
        }
        Err(e) => {
            return Err(HttpResponse::InternalServerError().json(json!({"message": e.to_string()})))
        }
    };

    // 根据找到的 YaraFile 查找所有关联的规则
    let rules = match existing.find_related(yara_rules::Entity).all(db).await {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("Error fetching related rules: {:?}", e);
            return Err(HttpResponse::InternalServerError().json(json!({"message": e.to_string()})));
        }
    };

    // 遍历每个 rule 并转换后 merge 到 base_yara_file 中
    for rule in rules {
        // let active_rule: yara_rules::ActiveModel = rule.clone().into();
        let tmp_yara_file = tokenizer::YaraFile {
            modules: vec![],
            rules: vec![tokenizer::YaraRule {
                name: rule.name,
                private: rule.private.unwrap_or(false),
                global: rule.global.unwrap_or(false),
                tags: rule.tag.unwrap_or(vec![]),
                meta: vec![
                    Meta {
                        key: "id".to_string(),
                        value: tokenizer::MetaValue::Number(rule.id.into()),
                    },
                    Meta {
                        key: "auth".to_string(),
                        value: tokenizer::MetaValue::String(rule.auth.unwrap_or("".to_string())),
                    },
                    Meta {
                        key: "description".to_string(),
                        value: tokenizer::MetaValue::String(
                            rule.description.unwrap_or("".to_string()),
                        ),
                    },
                    // Meta {
                    //     key: "description".to_string(),
                    //     value: tokenizer::MetaValue::String(
                    //         rule.description.unwrap_or("".to_string()),
                    //     ),
                    // },
                    Meta {
                        key: "last_modified_time".to_string(),
                        value: tokenizer::MetaValue::String(
                            Some(rule.last_modified_time)
                                .map_or(String::new(), |dt| dt.to_string()),
                        ),
                    },
                    Meta {
                        key: "loading_time".to_string(),
                        value: tokenizer::MetaValue::String(
                            rule.loading_time.map_or(String::new(), |dt| dt.to_string()),
                        ),
                    },
                    Meta {
                        key: "belonging".to_string(),
                        value: tokenizer::MetaValue::Number(rule.belonging.into()),
                    },
                    Meta {
                        key: "verification".to_string(),
                        value: tokenizer::MetaValue::Boolean(rule.verification.unwrap_or(false)),
                    },
                    Meta {
                        key: "source".to_string(),
                        value: tokenizer::MetaValue::String(
                            rule.source.unwrap().as_ref().to_string(),
                        ),
                    },
                    Meta {
                        key: "version".to_string(),
                        value: tokenizer::MetaValue::Number(rule.version.unwrap().into()),
                    },
                    Meta {
                        key: "sharing".to_string(),
                        value: tokenizer::MetaValue::String(
                            rule.sharing.unwrap().as_ref().to_string(),
                        ),
                    },
                    Meta {
                        key: "grayscale".to_string(),
                        value: tokenizer::MetaValue::Boolean(rule.grayscale.unwrap()),
                    },
                    Meta {
                        key: "attribute".to_string(),
                        value: tokenizer::MetaValue::String(
                            rule.attribute.unwrap().as_ref().to_string(),
                        ),
                    },
                    Meta {
                        key: "created_at".to_string(),
                        value: tokenizer::MetaValue::String(
                            rule.created_at.map_or(String::new(), |dt| dt.to_string()),
                        ),
                    },
                    Meta {
                        key: "updated_at".to_string(),
                        value: tokenizer::MetaValue::String(
                            rule.updated_at.map_or(String::new(), |dt| dt.to_string()),
                        ),
                    },
                ],
                strings: tokenizer::parse_strings_vec(rule.strings.unwrap()).unwrap(),
                condition: rule.condition.unwrap_or("".to_string()),
            }],
        };
        base_yara_file.merge(tmp_yara_file);
    }
    base_yara_file.modules = existing.imports.unwrap_or(vec![]);
    Ok(base_yara_file)
}

#[put("/api/update/{rule_id}")]
async fn api_update(
    db: web::Data<DatabaseConnection>,
    path: web::Path<i32>,
    item: web::Json<UpdateRule>,
) -> impl Responder {
    let rule_id = path.into_inner();
    let mut yara_file_id = 0;

    let rule: Option<yara_rules::Model> = YaraRules::find_by_id(rule_id)
        .one(db.get_ref())
        .await
        .unwrap();

    if rule.is_none() {
        return HttpResponse::NotFound().body("Rule not found");
    }

    let mut active_rule: yara_rules::ActiveModel = rule.unwrap().into();
    yara_file_id = active_rule.belonging.clone().unwrap();

    if let Some(name) = &item.name {
        active_rule.name = Set(name.clone());
    }
    if let Some(private) = item.private {
        active_rule.private = Set(Some(private));
    }
    if let Some(global) = item.global {
        active_rule.global = Set(Some(global));
    }
    if let Some(auth) = &item.auth {
        active_rule.auth = Set(Some(auth.clone()));
    }
    if let Some(description) = &item.description {
        active_rule.description = Set(Some(description.clone()));
    }
    if let Some(tag) = &item.tag {
        active_rule.tag = Set(Some(tag.clone()));
    }
    if let Some(strings) = &item.strings {
        active_rule.strings = Set(Some(strings.clone()));
    }
    if let Some(condition) = &item.condition {
        active_rule.condition = Set(Some(condition.clone()));
    }
    if let Some(belonging) = item.belonging {
        active_rule.belonging = Set(belonging);
    }
    if let Some(verification) = item.verification {
        active_rule.verification = Set(Some(verification));
    }
    if let Some(source) = &item.source {
        active_rule.source = Set(Some(source.clone()));
    }
    if let Some(version_) = item.version {
        active_rule.version = Set(Some(version_));
    }
    if let Some(sharing) = &item.sharing {
        active_rule.sharing = Set(Some(sharing.clone()));
    }
    if let Some(grayscale) = item.grayscale {
        active_rule.grayscale = Set(Some(grayscale));
    }
    if let Some(attribute) = &item.attribute {
        active_rule.attribute = Set(Some(attribute.clone()));
    }

    active_rule.updated_at = Set(Some(chrono::Utc::now().into()));

    let res = active_rule.update(db.get_ref()).await;

    let full_yara_file = match build_tokenizer_yara_file_from_db(
        db.get_ref(),
        yara_file_id,
        tokenizer::YaraFile {
            modules: vec![],
            rules: vec![],
        },
    )
    .await
    {
        Ok(file) => file,
        Err(resp) => return resp,
    };

    let text_yara = full_yara_file.to_string();
    let mut compiler = yara_x::Compiler::new();
    if let Err(e) = compiler.add_source(text_yara.as_str()) {
        eprintln!("Compiler add_source error: {:?}", e);
        return HttpResponse::InternalServerError()
            .json(json!({"message": format!("Compiler error: {:?}", e)}));
    }
    let rules = compiler.build();
    let compiled_yara = match rules.serialize() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Serialize rules error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Serialize error: {:?}", e)}));
        }
    };
    let imports = full_yara_file.modules.clone();

    // 为了更新数据库，这里需要获取现有的 ActiveModel（例如通过从已有 YaraFile 转换）
    let existing_file = match YaraFile::find_by_id(yara_file_id).one(db.get_ref()).await {
        Ok(Some(file)) => file,
        _ => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": "Failed to retrieve existing Yara file for update"}))
        }
    };

    let mut active_model: yara_file::ActiveModel = existing_file.into();
    active_model.last_modified_time = Set(chrono::Utc::now().into());
    active_model.compiled_data = Set(Some(compiled_yara.clone()));
    active_model.updated_at = Set(Some(chrono::Utc::now().into()));
    active_model.imports = Set(Some(imports));
    // active_model.version = Set(Some(api_create_json.version));

    match active_model.update(db.get_ref()).await {
        Ok(_) => {
            // 假定 create_or_update_rules_via_id 函数负责处理 rules 的更新操作
            // let rules_id = create_or_update_rules_via_id(
            let _ = create_or_update_rules_via_id(
                db.get_ref(),
                full_yara_file.rules,
                yara_file_id,
            )
            .await
            .unwrap();
            // HttpResponse::Ok().json(json!({
            //     "yara_file_id": api_create_json.yara_file_id,
            //     "rules_id": rules_id
            // }))
        }
        Err(e) => {
            eprintln!("Error updating Yara file: {:?}", e);
            return HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }

    match res {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(json!({"message": e.to_string()})),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db: DatabaseConnection = Database::connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(json_convert_to_text)
            .service(convert_to_json)
            .service(version)
            .service(file_convert_to_json)
            .service(get_all_rules)
            .service(get_rule_by_id)
            .service(create_rule)
            .service(update_rule)
            .service(delete_rule)
            .service(create_yara_file)
            .service(get_yara_file)
            .service(get_all_yara_files)
            .service(update_yara_file)
            .service(delete_yara_file)
            .service(api_create)
            .service(api_add)
            .service(api_update)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
