mod tokenizer;
mod yara;
use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use mimalloc::MiMalloc;
use sea_orm::ActiveValue::NotSet;
use serde_json::{json, Value};
use std::{io::Read, str::FromStr};
mod entity;
mod models;
use crate::entity::{prelude::*, yara_file, yara_rules};
use crate::models::{CreateRule, UpdateRule, UpdateYaraFile, YaraFileWeb};
use anyhow::bail;
use chrono::Utc;
use dotenvy::dotenv;
use std::time::Instant;
// use entity::prelude::*;
// use env_logger;
// use log::Record;
use log::{error, info};
use sea_orm::QueryOrder;
use sea_orm::QuerySelect;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, ModelTrait,
    QueryFilter, Set,
};
use sea_orm::{DbErr, PaginatorTrait};
use sea_orm::{FromQueryResult, IntoActiveModel};
use std::cmp::min;
// use std::fs::File;
use tokenizer::Meta;

use std::env;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

macro_rules! set_fields {
    ($obj:expr, $key:expr, $value:expr, { $($field:literal),* }) => {
        match $key.as_str() {
            $(
                $field => $obj[$field] = json!($value),
            )*
            _ => {}
        }
    };
}

macro_rules! create_json_object {
    ($var_name:ident) => {
        let mut $var_name = json!({});
    };
}

macro_rules! scan_error {
    ($msg:expr) => {
        return HttpResponse::Ok().json(json!(
            {
                "status" : false ,
                "message" : $msg,
                "result" : "",
                "logs" : ""
            }
        ))
    };
}

#[macro_export]
macro_rules! op_log {
    ($func:expr, $operator:expr, $log:expr) => {{
        match $func {
            Ok(val) => Ok(val),
            Err(e) => {
                let info = serde_json::json!(
                    {
                        "operator": format!("{:?}", $operator),
                        "error": format!("{}", e)
                    }
                );

                $log.push(info);

                Err(e)
            }
        }
    }};
}

#[macro_export]
macro_rules! ok_or_continue {
    ($result:expr) => {
        match $result {
            Ok(o) => o,
            Err(_) => continue,
        }
    };
}

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

    // Try to compile the YARA file
    let text_yara = yara_file.to_string();
    let mut compiler = yara_x::Compiler::new();
    if let Err(e) = compiler.add_source(text_yara.as_str()) {
        return HttpResponse::InternalServerError()
            .json(json!({"message": format!("Failed to add YARA source: {}", e)}));
    }

    let rules = compiler.build();

    let compiled_yara = match rules.serialize() {
        Ok(data) => data,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Failed to serialize YARA rules: {}", e)}))
        }
    };

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
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Database insertion failed: {}", e)}))
        }
    };

    let rules_id = match create_or_update_rules_via_id(&db, yara_file.rules, yara_file_id).await {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Failed to update rules: {}", e)}))
        }
    };

    HttpResponse::Ok().json(json!({
        "yara_file_id": yara_file_id,
        "rules_id": rules_id
    }))
}
#[derive(Debug, MultipartForm)]
struct UploadFormApiCreateFile {
    category: Text<String>,
    name: Text<String>,
    version: Text<i32>,
    description: Text<String>,
    #[multipart(limit = "100MB")]
    file: TempFile,
}

#[post("/api/create/file")]
async fn api_create_file(
    db: web::Data<DatabaseConnection>,
    MultipartForm(mut form): MultipartForm<UploadFormApiCreateFile>,
) -> impl Responder {
    // let api_create_json = req_body.into_inner();
    let mut buffer = vec![];
    // let response_str;
    let _ = form.file.file.read_to_end(&mut buffer);
    let s = String::from_utf8(buffer);
    let yara_file: tokenizer::YaraFile;
    match s {
        Ok(str) => match tokenizer::YaraFile::from_str(&str) {
            Ok(f) => yara_file = f,
            Err(e) => return HttpResponse::Ok().json(json!({"message": e.to_string()})),
        },
        Err(e) => return HttpResponse::Ok().json(json!({"message": e.to_string()})),
    }

    let name: String = form.name.into_inner();
    let version_: i32 = form.version.into_inner();
    let description: String = form.description.into_inner();
    let category: String = form.category.into_inner();

    // Try to compile the YARA file
    let text_yara = yara_file.to_string();
    let mut compiler = yara_x::Compiler::new();
    if let Err(e) = compiler.add_source(text_yara.as_str()) {
        return HttpResponse::InternalServerError()
            .json(json!({"message": format!("Failed to add YARA source: {}", e)}));
    }

    let rules = compiler.build();

    let compiled_yara = match rules.serialize() {
        Ok(data) => data,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Failed to serialize YARA rules: {}", e)}))
        }
    };

    let imports = yara_file.modules.clone();

    let new_yara_file = yara_file::ActiveModel {
        name: Set(name),
        last_modified_time: Set(chrono::Utc::now().into()),
        version: Set(Some(version_)),
        compiled_data: Set(Some(compiled_yara)),
        description: Set(Some(description)),
        created_at: NotSet,
        updated_at: NotSet,
        category: Set(Some(category)),
        imports: Set(Some(imports)),
        ..Default::default()
    };

    let res = YaraFile::insert(new_yara_file).exec(db.get_ref()).await;
    let yara_file_id = match res {
        Ok(inserted) => inserted.last_insert_id,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Database insertion failed: {}", e)}))
        }
    };

    let rules_id = match create_or_update_rules_via_id(&db, yara_file.rules, yara_file_id).await {
        Ok(id) => id,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": format!("Failed to update rules: {}", e)}))
        }
    };

    HttpResponse::Ok().json(json!({
        "yara_file_id": yara_file_id,
        "rules_id": rules_id
    }))
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
                        item.get_meta_string("source").unwrap_or_default().as_str(),
                    )
                    .unwrap_or(sea_orm_active_enums::Source::Official),
                )),
                version: Set(Some(1)),
                sharing: Set(Some(
                    sea_orm_active_enums::Sharing::try_from(
                        item.get_meta_string("sharing").unwrap_or_default().as_str(),
                    )
                    .unwrap_or(sea_orm_active_enums::Sharing::TlpRed),
                )),
                grayscale: Set(item.get_meta_bool("grayscale")),
                attribute: Set(Some(
                    sea_orm_active_enums::Attribute::try_from(
                        item.get_meta_string("attribute")
                            .unwrap_or_default()
                            .as_str(),
                    )
                    .unwrap_or(sea_orm_active_enums::Attribute::White),
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

    let rule: Option<yara_rules::Model> = YaraRules::find_by_id(rule_id)
        .one(db.get_ref())
        .await
        .unwrap();

    if rule.is_none() {
        return HttpResponse::NotFound().body("Rule not found");
    }

    let mut active_rule: yara_rules::ActiveModel = rule.unwrap().into();
    let yara_file_id = active_rule.belonging.clone().unwrap();

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
            let _ = create_or_update_rules_via_id(db.get_ref(), full_yara_file.rules, yara_file_id)
                .await
                .unwrap();
            // HttpResponse::Ok().json(json!({
            //     "yara_file_id": api_create_json.yara_file_id,
            //     "rules_id": rules_id
            // }))
        }
        Err(e) => {
            eprintln!("Error updating Yara file: {:?}", e);
            return HttpResponse::InternalServerError().json(json!({"message": e.to_string()}));
        }
    }

    match res {
        Ok(updated) => HttpResponse::Ok().json(updated),
        Err(e) => HttpResponse::InternalServerError().json(json!({"message": e.to_string()})),
    }
}

#[delete("/api/rule/delete/{rule_id}")]
async fn api_rule_delete(
    db: web::Data<DatabaseConnection>,
    path: web::Path<i32>,
) -> impl Responder {
    let rule_id = path.into_inner();

    let rule: Option<yara_rules::Model> = YaraRules::find_by_id(rule_id)
        .one(db.get_ref())
        .await
        .unwrap();

    if rule.is_none() {
        return HttpResponse::NotFound().body("Rule not found");
    }

    let active_rule: yara_rules::ActiveModel = rule.unwrap().into();
    let yara_file_id = active_rule.belonging.clone().unwrap();

    let res = YaraRules::delete_by_id(rule_id).exec(db.get_ref()).await;

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
            let _ = create_or_update_rules_via_id(db.get_ref(), full_yara_file.rules, yara_file_id)
                .await
                .unwrap();
            // HttpResponse::Ok().json(json!({
            //     "yara_file_id": api_create_json.yara_file_id,
            //     "rules_id": rules_id
            // }))
        }
        Err(e) => {
            eprintln!("Error updating Yara file: {:?}", e);
            return HttpResponse::InternalServerError().json(json!({"message": e.to_string()}));
        }
    }

    match res {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(json!({"message": e.to_string()})),
    }
}

#[delete("/api/yara_file/delete/{id}")]
async fn api_yara_file_delete(
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

/// 用于单个记录查询的参数
#[derive(Debug, serde::Deserialize)]
struct IdParam {
    id: i32,
}

/// 用于分页查询的参数
#[derive(Debug, serde::Deserialize)]
struct PaginationParams {
    page: Option<u32>,
    per_page: Option<u32>,
}

/// ---------------------- APIs for Rules ------------------------------

/// GET /api/rule/one?id={id}
/// 根据 query 参数获得单个 rule 信息
#[get("/api/rule/one")]
async fn api_rule_one(
    db: web::Data<sea_orm::DatabaseConnection>,
    web::Query(info): web::Query<IdParam>,
) -> impl Responder {
    let rule_id = info.id;
    match yara_rules::Entity::find_by_id(rule_id)
        .one(db.get_ref())
        .await
    {
        Ok(Some(rule)) => HttpResponse::Ok().json(rule),
        Ok(None) => HttpResponse::NotFound().json(json!({"message": "Rule not found"})),
        Err(e) => {
            eprintln!("Error fetching rule with id {}: {:?}", rule_id, e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

/// GET /api/rule/page?page={page}&per_page={per_page}
/// 分页获得 rule 信息
#[get("/api/rule/page")]
async fn api_rule_page(
    db: web::Data<sea_orm::DatabaseConnection>,
    web::Query(pagination): web::Query<PaginationParams>,
) -> impl Responder {
    // 默认页码为 1，每页 10 条记录
    let page: u32 = pagination.page.unwrap_or(1);
    let per_page: u32 = pagination.per_page.unwrap_or(10);
    let offset = (page - 1) * per_page;

    // 获取分页数据
    let rules_result = yara_rules::Entity::find()
        .order_by_asc(yara_rules::Column::Id)
        .limit(per_page as u64)
        .offset(offset as u64)
        .all(db.get_ref())
        .await;
    // 同时查询出总记录数
    let count_result = yara_rules::Entity::find().count(db.get_ref()).await;

    match (rules_result, count_result) {
        (Ok(rules), Ok(total)) => HttpResponse::Ok().json(json!({
            "page": page,
            "per_page": per_page,
            "total": total,
            "items": rules
        })),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("Error during paginated rules query: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

/// GET /api/rule/history?id={id}
/// 根据规则 id 查询对应的历史记录
#[get("/api/rule/history")]
async fn api_rule_history(
    db: web::Data<sea_orm::DatabaseConnection>,
    web::Query(info): web::Query<IdParam>,
) -> impl Responder {
    let rule_id = info.id;

    // 使用历史记录实体进行查询，此处假定历史记录的实体名称是 `yara_rule_history::Entity`
    let histories_result = YaraRuleHistory::find()
        .filter(entity::yara_rule_history::Column::RuleId.eq(rule_id))
        .all(db.get_ref())
        .await;

    match histories_result {
        Ok(histories) => HttpResponse::Ok().json(histories),
        Err(e) => {
            eprintln!("Error fetching histories for rule id {}: {:?}", rule_id, e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

/// ------------------- APIs for Yara Files ------------------------------

/// GET /api/yara_file/get?id={id}
/// 根据 query 参数获得单个 yara file 信息
#[get("/api/yara_file/get")]
async fn api_yara_file_get(
    db: web::Data<sea_orm::DatabaseConnection>,
    web::Query(info): web::Query<IdParam>,
) -> impl Responder {
    let file_id = info.id;
    match yara_file::Entity::find_by_id(file_id)
        .one(db.get_ref())
        .await
    {
        Ok(Some(file)) => HttpResponse::Ok().json(file),
        Ok(None) => HttpResponse::NotFound().json(json!({"message": "Yara file not found"})),
        Err(e) => {
            eprintln!("Error fetching yara file with id {}: {:?}", file_id, e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

/// GET /api/yara_file/page?page={page}&per_page={per_page}
/// 分页获得 yara file 信息
#[get("/api/yara_file/page")]
async fn api_yara_file_page(
    db: web::Data<sea_orm::DatabaseConnection>,
    web::Query(pagination): web::Query<PaginationParams>,
) -> impl Responder {
    let page: u32 = pagination.page.unwrap_or(1);
    let per_page: u32 = pagination.per_page.unwrap_or(10);
    let offset = (page - 1) * per_page;

    // 获取分页数据
    let files_result = yara_file::Entity::find()
        .order_by_asc(yara_file::Column::Id)
        .limit(per_page as u64)
        .offset(offset as u64)
        .all(db.get_ref())
        .await;
    // 查询总数
    let count_result = yara_file::Entity::find().count(db.get_ref()).await;

    match (files_result, count_result) {
        (Ok(files), Ok(total)) => HttpResponse::Ok().json(json!({
            "page": page,
            "per_page": per_page,
            "total": total,
            "items": files
        })),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("Error during paginated yara file query: {:?}", e);
            HttpResponse::InternalServerError().json(json!({"message": e.to_string()}))
        }
    }
}

use std::collections::HashMap;

use std::sync::RwLock;

pub struct YaraRulesPool {
    pub data: RwLock<HashMap<String, XPool>>, // <- Mutex is necessary to mutate safely across threads
}

impl YaraRulesPool {
    pub fn new() -> Self {
        YaraRulesPool {
            data: RwLock::new(HashMap::new()),
        }
    }
}

pub struct XPool(Vec<yara_x::Rules>);

impl XPool {
    // 创建一个新的空 XPool
    pub fn new() -> Self {
        XPool(Vec::new())
    }

    // 使用已有的 Vec<Rules> 创建 XPool
    pub fn from_vec(rules: Vec<yara_x::Rules>) -> Self {
        XPool(rules)
    }

    // 添加单个规则
    pub fn add(&mut self, rule: yara_x::Rules) {
        self.0.push(rule);
    }

    // 添加多个规则
    pub fn extend(&mut self, rules: impl IntoIterator<Item = yara_x::Rules>) {
        self.0.extend(rules);
    }

    // 获取规则数量
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // 获取指定索引的规则
    pub fn get(&self, index: usize) -> Option<&yara_x::Rules> {
        self.0.get(index)
    }

    // 获取可变引用
    pub fn get_mut(&mut self, index: usize) -> Option<&mut yara_x::Rules> {
        self.0.get_mut(index)
    }

    // 清空所有规则
    pub fn clear(&mut self) {
        self.0.clear();
    }

    // 转换回 Vec<Rules>
    pub fn into_vec(self) -> Vec<yara_x::Rules> {
        self.0
    }

    // 获取内部 Vec 的不可变引用
    pub fn as_slice(&self) -> &[yara_x::Rules] {
        &self.0
    }

    pub fn scan(&self, data: &Vec<u8>) -> anyhow::Result<serde_json::Value> {
        let mut list: Vec<serde_json::Value> = vec![];
        for rules in &self.0 {
            let mut scanner = yara_x::Scanner::new(&rules);
            let results = match scanner.scan(data) {
                Ok(r) => r,
                Err(e) => return Err(anyhow::anyhow!("Failed to scan file, {}", e)),
            };
            if let Ok(v) = self.consume_matching_rules(results.matching_rules()) {
                list.push(v);
            };
        }
        Ok(serde_json::json!(list))
    }

    /// 将 Rule 变成 JSON 格式
    fn consume_matching_rules(
        &self,
        matching_rules: yara_x::MatchingRules,
    ) -> anyhow::Result<serde_json::Value> {
        let mut json = serde_json::json!({});
        let mut json_rules: Vec<serde_json::Value> = Vec::new();
        let limit = 50;
        for matching_rule in matching_rules {
            let mut json_rule = serde_json::json!({
                "identifier": matching_rule.identifier()
            });
            json_rule["meta"] = matching_rule.metadata().into_json();
            let mut match_vec: Vec<serde_json::Value> = Vec::new();
            for p in matching_rule.patterns() {
                for m in p.matches() {
                    let match_range = m.range();
                    let match_data = m.data();

                    let mut s = String::new();

                    for b in &match_data[..min(match_data.len(), limit)] {
                        for c in b.escape_ascii() {
                            s.push_str(format!("{}", c as char).as_str());
                        }
                    }

                    if match_data.len() > limit {
                        s.push_str(
                            format!(" ... {} more bytes", match_data.len().saturating_sub(limit))
                                .as_str(),
                        );
                    }

                    let mut match_json = serde_json::json!({
                        "identifier": p.identifier(),
                        "start": match_range.start,
                        "length": match_range.len(),
                        "data": s.as_str()
                    });

                    if let Some(k) = m.xor_key() {
                        let mut p = String::with_capacity(s.len());
                        for b in &match_data[..min(match_data.len(), limit)] {
                            for c in (b ^ k).escape_ascii() {
                                p.push_str(format!("{}", c as char).as_str());
                            }
                        }
                        match_json["xor_key"] = serde_json::json!(k);
                        match_json["plaintext"] = serde_json::json!(p);
                    }
                    match_vec.push(match_json);
                }
                json_rule["strings"] = serde_json::json!(match_vec);
            }
            json_rules.push(json_rule);
        }
        json["rules"] = serde_json::json!(json_rules);
        Ok(json)
    }
}

// pub fn merge_rules(rules: Vec<yara_x::Rules>) -> yara_x::Rules {
//     // 示例：如果只有一个规则，直接返回；如果多个，则简单将各规则内容拼接后返回
//     if rules.is_empty() {
//         panic!("merge_rules: empty rules vector");
//     }
//     if rules.len() == 1 {
//         rules.into_iter().next().unwrap()
//     } else {
//         let merged_definition = rules
//             .into_iter()
//             .map(|r| r.definition)
//             .collect::<Vec<_>>()
//             .join("\n");
//         yara_x::Rules {
//             definition: merged_definition,
//         }
//     }
// }

// 定义一个临时结构体，只包含 category 字段
#[derive(Debug, FromQueryResult)]
struct CategoryResult {
    pub category: Option<String>,
}

#[post("/api/reload")]
async fn api_reload(
    db: web::Data<DatabaseConnection>,
    pool: web::Data<YaraRulesPool>,
) -> impl Responder {
    match hot_update_all(&db, &pool).await {
        Ok(_) => HttpResponse::Ok().body("Hot update triggered successfully!"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {:?}", e)),
    }
}

pub async fn hot_update_all(
    db: &DatabaseConnection,
    pool: &web::Data<YaraRulesPool>,
) -> anyhow::Result<()> {
    // 首先获取所有不同的 category
    let categories = yara_file::Entity::find()
        .select_only()
        .column(yara_file::Column::Category)
        .filter(yara_file::Column::Category.is_not_null())
        .group_by(yara_file::Column::Category)
        .into_model::<CategoryResult>()
        .all(db)
        .await?
        .into_iter()
        .filter_map(|record| record.category)
        .collect::<Vec<String>>();

    // let mut merged_map: HashMap<String, yara_x::Rules> = HashMap::new();
    let mut merged_map: HashMap<String, XPool> = HashMap::new();

    // 对每个 category 查询其所有规则
    for category in categories {
        let rules = yara_file::Entity::find()
            .filter(yara_file::Column::Category.eq(category.clone()))
            .all(db)
            .await?;

        let mut rules_vec = Vec::new();
        for rule in rules {
            if let Some(compiled_data) = rule.compiled_data {
                match yara_x::Rules::deserialize(&compiled_data) {
                    Ok(rule) => rules_vec.push(rule),
                    Err(e) => {
                        eprintln!("Deserialization failed for category {}: {}", category, e);
                    }
                }
            }
        }

        if !rules_vec.is_empty() {
            let mut xpool = XPool::new();
            xpool.extend(rules_vec);
            // let merged_rules = merge_rules(rules_vec);
            merged_map.insert(category, xpool);
        }
    }

    if merged_map.is_empty() {
        anyhow::bail!("No Yara file with valid compiled_data found for any category");
    }

    let mut pool_data = pool.data.write().unwrap();

    *pool_data = merged_map;

    Ok(())
}

use actix_multipart::form::text::Text;
#[derive(Debug, MultipartForm)]
struct ScanForm {
    #[multipart(limit = "50MB")]
    file: Vec<TempFile>,
    category: Text<String>,
    strelka_style: Option<Text<String>>,
    c_style: Option<Text<String>>,
}

#[post("/api/scan")]
pub async fn api_scan(
    MultipartForm(form): MultipartForm<ScanForm>,
    data: web::Data<YaraRulesPool>,
) -> impl Responder {
    let mut log: Vec<Value> = vec![];
    let mut c_style_result = vec![];
    let mut normal_result_value: Vec<Value> = vec![];
    let mut strelka_result_matches: Vec<String> = vec![];
    let mut strelka_result_meta: Vec<Value> = vec![];
    let mut strelka_result_strings: Vec<Value> = vec![];
    let scan_type = form.category.into_inner();
    let files = form.file;
    let file_num = files.len();
    let strelka_style = if let Some(s) = form.strelka_style {
        s.into_inner().to_lowercase() == "true"
    } else {
        false
    };
    let c_style = if let Some(s) = form.c_style {
        s.into_inner().to_lowercase() == "true"
    } else {
        false
    };
    info!(
        "BEGIN /api/v1/m01/files/scan -- type[{}], number of files[{}]",
        &scan_type, file_num
    );

    let start_time = Instant::now();

    let xpool: &XPool;
    // Check type
    let data = data.data.read().unwrap();
    let keys = &data.keys().collect::<Vec<&String>>();
    if !data.contains_key(&scan_type) {
        error!(
            "M01 scanned types are {:?}, can't find `{}`.",
            keys, &scan_type
        );
        scan_error!(format!("Type `{}` not in M01 scan type!", &scan_type));
    }
    xpool = data.get(&scan_type).unwrap();
    let check_type_duration = start_time.elapsed().as_millis();
    info!("Check type duration: {} ms", check_type_duration);
    log.push(json!({"stage": "check_type", "duration_ms": check_type_duration}));

    let xpool_start_time = Instant::now();
    for mut file in files {
        let read_start_time = Instant::now();
        let mut buffer = Vec::new();
        if let Err(e) = file.file.read_to_end(&mut buffer) {
            error!(
                "Failed on FILE<{:?}>`let Err(e) = f.file.read_to_end(&mut buffer)`: {}",
                file.file_name, e
            );
            continue;
        }
        let read_duration = read_start_time.elapsed().as_millis();
        info!("Read file duration: {} ms", read_duration);
        log.push(json!({"stage": "read_file", "duration_ms": read_duration}));

        if &scan_type == "domain" || &scan_type == "url" {
            info!(
                "{} CONTENT: \n{}",
                &scan_type.to_uppercase(),
                String::from_utf8(buffer.clone()).unwrap_or("error from_utf8".to_string())
            )
        }
        let name = file.file_name.unwrap_or("".to_string());
        // let xfile = XFile::Plain(Plain::new(&name, &buffer));

        let scan_start_time = Instant::now();
        let tmp_r = ok_or_continue!(op_log!(xpool.scan(&buffer), &name, &mut log));
        let scan_duration = scan_start_time.elapsed().as_millis();
        info!("Scan file duration: {} ms", scan_duration);
        log.push(json!({"stage": "scan_file", "duration_ms": scan_duration}));

        if strelka_style {
            let convert_start_time = Instant::now();
            match convert_to_strelka_style(tmp_r) {
                Err(_) => continue,
                Ok((match1, meta1, string1)) => {
                    strelka_result_matches.extend(match1);
                    strelka_result_meta.extend(meta1);
                    strelka_result_strings.extend(string1);
                }
            }
            let convert_duration = convert_start_time.elapsed().as_millis();
            info!("Convert to Strelka duration: {} ms", convert_duration);
            log.push(json!({"stage": "convert_strelka", "duration_ms": convert_duration}));
        } else if c_style {
            let convert_start_time = Instant::now();
            let name = match decide_name(&scan_type, &buffer) {
                Ok(n) => n,
                Err(e) => {
                    error!("Error: {}", e);
                    scan_error!(e.to_string())
                }
            };
            match convert_to_c_style(tmp_r, &scan_type, &name) {
                Err(e) => {
                    error!("Error: {}", e);
                    scan_error!(e.to_string())
                }
                Ok(o) => c_style_result = o,
            }
            let convert_duration = convert_start_time.elapsed().as_millis();
            info!("Convert to C-style duration: {} ms", convert_duration);
            log.push(json!({"stage": "convert_c_style", "duration_ms": convert_duration}));
        } else {
            normal_result_value.push(json!(
                {
                    &name:tmp_r
                }
            ));
        }
    }
    let process_files_duration = xpool_start_time.elapsed().as_millis();
    info!("Process files duration: {} ms", process_files_duration);
    log.push(json!({"stage": "process_files", "duration_ms": process_files_duration}));

    let result_start_time = Instant::now();
    let result = if strelka_style {
        json!(
            {
                "matches":strelka_result_matches,
                "meta":strelka_result_meta,
                "strings":strelka_result_strings
            }
        )
    } else {
        if c_style {
            json!(c_style_result)
        } else {
            json!(normal_result_value)
        }
    };
    let result_duration = result_start_time.elapsed().as_millis();
    info!("Prepare result duration: {} ms", result_duration);
    log.push(json!({"stage": "prepare_result", "duration_ms": result_duration}));

    HttpResponse::Ok().json(json!({
        "status" : true,
        "message" : "",
        "result" : result,
        "logs" : log
    }))
}

#[derive(Debug, FromQueryResult)]
struct CategoryResultApi {
    category: String,
}

#[get("/api/categories")]
pub async fn api_categories(db: web::Data<DatabaseConnection>) -> impl Responder {
    let query_result: Result<Vec<CategoryResultApi>, DbErr> = yara_file::Entity::find()
        .select_only()
        .column(yara_file::Column::Category)
        .distinct()
        .filter(yara_file::Column::Category.is_not_null())
        .into_model::<CategoryResultApi>()
        .all(db.get_ref())
        .await;

    let categories = match query_result {
        Ok(cats) => cats,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Database error: {}", e));
        }
    };

    let unique_categories: Vec<String> = categories.into_iter().map(|cat| cat.category).collect();

    HttpResponse::Ok().json(unique_categories)
}
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Host address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port number to listen on
    #[arg(long, default_value_t = 8080)]
    port: u16,
}
use chrono::Local;
use colored::Colorize;
use env_logger::Builder;
use log::LevelFilter;
use log::Record;
use std::io::Write;
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    Builder::new()
        .format(|buf, record: &Record| {
            let ts = Local::now().with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap());

            // Set color based on the log level
            let level_color = match record.level() {
                log::Level::Error => "red",
                log::Level::Warn => "yellow",
                log::Level::Info => "green",
                log::Level::Debug => "blue",
                log::Level::Trace => "magenta",
            };

            writeln!(
                buf,
                "{} [{}] - {}",
                ts.format("%Y-%m-%d %H:%M:%S"),
                record.level().to_string().color(level_color),
                record.args()
            )
        })
        // .filter_level(LevelFilter::Info)
        .filter_level(LevelFilter::Info)
        .init();

    let args = Args::parse();
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db: DatabaseConnection = Database::connect(&database_url)
        .await
        .expect("Failed to connect to the database");
    let pool = web::Data::new(YaraRulesPool::new());

    match hot_update_all(&db, &pool).await {
        Ok(_) => info!("init successfully!"),
        Err(e) => {
            error!("Error: {}", e);
        }
    }

    println!("Server running at http://{}:{}", args.host, args.port);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .app_data(pool.clone())
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
            .service(api_create_file)
            .service(api_add)
            .service(api_update)
            .service(api_rule_delete)
            .service(api_yara_file_delete)
            .service(api_rule_one)
            .service(api_rule_page)
            .service(api_yara_file_get)
            .service(api_yara_file_page)
            .service(api_scan)
            .service(api_reload)
            .service(api_categories)
            .service(api_rule_history)
    })
    .bind((args.host, args.port))?
    .run()
    .await
}

// 附件解析逻辑
use base64::{prelude::BASE64_STANDARD, Engine};
use serde::Deserialize;
use std::str;

#[derive(Debug, Deserialize)]
struct Rule {
    identifier: String,
    meta: Vec<Vec<MetaValue>>,
    strings: Vec<StringMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum MetaValue {
    String(String),
    Bytes(Vec<u8>),
    Number(f64),
    Bool(bool),
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct StringMatch {
    identifier: String,
    start: usize,
    length: usize, // dead
    data: DataValue,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DataValue {
    String(String),
    Bytes(Vec<u8>),
}

fn convert_to_strelka_style(v: Value) -> anyhow::Result<(Vec<String>, Vec<Value>, Vec<Value>)> {
    let mut identifiers = vec![];
    let mut metas = vec![];
    let mut strings = vec![];
    let vs = if let Some(a) = v.as_array() {
        a
    } else {
        bail!("Failed to parse Value in convert_to_strelka_style.")
    };
    for i in vs {
        match convert_to_strelka_style_one(&i) {
            Ok((r1, r2, r3)) => {
                identifiers.extend(r1);
                metas.extend(r2);
                strings.extend(r3);
            }
            Err(e) => {
                error!("Failed on {:?}: {}", i, e)
            }
        }
    }
    Ok((identifiers, metas, strings))
}

fn convert_to_strelka_style_one(
    v: &Value,
) -> anyhow::Result<(Vec<String>, Vec<Value>, Vec<Value>)> {
    let mut identifiers = vec![];
    let mut metas = vec![];
    let mut strings = vec![];
    // info!("{:?}", v);
    let rules: Vec<Rule> = serde_json::from_value(v["rules"].clone())?;
    for rule in rules {
        identifiers.push(rule.identifier.clone());

        let mut num = 0;
        for values in rule.meta {
            num += 1;
            let key = if let Some(first) = values.first() {
                match first {
                    MetaValue::String(s) => s.clone(),
                    MetaValue::Bytes(b) => {
                        String::from_utf8(b.clone()).unwrap_or_else(|_| "Invalid UTF-8".to_string())
                    }
                    MetaValue::Number(n) => n.to_string(),
                    MetaValue::Bool(b) => b.to_string(),
                }
            } else {
                num.to_string()
            };
            let value_str = if let Some(second) = values.get(1) {
                match second {
                    MetaValue::String(s) => s.clone(),
                    MetaValue::Bytes(b) => {
                        String::from_utf8(b.clone()).unwrap_or_else(|_| "Invalid UTF-8".to_string())
                    }
                    MetaValue::Number(n) => n.to_string(),
                    MetaValue::Bool(b) => b.to_string(),
                }
            } else {
                format!("value{}", num.to_string())
            };
            metas.push(json!(
                {
                    "rule":&rule.identifier,
                    "identifier":&key,
                    "value":&value_str
                }
            ))
        }

        for string_match in rule.strings {
            let data_str = match string_match.data {
                DataValue::String(s) => s,
                DataValue::Bytes(b) => BASE64_STANDARD.encode(&b),
            };
            strings.push(json!(
                {
                    "offset":string_match.start,
                    "stringidentifier":&string_match.identifier,
                    "str":&data_str
                }
            ))
        }
    }
    Ok((identifiers, metas, strings))
}

fn convert_to_c_style(v: Value, scan_type: &str, name: &str) -> anyhow::Result<Vec<Value>> {
    let mut final_value = vec![];
    let vs = if let Some(a) = v.as_array() {
        a
    } else {
        bail!("Failed to parse Value in convert_to_strelka_style.")
    };
    for i in vs {
        match convert_to_c_style_one(&i, scan_type, name) {
            Ok(o) => {
                final_value.extend(o);
            }
            Err(e) => {
                error!("Failed on {:?}: {}", i, e)
            }
        }
    }
    Ok(final_value)
}

fn convert_to_c_style_one(v: &Value, scan_type: &str, name: &str) -> anyhow::Result<Vec<Value>> {
    let mut final_value = vec![];
    let rules: Vec<Rule> = serde_json::from_value(v["rules"].clone())?;
    for rule in rules {
        create_json_object!(one_object);
        create_json_object!(meta);
        let rulename = rule.identifier.clone();
        one_object["rulename"] = json!(rulename);
        one_object["name"] = json!(name);
        one_object["type"] = json!(scan_type);
        let mut strings = vec![];
        let mut num = 0;
        for values in rule.meta {
            num += 1;
            let key = if let Some(first) = values.first() {
                match first {
                    MetaValue::String(s) => s.clone(),
                    MetaValue::Bytes(b) => {
                        String::from_utf8(b.clone()).unwrap_or_else(|_| "Invalid UTF-8".to_string())
                    }
                    MetaValue::Number(n) => n.to_string(),
                    MetaValue::Bool(b) => b.to_string(),
                }
            } else {
                num.to_string()
            };
            let value_str = if let Some(second) = values.get(1) {
                match second {
                    MetaValue::String(s) => s.clone(),
                    MetaValue::Bytes(b) => {
                        String::from_utf8(b.clone()).unwrap_or_else(|_| "Invalid UTF-8".to_string())
                    }
                    MetaValue::Number(n) => n.to_string(),
                    MetaValue::Bool(b) => b.to_string(),
                }
            } else {
                format!("value{}", num.to_string())
            };
            set_fields!(one_object, key, value_str, { "action", "score" });
            meta[key] = json!(value_str);
        }

        for string_match in rule.strings {
            let data_str = match string_match.data {
                DataValue::String(s) => BASE64_STANDARD.encode(s.as_bytes()),
                DataValue::Bytes(b) => BASE64_STANDARD.encode(&b),
            };
            strings.push(json!(
                {
                    "offset":string_match.start,
                    "str":&data_str
                }
            ))
        }

        one_object["meta"] = json!(meta);
        one_object["matched_str"] = json!(strings);
        final_value.push(one_object)
    }

    Ok(final_value)
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct UrlDict {
    #[serde(rename = "primitiveUrl")]
    primitive_url: String,
    protocol: String,
    hostname: String,
    port: Option<u16>,
    path: String,
    parameters: String,
}

fn decide_name(scan_type: &str, data: &Vec<u8>) -> anyhow::Result<String> {
    match scan_type {
        "domain" => Ok("domain".to_string()),
        "whitelist" => Ok("body".to_string()),
        "white" => Ok("body".to_string()),
        "text" => Ok("body".to_string()),
        "url" => decide_url_name(data),
        // TODO: 做到配置文件中，之后从配置文件里读取
        _other => Ok("body".to_string()),
    }
}

fn decide_url_name(data: &Vec<u8>) -> anyhow::Result<String> {
    let url_dict: UrlDict = serde_json::from_slice(data)?;
    Ok(url_dict.primitive_url)
}

// fn read_file_to_vec_u8(file_path: &str) -> anyhow::Result<Vec<u8>> {
//     let mut file = File::open(file_path)?;
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;
//     Ok(buffer)
// }
