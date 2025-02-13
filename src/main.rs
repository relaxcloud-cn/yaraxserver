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
use dotenvy::dotenv;
use entity::prelude::*;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter, Set,
};

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
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
