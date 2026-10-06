use clap::Parser; //导入解析库和“资格证
use reqwest::blocking::Client; //create+模块+工具，同步
use serde_json::{Value, json}; //导入库中的类型和宏，感叹号就是宏，json方便编程
use std::io::{self, Write}; //std standard library //self帮助省略io的引入，让io和write这个资格证一起引入
use std::time::Duration; //时间测量

#[derive(Parser)] //能够自动读取，通过一个派生宏derive
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:7878")]
    url: String,
}
fn input(prompt: &str) -> io::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}
fn read_text() -> io::Result<String> {
    println!("逐行输入文字，单独一行 . 表示结束（正文里想要单独一行有“.” 就敲 ..）");
    let mut lines: Vec<String> = Vec::new();
    loop {
        let line = input("")?;
        let finished = line == ".";
        lines.push(line);
        if finished {
            break;
        }
    }
    Ok(rm_client_sync::join_text(&lines))
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let client = Client::builder()
        .timeout(Duration::from_secs(12))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut token = String::new();
    loop {
        let command = match input(
            "ping / register / login / logout / list / echo / delete-user / put / get / delete / q > ",
        ) {
            Ok(command) => command,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        };
        let mut body = Value::Null;
        let (method, path) = match command.as_str() {
            "q" => break,
            "ping" => ("GET", "/ping".to_string()),
            "list" => ("GET", "/texts".to_string()),
            "logout" => ("DELETE", "/sessions/current".to_string()),
            "register" | "login" => {
                body = json!({"username": input("username: ")?, "password": rpassword::prompt_password("password: ")?});
                (
                    "POST",
                    if command == "register" {
                        "/users".to_string()
                    } else {
                        "/sessions".to_string()
                    },
                )
            }
            "echo" => {
                body = json!({ "text": read_text()? });
                ("POST", "/echo".to_string())
            }
            // Both text commands name their target the same way: the path is built
            // from the name the user types. The owner is never part of it, because
            // the server derives that from the token.
            "put" => {
                let name = input("text name: ")?;
                body = json!({ "text": read_text()? });
                ("PUT", format!("/texts/{name}"))
            }
            "get" => {
                let name = input("text name: ")?;
                ("GET", format!("/texts/{name}"))
            }
            "delete-user" | "delete" => {
                println!("This task is not implemented in the starting code yet.");
                continue;
            }
            _ => {
                println!("Unknown command.");
                continue;
            }
        };
        let result = rm_client_sync::exchange(
            &client,
            &args.url,
            method.parse().unwrap(),
            &path,
            &token,
            if body.is_null() { None } else { Some(&body) },
        );
        match result {
            Ok((status, value)) => {
                println!("{status} {value}");
                if command == "login"
                    && status == 200
                    && let Some(next) = value["data"]["token"].as_str()
                {
                    token = next.into();
                }
                if status == 401 {
                    println!("Please log in again.");
                }
                if status == 401 || (command == "logout" && status == 200) {
                    token.clear();
                }
            }
            Err(error) => eprintln!("Request failed: {error}"),
        }
    }
    Ok(())
}
