/// 检查传入的yara字符串的合法性
pub fn check_yara_str_effectiveness(s: &[u8]) -> anyhow::Result<()> {
    let mut compiler = yara_x::Compiler::new();

    compiler
        .add_source(s)
        .map_err(|e| anyhow::anyhow!("Error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_yara_rule() {
        let s = r#"
    rule lorem_ipsum {
      strings:
        $ = "Lorem ipsum"
        $hex1 = { 4D 5A  90 00 }
      condition:
        all of them
    }
"#
        .as_bytes();
        assert!(check_yara_str_effectiveness(s).is_ok());
    }
}
