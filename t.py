import psycopg2


conn_info = {
    "dbname": "postgres",  # 数据库名称
    "user": "postgres",    # 数据库用户名
    "password": "postgres",  # 数据库密码
    "host": "localhost",   # 数据库主机地址（如果使用 Docker，默认为 localhost）
    "port": "5432"         # 数据库端口
}

try:
    # 建立连接
    conn = psycopg2.connect(**conn_info)
    print("连接成功！")
    
    # 创建游标
    cursor = conn.cursor()
    
    # 执行查询
    cursor.execute("SELECT version();")
    result = cursor.fetchone()
    print("PostgreSQL 版本：", result)
    
    # 关闭游标和连接
    cursor.close()
    conn.close()
except Exception as e:
    print("连接失败：", e)