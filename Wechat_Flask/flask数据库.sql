create database wechat_chat;
-- 切换到目标数据库（如果需要）
USE wechat_chat;

-- 创建 users 表（如果表已存在则先删除，谨慎使用！）
-- 若不想删除原有表，可去掉 DROP TABLE IF EXISTS 这一行
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    -- 主键ID，自增
    id INT NOT NULL AUTO_INCREMENT COMMENT '用户主键ID',
    -- 用户名，唯一索引，不允许为空
    username VARCHAR(50) NOT NULL COMMENT '用户名',
    -- 密码，不允许为空（建议存储加密后的密码）
    password VARCHAR(500) NOT NULL COMMENT '用户密码（加密存储）',
    -- 在线状态，tinyint(1) 通常用于布尔值（0/1）
    online TINYINT(1) NULL COMMENT '在线状态：0-离线，1-在线',
    -- 登录失败次数，默认值0
    login_attempts INT NULL DEFAULT 0 COMMENT '登录失败尝试次数',
    -- 账号锁定时间
    lock_time DATETIME NULL COMMENT '账号锁定截止时间',
    -- 验证码
    verify_code VARCHAR(4) NULL COMMENT '短信/邮箱验证码',
    -- 角色，默认值user
    role VARCHAR(20) NULL DEFAULT 'user' COMMENT '用户角色：user-普通用户，admin-管理员等',
    -- 是否被封禁，默认值0
    is_banned TINYINT(1) NULL DEFAULT 0 COMMENT '是否被封禁：0-未封禁，1-封禁',
    -- 是否被禁言，默认值0
    is_muted TINYINT(1) NULL DEFAULT 0 COMMENT '是否被禁言：0-未禁言，1-禁言',
    -- 登录设备信息
    login_device VARCHAR(100) NULL COMMENT '最近登录设备信息',
    -- 最后登录时间
    last_login_time DATETIME NULL COMMENT '最后登录时间',
    -- 当前有效会话ID
    current_session_id VARCHAR(100) NULL COMMENT '当前有效会话ID',
    
    -- 主键约束（对应 PRI）
    PRIMARY KEY (id),
    -- 唯一索引（对应 UNI），确保用户名不重复
    UNIQUE INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='用户信息表';