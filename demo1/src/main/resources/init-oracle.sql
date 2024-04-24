-- 用户授权确认表
CREATE TABLE oauth2_authorization_consent
(
    registered_client_id VARCHAR2(100) NOT NULL,
    principal_name       VARCHAR2(200) NOT NULL,
    authorities          VARCHAR2(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- 用户认证信息表
CREATE TABLE oauth2_authorization
(
    id                            VARCHAR2(100) NOT NULL,
    registered_client_id          VARCHAR2(100) NOT NULL,
    principal_name                VARCHAR2(200) NOT NULL,
    authorization_grant_type      VARCHAR2(100) NOT NULL,
    authorized_scopes             VARCHAR2(1000),
    attributes                    BLOB,
    state                         VARCHAR2(500),
    authorization_code_value      BLOB,
    authorization_code_issued_at  TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    authorization_code_metadata   BLOB,
    access_token_value            BLOB,
    access_token_issued_at        TIMESTAMP,
    access_token_expires_at       TIMESTAMP,
    access_token_metadata         BLOB,
    access_token_type             VARCHAR2(100),
    access_token_scopes           VARCHAR2(1000),
    oidc_id_token_value           BLOB,
    oidc_id_token_issued_at       TIMESTAMP,
    oidc_id_token_expires_at      TIMESTAMP,
    oidc_id_token_metadata        BLOB,
    refresh_token_value           BLOB,
    refresh_token_issued_at       TIMESTAMP,
    refresh_token_expires_at      TIMESTAMP,
    refresh_token_metadata        BLOB,
    user_code_value               BLOB,
    user_code_issued_at           TIMESTAMP,
    user_code_expires_at          TIMESTAMP,
    user_code_metadata            BLOB,
    device_code_value             BLOB,
    device_code_issued_at         TIMESTAMP,
    device_code_expires_at        TIMESTAMP,
    device_code_metadata          BLOB,
    PRIMARY KEY (id)
);

-- 客户端表
CREATE TABLE oauth2_registered_client
(
    id                            VARCHAR2(100) NOT NULL,
    client_id                     VARCHAR2(100) NOT NULL,
    client_id_issued_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 VARCHAR2(200),
    client_secret_expires_at      TIMESTAMP,
    client_name                   VARCHAR2(200) NOT NULL,
    client_authentication_methods VARCHAR2(1000) NOT NULL,
    authorization_grant_types     VARCHAR2(1000) NOT NULL,
    redirect_uris                 VARCHAR2(1000),
    post_logout_redirect_uris     VARCHAR2(1000),
    scopes                        VARCHAR2(1000) NOT NULL,
    client_settings               VARCHAR2(2000) NOT NULL,
    token_settings                VARCHAR2(2000) NOT NULL,
    PRIMARY KEY (id)
);