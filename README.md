1.[授权码模式](https://blog.csdn.net/weixin_43356507/article/details/131006763#t25)

2.[设备码模式](https://blog.csdn.net/weixin_43356507/article/details/131050408#t9)

3.[客户端模式](https://blog.csdn.net/qq_41896122/article/details/131457350#t2)

发送post请求,服务器验证过"Authorization: Basic dG9rZW4tY2xpZW50OjEyMzQ1Ng=="后就能成功获取access_token

```bash
curl --location --request POST 'http://127.0.0.1:8080/oauth2/token' \
--header 'Authorization: Basic dG9rZW4tY2xpZW50OjEyMzQ1Ng==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=client_credentials'
```

4.自定义-用户密码模式：

发送post请求用户名密码正确就可以成功获取access_token

```bash
curl --location --request POST 'http://127.0.0.1:8080/oauth2/token' \
--header 'Authorization: Basic dXNlci1jbGllbnQ6MTIzNDU2' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=admin' \
--data-urlencode 'password=123456' \
--data-urlencode 'scope=test01' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:user_code'
```

> dXNlci1jbGllbnQ6MTIzNDU2= 是{$clientId}:{$clientSecret}拼接Base64编码
