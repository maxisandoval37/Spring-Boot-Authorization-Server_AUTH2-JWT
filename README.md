# Spring Boot OAuth2 Project

This project consists of two Spring Boot applications:

1. **auth2-server-app**: An authorization server.
2. **auth-client-app**: A client application interacting with the authorization server.

---

## Prerequisites

- Java 11+
- Maven 3.6+
- Spring Boot framework

---

## Dependencies

### auth2-server-app

- spring-boot-starter-web
- spring-boot-starter-security
- spring-boot-starter-oauth2-authorization-server
- spring-boot-devtools
- lombok

### auth-client-app

- spring-boot-starter-oauth2-client
- spring-boot-starter-security
- spring-boot-starter-web
- spring-security-oauth2-resource-server
- spring-boot-devtools
- lombok

---

## Testing the Application

### 1. Obtain Authorization Code

**Request:**
```http
POST http://127.0.0.1:8081/login
```
**Body:**
```plaintext
user:password1
```
**Response:**
```json
{
  "code": "<GENERATED_AUTHORIZATION_CODE>"
}
```

### 2. Exchange Authorization Code for Tokens

**Request:**
```http
POST http://127.0.0.1:8081/oauth2/token
```
**Headers:**
```plaintext
Authorization: app-client:password-client
```
**Body (form-data):**
- `code`: `<GENERATED_AUTHORIZATION_CODE>`
- `grant_type`: `authorization_code`
- `redirect_uri`: `http://127.0.0.1:8080/authorized`

**Response:**
```json
{
    "access_token": "<ACCESS_TOKEN>",
    "refresh_token": "<REFRESH_TOKEN>",
    "scope": "read openid profile write",
    "id_token": "<ID_TOKEN>",
    "token_type": "Bearer",
    "expires_in": 300
}
```

### 3. Create a Message

**Request:**
```http
POST http://127.0.0.1:8080/createMessage
```
**Headers:**
```plaintext
Authorization: Bearer <ACCESS_TOKEN>
```
**Body (raw):**
```json
{
    "text": "test123"
}
```
**Response:**
```json
{
    "text": "test123"
}
```

### 4. List Messages

**Request:**
```http
GET http://127.0.0.1:8080/listMessages
```
**Headers:**
```plaintext
Authorization: Bearer <ACCESS_TOKEN>
```
**Response:**
```json
[
    {
        "text": "Test"
    }
]
```

---

## Notes

- Replace placeholders (e.g., `<ACCESS_TOKEN>`, `<GENERATED_AUTHORIZATION_CODE>`) with actual values.
- Ensure both apps are running on their respective ports (`8081` for the auth2-server-app and `8080` for the auth-client-app).

---

## License

This project is licensed under the MIT License.

---

## Author

### Created By: [Maximiliano Sandoval](https://github.com/maxisandoval37)
