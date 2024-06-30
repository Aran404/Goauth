
# Goauth

An open source proof of concept license authentication system inspired by Keyauth. 
A cryptographically secure server with a pre-made SDK/client as an example.




## Features (Cryptography)

- JWT Protected Endpoints
- Bcrypt Password Hashing
- SHA-512 HMAC Request Signing
- DHKE w/AES-256-CBC Encrypted Requests
- Customizable Context Windows

## Features (API)

- / (**WS**: Preform DHKE)
- /license (**Encrypted**: Validate License)
- /register (**Encrypted**: Create Account)
- /login (**Encrypted**: Returns JWT Tokens)
- /logout (**JWT**: Delete JWT Token)
- /refresh (**JWT**: Refresh Access Token)
- /create-owner (**Admin**: Creates an OwnerID)
- /create-application (**Owner**: Creates an Application)
- /create-license (**Owner**: Creates a License)



## API Reference

#### Validate a license

```http
  POST /license
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `integrity_signature` | `string` | **Required**. A hash of the binary |
| `fingerprint` | `string` | **Required**. A device-based fingerprint |
| `app_id` | `string` | **Required**. Application ID |
| `owner_id` | `string` | **Required**. Owner ID |
| `license_key` | `string` | **Required**. Unique License Key |


## License

[MIT](https://choosealicense.com/licenses/gpl-3.0/)

