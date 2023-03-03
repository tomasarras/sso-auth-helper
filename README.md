# SSO Auth Helper

## Docker
1 Rename **.env.example.docker** to **.env**<br>
2 ```docker-compose up```

## Local
1 Rename **.env.example.local** to **.env** <br>
2 ```node app.js``` (requires redis running)

## Postman
1 Import collection:<br>
Collections->import->upload files->**sso-auth-helper.postman_collection.json**<br><br>
2 Import environment:<br>
Environments->import->upload files->**sso-auth-helper-local.postman_environment.json**