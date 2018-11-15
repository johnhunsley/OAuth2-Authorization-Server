# OAuth2-Authorization-Server
A Spring Boot 2 OAuth2 Authorization Server which provides JWT Tokens for users to access the resource server in a Authorization Code Grant flow.

This working example of an Authorization can be run along with the an example [Client](https://github.com/johnhunsley/OAuth2-Client) and example [Resource](https://github.com/johnhunsley/OAuth2-Resource-Server) Service as show below.

![OAuth2 Code Grant](./OAuth%20Code%20Grant.png "OAuth2 Code Grant")

1. Resource Owner, the User, Opens a browser and makes a request to the client application for their resource. Client app redirects the users browser to a page on the auth server to authenitcate
2. user enters credentials (username/password) submits request to authenticate. Auth server receives request, loads user by username, checks pass, authenitcates. returns a redirect to the client with a temporary code and state for CSRF check
3. Client receives request with the code and makes the request to the auth server to exchange it for a token which it creates with the private key.
4. Client makes the request to the resource server with the token which is decrypted with the public key. Access to the resource is restricted by the scope or custom claim in the key

 
