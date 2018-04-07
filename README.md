# spring-jwt-gateway
A JWT based authentication api gateway based on Spring Cloud Gateway

This api gateway can be used to provide a central place to authenticate JWT token for all the back-ends services, and if the request is authenticated, this gateway will add 'X-jwt-sub=xxx' in the request http header, then all the backend services can use this customized header to do its own authorization. The 'X-jwt-sub' header value is extracted from the provided JWT token. 

This is still under development until the Spring Cloud Gateway 2.0 officially released. 

Road Map:
- Support JWT RSA256 and HMAC algorithm. Right now only RSA256 is supported to verify JWT token.
- Support to inject more JWT fields (issuer, expire_at) in the header.
- Support official Spring Cloud Gateway 2.0.
- Change the configuration more easy.
- Support Docker.
- Support Rate Limiter.

Get Started:
- git checkout and run maven install 
- modify the application.yaml file example for your needs
- you must provide 2 environment variables: '${jwt.issuer}' and '${jwt.audience}' when launching this app
- then enjoy
