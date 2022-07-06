# Password-Migration
Java example of a web service that can facilitate the migration of a users credentials from Azure to Okta.

Before building the war file, update the /src/main/java/iamse.properties file with:
1. token_endpoint - The complete URL to the Azure token endpoint. This will be used to authenticate the user.
2. client_id - The Client Id of the Azure OAuth application
