# Annuaire des Entreprises

## Configuration

| Variable                          | Default                                   | Description                                                                                   |
| --------------------------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| PORT                              | 3000                                      | Port d'écoute                                                                                 |
| AUTHORIZED_USER_EMAILS CSV        |                                           | Liste des emails ayant accès à la zone protégée (sensible à la casse)                         |
| IRON_SESSION_PWD                  |                                           | Mot de passe de protection du cookie de session (au moins 32 caractères)                      |
| OPENID_CLIENT_ID                  |                                           |                                                                                               |
| OPENID_CLIENT_SECRET              |                                           |                                                                                               |
| OPENID_URL_DISCOVER               |                                           |                                                                                               |
| OPENID_REDIRECT_URI               |                                           |                                                                                               |
| OPENID_POST_LOGOUT_REDIRECT_URI   |                                           |                                                                                               |
| VERIFY_BROWSER_SIGNATURE          | 1                                         | Déconnecte automatiquement l'utilisateur si son navigateur a changé                           |
| VERIFY_IP_ADDRESS                 | 1                                         | Déconnecte automatiquement l'utilisateur si son adresse IP a changée                          |
| AUTH_COOKIE_NAME                  | annuaire-entreprises-admin-auth-session   | Nom du cookie de session                                                                      |
| AUTH_COOKIE_DOMAIN                | localhost                                 | @see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value |
| AUTH_COOKIE_TTL                   | 3600                                      | @see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#max-agenumber      |
