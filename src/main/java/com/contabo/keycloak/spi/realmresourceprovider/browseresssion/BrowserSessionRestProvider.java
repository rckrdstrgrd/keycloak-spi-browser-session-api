package com.contabo.keycloak.spi.realmresourceprovider.browseresssion;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authorization.util.Tokens;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.MediaType;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;

import javax.ws.rs.Encoded;
import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

public class BrowserSessionRestProvider implements RealmResourceProvider {

  private final KeycloakSession keycloakSession;

  public BrowserSessionRestProvider(KeycloakSession session) {
    this.keycloakSession = session;
  }

  public void close() {
    // NOP
  }

  public Object getResource() {
    return this;
  }

  @OPTIONS
  @Path("init")
  @NoCache
  @Produces({ MediaType.TEXT_PLAIN_UTF_8 })
  @Encoded
  public Response checkCORS(@QueryParam("publicClient") String targetClient) {
    String BSAPI_ACCESS_CONTROL_ALLOW_HEADERS = System.getenv("BSAPI_ACCESS_CONTROL_ALLOW_HEADERS");
    if (null == BSAPI_ACCESS_CONTROL_ALLOW_HEADERS) {
      BSAPI_ACCESS_CONTROL_ALLOW_HEADERS = "origin, content-type, accept, authorization";
    }
    String accessControlAllowOrigin = this.getAccessControlAllowOrigin(targetClient);
    return Response
        .status(200)
        .header("Access-Control-Allow-Origin", accessControlAllowOrigin)
        .header("Access-Control-Allow-Credentials", "true")
        .header("Access-Control-Allow-Headers",
            BSAPI_ACCESS_CONTROL_ALLOW_HEADERS)
        .header("Access-Control-Allow-Methods",
            "GET, OPTIONS")
        .entity("")
        .build();
  }

  @GET
  @Path("init")
  @NoCache
  @Produces({ MediaType.TEXT_HTML_UTF_8 })
  @Encoded
  public Response setSessionCookies(@QueryParam("clientId") String targetClient,
      @QueryParam("redirect_uri") String redirectUri) {
    AccessToken validToken = this.validateAccessToken();

    ClientModel newClient = this.getValidatedTargetClient(targetClient);
    final RealmModel realm = this.keycloakSession.getContext().getRealm();

    // create new user session and bind it to the target client Id
    final UserModel user = this.keycloakSession.users().getUserById(realm, validToken.getSubject());
    final ClientConnection clientConnection = this.keycloakSession.getContext().getConnection();
    UserSessionModel newUserSession = this.keycloakSession.sessions().createUserSession(realm, user, user.getUsername(),
        clientConnection.getRemoteAddr(), "KEYCLOAK", false, null, null);
    this.keycloakSession.sessions().createClientSession(realm,
        newClient, newUserSession);

    // finally create cookies
    final UriInfo uriInfo = this.keycloakSession.getContext().getUri();
    AuthenticationManager.createLoginCookie(this.keycloakSession, realm,
        newUserSession.getUser(), newUserSession,
        uriInfo, clientConnection);

    String accessControlAllowOrigin = this.getAccessControlAllowOrigin(targetClient);

    String decodedRedirectUri;
    try {
      decodedRedirectUri = URLDecoder.decode(
          redirectUri, "UTF-8");
    } catch (Exception e) {
      throw new ErrorResponseException(Errors.INVALID_REQUEST, "Malformed request, invalid redirect uri",
          Response.Status.UNAUTHORIZED);
    }

    String validRedirectUri = RedirectUtils.verifyRedirectUri(
        this.keycloakSession,
        decodedRedirectUri,
        newClient);

    if (validRedirectUri != null) {
      return Response.temporaryRedirect(URI.create(validRedirectUri)).build();
    }

    return Response
        .noContent()
        .header("Access-Control-Allow-Origin", accessControlAllowOrigin)
        .header("Access-Control-Allow-Credentials", "true")
        .build();
  }

  private String getAccessControlAllowOrigin(String targetClient) {
    ClientModel newClient = this.getValidatedTargetClient(targetClient);
    // get referer
    String refererHeader = this.keycloakSession.getContext().getRequestHeaders().getHeaderString("Referer");
    String referer;
    try {
      URL url;
      url = new URL(refererHeader);
      String protocol = url.getProtocol();
      String authority = url.getAuthority();
      referer = String.format("%s://%s", protocol, authority);
    } catch (MalformedURLException e) {
      referer = "";
    }
    newClient.getRedirectUris();
    // search for matching web origin
    for (String currentWebOrigin : newClient.getWebOrigins()) {
      if (currentWebOrigin.equals("*")) {
        // `*` not allowed when `Access-Control-Allow-Credentials` is `true`
        return referer;
      }
      if (currentWebOrigin.equalsIgnoreCase(referer)) {
        return referer;
      }
    }

    // fail with empty one
    return "";
  }

  private ClientModel getValidatedTargetClient(String targetClient) {
    final RealmModel realm = this.keycloakSession.getContext().getRealm();
    ClientModel newClient = this.keycloakSession.clients().getClientByClientId(realm, targetClient);
    if (null == newClient || !newClient.isPublicClient()) {
      throw new ErrorResponseException(Errors.CLIENT_NOT_FOUND, "Client not found or not public",
          Response.Status.BAD_REQUEST);
    }
    return newClient;
  }

  private AccessToken validateAccessToken() {
    final HttpHeaders headers = this.keycloakSession.getContext().getRequestHeaders();
    final String authorization = headers.getHeaderString(HttpHeaders.AUTHORIZATION);
    if (authorization == null) {
      throw new ErrorResponseException(Errors.INVALID_TOKEN, "No authorization header provided",
          Response.Status.UNAUTHORIZED);
    }
    final String[] authorizationParts = authorization.split(" ");
    if (authorizationParts.length != 2 || !authorizationParts[0].toLowerCase().equals("bearer")) {
      throw new ErrorResponseException(Errors.INVALID_TOKEN, "Malformed access token", Response.Status.UNAUTHORIZED);
    }
    final String accessToken = authorizationParts[1];
    final AccessToken token = Tokens.getAccessToken(accessToken, this.keycloakSession);
    if (token == null) {
      throw new ErrorResponseException(Errors.INVALID_TOKEN, "Invalid or expired access token",
          Response.Status.UNAUTHORIZED);
    }
    return token;
  }
}
