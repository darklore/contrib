package com.lbg.kafka.opa;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.gson.Gson;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.Cleanup;
import lombok.Data;
import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.server.authorizer.AclCreateResult;
import org.apache.kafka.server.authorizer.AclDeleteResult;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.Authorizer;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpaAuthorizer2 implements Authorizer {

  private static final Logger log = LoggerFactory.getLogger(OpaAuthorizer2.class);
  // Use "kafka.authorizer.logger" topic to log DENY and ALLOW action. See log4j.properties
  private static final Logger authorizerLog = LoggerFactory.getLogger("kafka.authorizer.logger");

  private final static String OPA_AUTHORIZER_URL_CONFIG = "opa.authorizer.url";
  private final static String OPA_AUTHORIZER_DENY_ON_ERROR_CONFIG = "opa.authorizer.allow.on.error";
  private final static String OPA_AUTHORIZER_CACHE_INITIAL_CAPACITY_CONFIG = "opa.authorizer.cache.initial.capacity";
  private final static String OPA_AUTHORIZER_CACHE_MAXIMUM_SIZE_CONFIG = "opa.authorizer.cache.maximum.size";
  private final static String OPA_AUTHORIZER_CACHE_EXPIRE_AFTER_MS_CONFIG = "opa.authorizer.cache.expire.after.ms";
  private final static String OPA_AUTHORIZER_TOKEN = "opa.authorizer.token";

  private final Gson gson = new Gson();
  private final Map<String, Object> configs = new HashMap<>();

  private String opaUrl;
  private AuthorizationResult resultOnError = AuthorizationResult.DENIED;
  private int initialCapacity;
  private int maximumSize;
  private long expireAfterMs;
  private String opaToken;
  private LoadingCache<OpaQuery.Input, AuthorizationResult> cache;

  @Data
  static class OpaQuery {

    private final Input input;

    @Data
    static class Input {

      private final Operation operation;
      private final Resource resource;
      private final Session session;

      @Data
      static class Operation {

        private final String name;
      }

      @Data
      static class Resource {

        private final String name;
        private final ResourceType resourceType;

        @Data
        static class ResourceType {

          private final String name;
        }
      }

      @Data
      static class Session {

        private final String clientAddress;
        private final Principal principal;

        @Data
        static class Principal {

          private final String name;
          private final String principalType;
        }
      }
    }
  }

  public OpaAuthorizer2() {
    configure(new HashMap<>());
  }

  private LoadingCache<OpaQuery.Input, AuthorizationResult> buildCache() {
    return CacheBuilder.newBuilder()
      .initialCapacity(initialCapacity)
      .maximumSize(maximumSize)
      .expireAfterWrite(expireAfterMs, TimeUnit.MILLISECONDS)
      .build(
        new CacheLoader<>() {
          @Override
          public AuthorizationResult load(OpaQuery.Input key) {
            log.debug("cache load");
            return allow(key);
          }
        });
  }

  private AuthorizationResult allow(OpaQuery.Input input) {
    try {
      HttpURLConnection conn = (HttpURLConnection) new URL(opaUrl).openConnection();

      conn.setDoOutput(true);
      conn.setRequestMethod("POST");
      conn.setRequestProperty("Content-Type", "application/json");
      if (!opaToken.isEmpty()) {
        conn.setRequestProperty("Authorization", "Bearer " + opaToken);
      }

      String data = gson.toJson(new OpaQuery(input));
      OutputStream os = conn.getOutputStream();
      os.write(data.getBytes());
      os.flush();

      log.debug("Response code: {}, Request data: {}", conn.getResponseCode(), data);

      @Cleanup BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      String ret = br.readLine();
      log.debug("Response: {}", ret);
      boolean result = (boolean) gson.fromJson(ret, Map.class).get("result");

      if (result) {
        return AuthorizationResult.ALLOWED;
      } else {
        return AuthorizationResult.DENIED;
      }
    } catch (IOException e) {
      log.error("Error when communicating OPA server", e);
      return resultOnError;
    }
  }

  private String getValueOrDefault(String property, String defaultValue) {
    return Optional.ofNullable((String) configs.get(property)).orElse(defaultValue);
  }

  private AuthorizationResult authorizeOne(AuthorizableRequestContext requestContext,
    Action action) {
    var operation = new OpaQuery.Input.Operation(action.operation().name());
    var resource = new OpaQuery.Input.Resource(
      action.resourcePattern().name(),
      new OpaQuery.Input.Resource.ResourceType(action.resourcePattern().resourceType().name()));
    var session = new OpaQuery.Input.Session(
      requestContext.clientAddress().getHostAddress(),
      new OpaQuery.Input.Session.Principal(requestContext.principal().getName(),
        requestContext.principal().getPrincipalType()));

    var input = new OpaQuery.Input(operation, resource, session);

    AuthorizationResult result;
    try {
      result = cache.get(input);
    } catch (ExecutionException e) {
      log.error("Error when communicating ACL cache", e);
      result = resultOnError;
    }

    // Access denials are logged at INFO level, change to DEBUG to also log allowed accesses
    // See log4j.properties
    if (result == AuthorizationResult.DENIED) {
      authorizerLog.info("Result: {}, OpaQuery: {}", result, input);
    } else {
      authorizerLog.debug("Result: {}, OpaQuery: {}", result, input);
    }
    return result;
  }

  @Override
  public Map<Endpoint, ? extends CompletionStage<Void>> start(
    AuthorizerServerInfo authorizerServerInfo) {
    Map<Endpoint, CompletionStage<Void>> completableFutureStream = authorizerServerInfo.endpoints()
      .stream().collect(Collectors
        .toMap(endpoint -> endpoint, endpoint -> CompletableFuture.completedFuture(null)));

    if (log.isTraceEnabled()) {
      log.trace("start {}", completableFutureStream);
    }
    return completableFutureStream;
  }

  @Override
  public List<AuthorizationResult> authorize(AuthorizableRequestContext requestContext,
    List<Action> actions) {
    if (log.isTraceEnabled()) {
      log.trace(
        "AuthorizableRequest listener:{}, protocol:{}, clientAddress:{}, principal:{}, principalType:{}, clientID:{}, requestType; {}",
        requestContext.listenerName(), requestContext.securityProtocol().name,
        requestContext.clientAddress(),
        requestContext.principal(), requestContext.principal().getPrincipalType(),
        requestContext.clientId(), requestContext.requestType());
      log.trace("Actions {}", actions);
    }
    return actions.stream().map(action -> authorizeOne(requestContext, action))
      .collect(Collectors.toList());
  }

  @Override
  public void configure(Map<String, ?> configs) {
    this.configs.clear();
    this.configs.putAll(configs);

    log.info("CONFIGS: {}", this.configs);

    opaUrl = getValueOrDefault(OPA_AUTHORIZER_URL_CONFIG, "http://localhost:8181");
    initialCapacity = Integer
      .parseInt(getValueOrDefault(OPA_AUTHORIZER_CACHE_INITIAL_CAPACITY_CONFIG, "100"));
    maximumSize = Integer
      .parseInt(getValueOrDefault(OPA_AUTHORIZER_CACHE_MAXIMUM_SIZE_CONFIG, "100"));
    expireAfterMs = Long
      .parseLong(getValueOrDefault(OPA_AUTHORIZER_CACHE_EXPIRE_AFTER_MS_CONFIG, "600000"));
    opaToken = getValueOrDefault(OPA_AUTHORIZER_TOKEN, "");
    boolean allowOnError = Boolean
      .parseBoolean(getValueOrDefault(OPA_AUTHORIZER_DENY_ON_ERROR_CONFIG, "false"));

    if (allowOnError) {
      resultOnError = AuthorizationResult.ALLOWED;
    } else {
      resultOnError = AuthorizationResult.DENIED;
    }
    cache = buildCache();
  }

  @Override
  public List<? extends CompletionStage<AclCreateResult>> createAcls(
    AuthorizableRequestContext requestContext,
    List<AclBinding> aclBindings) {
    log.trace("createAcls");
    return null;
  }

  @Override
  public List<? extends CompletionStage<AclDeleteResult>> deleteAcls(
    AuthorizableRequestContext requestContext,
    List<AclBindingFilter> aclBindingFilters) {
    log.trace("deleteAcls");
    return null;
  }

  @Override
  public Iterable<AclBinding> acls(AclBindingFilter filter) {
    log.trace("acls");
    return null;
  }

  @Override
  public void close() {
    log.info("close");
  }
}
