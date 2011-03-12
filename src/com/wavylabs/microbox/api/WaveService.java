/* Copyright (c) 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.wavylabs.microbox.api;

import com.google.gson.Gson;
import com.google.wave.api.JsonRpcResponse;
import com.google.wave.api.OperationQueue;
import com.google.wave.api.ProtocolVersion;
import com.google.wave.api.impl.GsonFactory;

import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthValidator;
import net.oauth.SimpleOAuthValidator;
import net.oauth.client.OAuthClient;
import net.oauth.http.HttpClient;
import net.oauth.http.HttpMessage;
import net.oauth.http.HttpResponseMessage;
import net.oauth.signature.OAuthSignatureMethod;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.waveprotocol.wave.model.id.InvalidIdException;
import org.waveprotocol.wave.model.id.WaveId;
import org.waveprotocol.wave.model.id.WaveletId;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.AbstractMap.SimpleEntry;
import java.util.logging.Logger;

/**
 * Utility class for using OAuth to talk to Wave service.
 */
public class WaveService {

  /**
   * Helper class to make outgoing OAuth HTTP requests.
   */
  static class HttpFetcher implements HttpClient {

    /** The {@code urlfetch} fetch timeout in ms. */
    private static final int URLFETCH_TIMEOUT_IN_MS = 10 * 1000;

    private static final String HTTP_POST_METHOD = "POST";
    private static final String HTTP_PUT_METHOD = "PUT";

    @Override
    public HttpResponseMessage execute(HttpMessage request, Map<String, Object> stringObjectMap)
        throws IOException {
      String body = readInputStream(request.getBody());
      OutputStreamWriter out = null;
      HttpURLConnection conn = null;
      // Open the connection.
      conn = (HttpURLConnection) request.url.openConnection();
      conn.setReadTimeout(URLFETCH_TIMEOUT_IN_MS);
      conn.setRequestMethod(request.method);
      // Add the headers
      if (request.headers != null) {
        for (java.util.Map.Entry<String, String> header : request.headers) {
          conn.setRequestProperty(header.getKey(), header.getValue());
        }
      }

      boolean doOutput =
          body != null && (HTTP_POST_METHOD.equalsIgnoreCase(request.method)
              || HTTP_PUT_METHOD.equalsIgnoreCase(request.method));

      if (doOutput) {
        conn.setDoOutput(true);
      }

      conn.connect();

      if (doOutput) {
        // Send the request body.
        out = new OutputStreamWriter(conn.getOutputStream(), UTF_8);
        try {
          out.write(body);
          out.flush();
        } finally {
          out.close();
        }
      }

      // Return the response stream.
      return new HttpResponse(
          request.method, request.url, conn.getResponseCode(), conn.getInputStream());
    }

    /**
     * Reads the given {@link java.io.InputStream} into a {@link String}
     *
     * @param inputStream the {@link java.io.InputStream} to be read.
     * @return a string content of the {@link java.io.InputStream}.
     * @throws IOException if there is a problem reading the stream.
     */
    static String readInputStream(InputStream inputStream) throws IOException {
      if (inputStream == null) {
        return null;
      }
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      StringBuilder result = new StringBuilder();
      String s;
      while ((s = reader.readLine()) != null) {
        result.append(s);
      }
      return result.toString();
    }
  }

  /**
   * A simple implementation of {@link HttpResponseMessage} that gets the
   * response from {@link HttpURLConnection#getInputStream()}.
   */
  static class HttpResponse extends HttpResponseMessage {

    /** The HTTP response code. */
    private final int statusCode;

    /** The response stream. */
    private final InputStream responseStream;

    /**
     * Constructor.
     *
     * @param method the HTTP method, for example, GET or POST.
     * @param url the URL where the response comes from.
     * @param statusCode the HTTP response code.
     * @param responseStream the response stream.
     */
    public HttpResponse(String method, URL url, int statusCode, InputStream responseStream) {
      super(method, url);
      this.statusCode = statusCode;
      this.responseStream = responseStream;
    }

    @Override
    public int getStatusCode() {
      return statusCode;
    }

    @Override
    public InputStream openBody() {
      return responseStream;
    }
  }

  /**
   * Helper class that contains various OAuth credentials.
   */
  static class ConsumerData {

    /** Consumer key used to sign the operations in the active mode. */
    private final String consumerKey;

    /** Consumer secret used to sign the operations in the active mode. */
    private final String consumerSecret;

    /** The URL that handles the JSON-RPC request in the active mode. */
    private final String rpcServerUrl;

    /** Whether this session is user authenticated */
    private final boolean userAuthenticated;

    /** The OAuth Accessor contains authentication data used to make requests */
    private final OAuthAccessor accessor;

    /**
     * Constructor.
     *
     * @param consumerKey the consumer key.
     * @param consumerSecret the consumer secret
     * @param rpcServerUrl the URL of the JSON-RPC request handler
     */
    public ConsumerData(String consumerKey, String consumerSecret, String rpcServerUrl) {
      String consumerKeyPrefix = "";
      // NOTE(ljvderijk): Present for backwards capability.
      if (RPC_URL.equals(rpcServerUrl) || SANDBOX_RPC_URL.equals(rpcServerUrl)) {
        consumerKeyPrefix = "google.com:";
      }
      this.consumerKey = consumerKeyPrefix + consumerKey;
      this.consumerSecret = consumerSecret;
      this.rpcServerUrl = rpcServerUrl;

      userAuthenticated = false;
      OAuthConsumer consumer = new OAuthConsumer(null, consumerKey, consumerSecret, null);
      consumer.setProperty(OAuth.OAUTH_SIGNATURE_METHOD, OAuth.HMAC_SHA1);
      accessor = new OAuthAccessor(consumer);
    }

    public ConsumerData(OAuthAccessor accessor, String rpcServerUrl) {
      this.consumerKey = accessor.consumer.consumerKey;
      this.consumerSecret = accessor.consumer.consumerSecret;
      this.accessor = accessor;
      this.rpcServerUrl = rpcServerUrl;
      userAuthenticated = true;
    }

    /**
     * @return the consumer key used to sign the operations in the active mode.
     */
    public String getConsumerKey() {
      return consumerKey;
    }

    /**
     * @return the consumer secret used to sign the operations in the active mode.
     */
    public String getConsumerSecret() {
      return consumerSecret;
    }

    /**
     * @return the URL of the JSON-RPC request handler.
     */
    public String getRpcServerUrl() {
      return rpcServerUrl;
    }

    public boolean isUserAuthenticated() {
      return userAuthenticated;
    }

    public OAuthAccessor getAccessor() {
      return accessor;
    }

  }

  /** The wire protocol version. */
  public static final ProtocolVersion PROTOCOL_VERSION = ProtocolVersion.DEFAULT;

  private static final String JSON_MIME_TYPE = "application/json; charset=utf-8";
  private static final String OAUTH_BODY_HASH = "oauth_body_hash";
  private static final String POST = "POST";
  private static final String SHA_1 = "SHA-1";
  private static final String UTF_8 = "UTF-8";

  /** Wave RPC URLs. */
  public static final String RPC_URL = "https://www-opensocial.googleusercontent.com/api/rpc";
  public static final String SANDBOX_RPC_URL =
      "https://www-opensocial-sandbox.googleusercontent.com/api/rpc";

  private static final Logger LOG = Logger.getLogger(WaveService.class.getName());

  /** Namespace to prefix all active api operation calls. */
  private static final String OPERATION_NAMESPACE = "wave";

  /** Serializer to serialize events and operations in active mode. */
  private static final Gson SERIALIZER = new GsonFactory().create(OPERATION_NAMESPACE);

  /** OAuth request validator. */
  private static final OAuthValidator VALIDATOR = new SimpleOAuthValidator();

  /** A map of RPC server URL to its consumer data object. */
  private final Map<String, ConsumerData> consumerDataMap = new HashMap<String, ConsumerData>();

  /** A version number. */
  private final String version;

  /** A utility to make HTTP requests. */
  private final HttpFetcher httpFetcher;

  /**
   * Constructor.
   */
  public WaveService() {
    this(new HttpFetcher(), null);
  }

  /**
   * Constructor.
   *
   * @param version the version number.
   */
  public WaveService(String version) {
    this(new HttpFetcher(), version);
  }

  /**
   * Constructor.
   *
   * @param httpFetcher the fetcher to make HTTP calls.
   * @param version the version number.
   */
  public WaveService(HttpFetcher httpFetcher, String version) {
    this.httpFetcher = httpFetcher;
    this.version = version;
  }

  /**
   * Sets the OAuth related properties, including the consumer key and secret
   * that are used to sign the outgoing operations.
   *
   * <p>
   * This version of the method is for 2-legged OAuth, where the robot is not
   * acting on behalf of a user.
   *
   * <p>
   * For the rpcServerUrl you can use:
   * <ul>
   * <li>https://www-opensocial.googleusercontent.com/api/rpc - for wave
   * preview.
   * <li>
   * https://www-opensocial-sandbox.googleusercontent.com/api/rpc - for wave
   * sandbox.
   * </ul>
   *
   * @param consumerKey the consumer key.
   * @param consumerSecret the consumer secret.
   * @param rpcServerUrl the URL of the server that serves the JSON-RPC request.
   */
  public void setupOAuth(String consumerKey, String consumerSecret, String rpcServerUrl) {
    if (consumerKey == null || consumerSecret == null || rpcServerUrl == null) {
      throw new IllegalArgumentException(
          "Consumer Key, Consumer Secret and RPCServerURL " + "have to be non-null");
    }
    consumerDataMap.put(rpcServerUrl, new ConsumerData(consumerKey, consumerSecret, rpcServerUrl));
  }

  /**
   * Sets the OAuth related properties that are used to sign the outgoing
   * operations for 3-legged OAuth.
   *
   * <p>
   * Performing the OAuth dance is not part of this interface - once you've done
   * the dance, pass the constructed accessor and rpc endpoint into this method.
   *
   * <p>
   * Ensure that the endpoint URL you pass in matches exactly the URL used to
   * request an access token (including https vs http).
   *
   *  For the rpcServerUrl you can use:
   * <ul>
   * <li>https://www-opensocial.googleusercontent.com/api/rpc - for wave
   * preview.
   * <li>
   * https://www-opensocial-sandbox.googleusercontent.com/api/rpc - for wave
   * sandbox.
   * </ul>
   *
   * @param accessor the {@code OAuthAccessor} with access token and secret
   * @param rpcServerUrl the endpoint URL of the server that serves the JSON-RPC
   *        request.
   */
  public void setupOAuth(OAuthAccessor accessor, String rpcServerUrl) {
    if (accessor == null || rpcServerUrl == null) {
      throw new IllegalArgumentException("Accessor and RPCServerURL have to be non-null");
    }
    consumerDataMap.put(rpcServerUrl, new ConsumerData(accessor, rpcServerUrl));
  }

  /**
   * Validates the incoming HTTP request.
   *
   * @param requestUrl the URL of the request.
   * @param jsonBody the request body to be validated.
   * @param rpcServerUrl the RPC server URL.
   *
   * @throws OAuthException if it can't validate the request.
   */
  public void validateOAuthRequest(
      String requestUrl, Map<String, String[]> requestParams, String jsonBody, String rpcServerUrl)
      throws OAuthException {
    ConsumerData consumerData = consumerDataMap.get(rpcServerUrl);
    if (consumerData == null) {
      throw new IllegalArgumentException(
          "There is no consumer key and secret associated " + "with the given RPC URL "
              + rpcServerUrl);
    }

    List<OAuth.Parameter> params = new ArrayList<OAuth.Parameter>();
    for (Map.Entry<String, String[]> entry : requestParams.entrySet()) {
      for (String value : entry.getValue()) {
        params.add(new OAuth.Parameter(entry.getKey(), value));
      }
    }
    OAuthMessage message = new OAuthMessage(POST, requestUrl, params);

    // Compute and check the hash of the body.
    try {
      MessageDigest md = MessageDigest.getInstance(SHA_1);
      byte[] hash = md.digest(jsonBody.getBytes(UTF_8));
      String encodedHash = new String(Base64.encodeBase64(hash, false), UTF_8);
      if (!encodedHash.equals(message.getParameter(OAUTH_BODY_HASH))) {
        throw new IllegalArgumentException(
            "Body hash does not match. Expected: " + encodedHash + ", provided: "
                + message.getParameter(OAUTH_BODY_HASH));
      }

      OAuthAccessor accessor = consumerData.getAccessor();
      LOG.info("Signature base string: " + OAuthSignatureMethod.getBaseString(message));
      VALIDATOR.validateMessage(message, accessor);
    } catch (NoSuchAlgorithmException e) {
      throw new OAuthException("Error validating OAuth request", e);
    } catch (URISyntaxException e) {
      throw new OAuthException("Error validating OAuth request", e);
    } catch (OAuthException e) {
      throw new OAuthException("Error validating OAuth request", e);
    } catch (IOException e) {
      throw new OAuthException("Error validating OAuth request", e);
    }
  }

  /**
   * @return the map of consumer key and secret.
   */
  protected Map<String, ConsumerData> getConsumerDataMap() {
    return consumerDataMap;
  }

  /**
   * @return {@code true} if this service object contains a consumer key and
   *         secret for the given RPC server URL.
   */
  protected boolean hasConsumerData(String rpcServerUrl) {
    return consumerDataMap.containsKey(rpcServerUrl);
  }

  /**
   * Submits the given operations.
   *
   * @param opQueue the operation queue to be submitted.
   * @param rpcServerUrl the active gateway to send the operations to.
   * @return a list of {@link JsonRpcResponse} that represents the responses
   *         from the server for all operations that were submitted.
   *
   * @throws IllegalStateException if this method is called prior to setting the
   *         proper consumer key, secret, and handler URL.
   * @throws IOException if there is a problem submitting the operations.
   * @throws OAuthException 
   */
  public String makeRpc(OperationQueue opQueue, String rpcServerUrl)
      throws IOException, OAuthException {
    if (rpcServerUrl == null) {
      throw new IllegalStateException("RPC Server URL is not set up.");
    }

    ConsumerData consumerDataObj = consumerDataMap.get(rpcServerUrl);
    if (consumerDataObj == null) {
      throw new IllegalStateException("Consumer key, consumer secret, and  JSON-RPC server URL "
          + "have to be set first, by calling AbstractRobot.setupOAuth(), before invoking "
          + "AbstractRobot.submit().");
    }

    opQueue.notifyRobotInformation(PROTOCOL_VERSION, version);
    String json =
        SERIALIZER.toJson(opQueue.getPendingOperations(), GsonFactory.OPERATION_REQUEST_LIST_TYPE);

    try {
      InputStream bodyStream;
      InputStream responseStream;
      try {
        bodyStream = new ByteArrayInputStream(json.getBytes("UTF-8"));
      } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException(e);
      }
      if (!consumerDataObj.isUserAuthenticated()) {
        String url = createOAuthUrlString(
            json, consumerDataObj.getRpcServerUrl(), consumerDataObj.getAccessor());
        LOG.info("JSON request to be sent: " + json);
        HttpMessage request = new HttpMessage("POST", new URL(url), bodyStream);
        request.headers.add(
            new SimpleEntry<String, String>(HttpMessage.CONTENT_TYPE, JSON_MIME_TYPE));
        request.headers.add(new SimpleEntry<String, String>("oauth_version", "1.0"));
        responseStream =
            httpFetcher.execute(request, Collections.<String, Object>emptyMap()).getBody();
      } else {
        OAuthAccessor accessor = consumerDataObj.getAccessor();
        OAuthMessage message = accessor.newRequestMessage("POST", rpcServerUrl, null, bodyStream);
        message.getHeaders().add(
            new SimpleEntry<String, String>(HttpMessage.CONTENT_TYPE, "application/json"));
        message.getHeaders().add(new SimpleEntry<String, String>("oauth_version", "1.0"));
        OAuthClient client = new OAuthClient(httpFetcher);
        responseStream = client.invoke(message, net.oauth.ParameterStyle.BODY).getBodyAsStream();
      }

      String responseString = HttpFetcher.readInputStream(responseStream);
      LOG.info("Response returned: " + responseString);

      return responseString;
    } catch (URISyntaxException e) {
      LOG.warning("URISyntaxException when constructing the OAuth parameters: " + e);
      throw new IOException(e);
    }
  }

  /**
   * Creates a URL that contains the necessary OAuth query parameters for the
   * given JSON string.
   *
   * The required OAuth parameters are:
   * <ul>
   * <li>oauth_body_hash</li>
   * <li>oauth_consumer_key</li>
   * <li>oauth_signature_method</li>
   * <li>oauth_timestamp</li>
   * <li>oauth_nonce</li>
   * <li>oauth_version</li>
   * <li>oauth_signature</li>
   * </ul>
   *
   * @param jsonBody the JSON string to construct the URL from.
   * @param rpcServerUrl the URL of the handler that services the JSON-RPC
   *        request.
   * @param accessor the OAuth accessor used to create the signed string.
   * @return a URL for the given JSON string, and the required OAuth parameters.
   */
  public static String createOAuthUrlString(
      String jsonBody, String rpcServerUrl, OAuthAccessor accessor)
      throws IOException, URISyntaxException, OAuthException {
    OAuthMessage message =
        new OAuthMessage(POST, rpcServerUrl, Collections.<SimpleEntry<String, String>>emptyList());

    // Compute the hash of the body.
    byte[] rawBody = jsonBody.getBytes(UTF_8);
    byte[] hash = DigestUtils.sha(rawBody);
    byte[] encodedHash = Base64.encodeBase64(hash);
    message.addParameter(OAUTH_BODY_HASH, new String(encodedHash, UTF_8));

    // Add other parameters.

    message.addRequiredParameters(accessor);
    LOG.info("Signature base string: " + OAuthSignatureMethod.getBaseString(message));

    // Construct the resulting URL.
    StringBuilder sb = new StringBuilder(rpcServerUrl);
    char connector = '?';
    for (Map.Entry<String, String> p : message.getParameters()) {
      if (!p.getKey().equals(jsonBody)) {
        sb.append(connector);
        sb.append(URLEncoder.encode(p.getKey(), UTF_8));
        sb.append('=');
        sb.append(URLEncoder.encode(p.getValue(), UTF_8));
        connector = '&';
      }
    }
    return sb.toString();
  }
}
