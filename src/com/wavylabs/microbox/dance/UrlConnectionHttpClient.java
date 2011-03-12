/**
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.wavylabs.microbox.dance;

import net.oauth.http.HttpClient;
import net.oauth.http.HttpMessage;
import net.oauth.http.HttpResponseMessage;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;

/**
 * An implementation of {@link HttpClient} based on {@link HttpURLConnection}.
 *
 * @author Marcel Prasetya
 */
public class UrlConnectionHttpClient implements HttpClient {

  /**
   * A simple implementation of {@link HttpResponseMessage} that gets the
   * response from {@link HttpURLConnection#getInputStream()}.
   */
  class HttpResponse extends HttpResponseMessage {

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

  private static final String HTTP_POST_METHOD = "POST";
  private static final String HTTP_PUT_METHOD = "PUT";

  @Override
  public HttpResponseMessage execute(HttpMessage request, Map<String, Object> httpParameters)
      throws IOException {
    // Setup the connection.
    HttpURLConnection connection = (HttpURLConnection) request.url.openConnection();
    connection.setRequestMethod(request.method);
    for (Entry<String, String> header : request.headers) {
      connection.setRequestProperty(header.getKey(), header.getValue());
    }
    InputStream messageBodyStream = request.getBody();
    boolean doOutput = messageBodyStream != null &&
       (HTTP_POST_METHOD.equalsIgnoreCase(request.method) ||
           HTTP_PUT_METHOD.equalsIgnoreCase(request.method)) ;
    if (doOutput) {
      connection.setDoOutput(true);
    }
    connection.connect();

    // Send the request body.
    if (doOutput) {
      Writer outputWriter = new OutputStreamWriter(connection.getOutputStream());
      outputWriter.write(readInputStream(messageBodyStream));
      outputWriter.flush();
      outputWriter.close();
    }

    // Return the response stream.
    return new HttpResponse(request.method, request.url, connection.getResponseCode(),
        connection.getInputStream());
  }

  /**
   * Reads the given {@link InputStream} as a {@link String}
   *
   * @param inputStream the {@link InputStream} to be read.
   * @return a string content of the {@link InputStream}.
   *
   * @throws IOException if there is a problem reading the stream.
   */
  private static String readInputStream(InputStream inputStream) throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
    StringBuilder result = new StringBuilder();
    String s;
    while ((s = reader.readLine()) != null) {
      result.append(s);
    }
    return result.toString();
  }
}
