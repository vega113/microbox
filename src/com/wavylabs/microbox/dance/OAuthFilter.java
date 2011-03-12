/**
 * Copyright 2011 vega113@gmail.com
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

import java.io.*;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.name.Named;
import net.oauth.OAuth;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthServiceProvider;
import net.oauth.client.*;

/**
 * @author vega113@gmail.com
 */
@Singleton
public class OAuthFilter implements Filter {
  private static Logger LOG = Logger.getLogger(OAuthFilter.class.getName());

  
  
  private static final String SCOPE = "";
  //OAuth handlers.
  private static final String REQUEST_URL_POSTFIX = "/robot/dataapi/oauth/OAuthGetRequestToken";
  private static final String AUTH_URL_POSTFIX = "/robot/dataapi/oauth/OAuthAuthorizeToken";
  private static final String ACCESS_URL_POSTFIX = "/robot/dataapi/oauth/OAuthGetAccessToken";
  
  private final String baseUrl;
  private final int basePort;

  private static String CALLBACK_URL = "dev.html";

  // OAuth client.
  public static final OAuthClient OAUTH_CLIENT = new OAuthClient(
      new UrlConnectionHttpClient());

  @Inject
  public OAuthFilter(@Named("baseUrl") String url, @Named("basePort") int port) {
    this.baseUrl = url;
    this.basePort = port;
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse resp,
      FilterChain filterChain) throws IOException, ServletException {

    HttpServletResponse response = (HttpServletResponse) resp;
    HttpServletRequest request = (HttpServletRequest) req;
    OAuthAccessor accessor = createAccessor((HttpServletRequest) req, baseUrl, basePort);
    if (!requiresAuthentication(request)) {
      filterChain.doFilter(req, resp);
      return;
    }
    try {
      if (accessor.requestToken == null) {
        OAUTH_CLIENT.getRequestToken(accessor);
        OAuthUtil.createRequestSession(response,request,accessor);

        CALLBACK_URL = request.getRequestURL().toString();
        String url = accessor.consumer.serviceProvider.userAuthorizationURL
            + "?oauth_token=" + accessor.requestToken + "&oauth_callback="
            + CALLBACK_URL + "&hd=default";

        response.sendRedirect(url);
        return;
      }

      if (accessor.accessToken == null) {
        OAuthMessage msg = null;
        msg = OAUTH_CLIENT.getAccessToken(accessor, "GET",
            OAuth.newList("oauth_token", accessor.requestToken));
        accessor.accessToken = msg.getParameter("oauth_token");
        accessor.tokenSecret = msg.getParameter("oauth_token_secret");
        
        OAuthUtil.createAccessSession(response,request,accessor);
      }
    } catch (OAuthException e) {
      LOG.log(Level.SEVERE, "", e);
      OAuthUtil.invalidateSession(response);
      resp.getWriter().print(e.getMessage());
      return;
    } catch (URISyntaxException e) {
      LOG.log(Level.SEVERE, "", e);
      OAuthUtil.invalidateSession(response);
      resp.getWriter().print(e.getMessage());
      return;
    }
    filterChain.doFilter(req, resp);
  }
  
  public static OAuthAccessor createAccessor(HttpServletRequest req, String url, int port)
      throws UnsupportedEncodingException {
    String prefix = "http://" + url + ":" + port;
    String requestUrl = prefix + REQUEST_URL_POSTFIX;
    String authUrl = prefix + AUTH_URL_POSTFIX;
    String accessUrl = prefix + ACCESS_URL_POSTFIX;
    
    OAuthServiceProvider provider = new OAuthServiceProvider(requestUrl
        + "?scope=" + URLEncoder.encode(SCOPE, "utf-8"), authUrl, accessUrl);
    OAuthConsumer consumer = new OAuthConsumer(CALLBACK_URL,
        OAuthUtil.CONSUMER_KEY, OAuthUtil.CONSUMER_SECRET, provider);
    OAuthAccessor accessor = new OAuthAccessor(consumer);
    accessor.requestToken = Cookies.getCookie(req, OAuthUtil.REQUEST_TOKEN);
    accessor.accessToken = Cookies.getCookie(req, OAuthUtil.ACCESS_TOKEN);
    accessor.tokenSecret = Cookies.getCookie(req, OAuthUtil.TOKEN_SECRET);
    return accessor;
  }

  private boolean requiresAuthentication(HttpServletRequest req) {
    if (OAuthUtil.isAuthenticated(req)) {
      return false;
    }
    return true;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
  }

  @Override
  public void destroy() {
  }
}
