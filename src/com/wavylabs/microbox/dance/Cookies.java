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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides utility class for storing and retrieving cookies.
 *
 * @author David Byttow
 */
public class Cookies {
  private static final String EXPIRED_COOKIE_VALUE = "EXPIRED";
  private static final boolean SECURE_DEFAULT = false;
  private static final int PERSISTENT_AGE = 315360000;  // 10 years.

  /**
   * Gets the value of a cookie by name or null if it does not exist.
   */
  public static String getCookie(HttpServletRequest req, String name) {
    Cookie[] cookies = req.getCookies();
    if (cookies == null) {
      return null;
    }
    return getCookie(cookies, name);
  }

  /**
   * Gets the value of a cookie by name from a set of cookies or null if it
   * does not exist.
   */
  public static String getCookie(Cookie[] cookies, String name) {
    for (int i = 0; i < cookies.length; ++i) {
      if (name.equals(cookies[i].getName())) {
        String value = cookies[i].getValue();
        if (EXPIRED_COOKIE_VALUE.equalsIgnoreCase(value)) {
          value = null;
        }
        return value;
      }
    }
    return null;
  }

  /**
   * Adds a cookie that never expires.
   * @see Cookie
   */
  public static void addPersistentCookie(HttpServletResponse response, String name, String value,
      String path) {
    addCookieDirectly(response, name, value, path, PERSISTENT_AGE, SECURE_DEFAULT);
  }

  /**
   * Adds a cookie that expires with the web browser.
   * @see Cookie
   */
  public static void addSessionCookie(HttpServletResponse response, String name, String value,
      String path) {
    addCookieDirectly(response, name, value, path, -1, SECURE_DEFAULT);
  }

  /**
   * Expires the given cookie.
   */
  public static void expireCookie(HttpServletResponse response, String name, String path) {
    Cookie cookie = new Cookie(name, EXPIRED_COOKIE_VALUE);
    cookie.setMaxAge(0);
    cookie.setPath(path);
    response.addCookie(cookie);
  }

  private static void addCookieDirectly(HttpServletResponse response, String name, String value,
      String path, int maxAge, boolean secure) {
    Cookie cookie = new Cookie(name, value);
    if (path != null) {
      cookie.setPath(path);
    }
    cookie.setMaxAge(maxAge);
    if (secure) {
      cookie.setSecure(secure);
    }
    response.addCookie(cookie);
  }
}
