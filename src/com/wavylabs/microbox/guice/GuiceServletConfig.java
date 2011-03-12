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

package com.wavylabs.microbox.guice;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ResourceBundle;
import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.wavylabs.microbox.dance.OAuthFilter;
import com.wavylabs.microbox.dance.OAuthUtil;
import com.wavylabs.microbox.options.Options;
import com.wavylabs.microbox.servlet.ProxyRpcServlet;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Singleton;
import com.google.inject.name.Names;
import com.google.inject.servlet.GuiceServletContextListener;
import com.google.inject.servlet.ServletModule;

public class GuiceServletConfig extends GuiceServletContextListener {
  private static final Logger LOG = Logger.getLogger(GuiceServletConfig.class.getName());
  
  
  /**
   * Loads options from options.properties and binds them behind the Options interface.
   */
  private static Options loadOptions() {
    final ResourceBundle properties =
        ResourceBundle.getBundle(Options.class.getPackage().getName() + ".options");

    return (Options)
        Proxy.newProxyInstance(Options.class.getClassLoader(), new Class<?>[]{Options.class},
            new InvocationHandler() {
              @Override
              public Object invoke(Object o, Method method, Object[] objects) throws Throwable {
                String prop = properties.getString(method.getName());
                try {
                  Integer propInt = Integer.parseInt(prop);
                  return propInt;
                } catch (Exception e) {
                  if (Boolean.TRUE.toString().equals(prop) || Boolean.FALSE.toString().equals(prop)) {
                    try {
                      boolean propBool = Boolean.parseBoolean(prop);
                      return propBool;
                    } catch (Exception e1) {
                      return prop;
                    }
                  } else {
                    return prop;
                  }
                }
              }
            }
        );
  }
  
  private static final Options OPTIONS = loadOptions();
  
  /**
   * Simple logout servlet.
   */
  @Singleton
  static class LogoutServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
      OAuthUtil.invalidateSession(resp);

      // TODO: Implement something less lame.
      resp.setHeader("Content-Type", "text/html");
      resp.getWriter().println("<h3>You've been logged out.</h3>");
      resp.getWriter().flush();
      resp.getWriter().close();
    }
  }
  
  /**
   * Simple logout servlet.
   */
  @Singleton
  static class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
      resp.sendRedirect("ui.html");
    }
  }


  @Singleton
  static class IsLoggedServlet extends HttpServlet {
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws IOException {
      resp.setContentType("application/json");
      resp.getWriter().println(String.valueOf(OAuthUtil.isAuthenticated(req)));
      resp.getWriter().flush();
      resp.setStatus(HttpServletResponse.SC_OK);
    }
  }
  
  
  
  @Override
  protected Injector getInjector() {
    ServletModule servletModule = new ServletModule() {
      @Override
      protected void configureServlets() {
          serve("/rpc").with(ProxyRpcServlet.class); 
    	  serve("/logout").with(LogoutServlet.class);
    	  serve("/islogged").with(IsLoggedServlet.class);
    	  serve("/auth").with(LoginServlet.class);
    	  filter("/auth").through(OAuthFilter.class);
      }
    };

    AbstractModule businessModule = new AbstractModule() {
      @Override
      protected void configure() {
        bind(String.class).annotatedWith(Names.named("baseUrl")).toInstance(
            OPTIONS.waveDomain());
        bind(Integer.class).annotatedWith(Names.named("basePort")).toInstance(
            OPTIONS.port());
      }
    };

    return Guice.createInjector(servletModule, businessModule);
  }
}
