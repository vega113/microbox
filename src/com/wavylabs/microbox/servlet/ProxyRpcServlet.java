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

package com.wavylabs.microbox.servlet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.NavigableMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.oauth.OAuthAccessor;
import net.oauth.OAuthException;

import com.google.common.collect.Maps;
import com.google.gson.Gson;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.name.Named;
import com.google.wave.api.Attachment;
import com.google.wave.api.Element;
import com.google.wave.api.InvalidRequestException;
import com.google.wave.api.JsonRpcResponse;
import com.google.wave.api.OperationQueue;
import com.google.wave.api.OperationRequest;
import com.google.wave.api.OperationType;
import com.google.wave.api.ProtocolVersion;
import com.google.wave.api.RobotSerializer;
import com.google.wave.api.JsonRpcConstant.ParamsProperty;
import com.google.wave.api.impl.GsonFactory;
import com.google.wave.api.v2.ElementGsonAdaptorV2;
import com.wavylabs.microbox.api.WaveService;
import com.wavylabs.microbox.dance.OAuthFilter;
import com.wavylabs.microbox.dance.OAuthUtil;

  /**
   *  Servlet that serves as a proxy between the js AJAX queries and the WIAB server.
   */
  @SuppressWarnings("serial")
  @Singleton
  public class ProxyRpcServlet extends HttpServlet {
    
    private static Logger LOG = Logger.getLogger(ProxyRpcServlet.class.getName());
    
    private static final String JSON_CONTENT_TYPE = "application/json";
    private static final String DATA_API_RPC = "/robot/dataapi/rpc";
    
    private final String url;
    private final int port;
    
    final String rpcUrl;
    
    private WaveService waveService = new WaveService();
    
    /** Holds incoming operation requests. */
    private List<OperationRequest> operations;
    
    private final RobotSerializer robotSerializer;
    
    @Inject
    public ProxyRpcServlet(@Named("baseUrl") String baseUrl, @Named("basePort") int basePort) {
      url = baseUrl;
      port = basePort;
      rpcUrl = "http://" + url + ":" + port + DATA_API_RPC;
      NavigableMap<ProtocolVersion, Gson> gsons = Maps.newTreeMap();
      Gson gsonForPostV2 = new GsonFactory().create();
      gsons.put(ProtocolVersion.V2_2, gsonForPostV2);
      // Remove lines below if we want to stop support for <0.22
      gsons.put(ProtocolVersion.V2_1, gsonForPostV2);

      GsonFactory factoryForV2 = new GsonFactory();
      ElementGsonAdaptorV2 elementGsonAdaptorV2 = new ElementGsonAdaptorV2();
      factoryForV2.registerTypeAdapter(Element.class, elementGsonAdaptorV2);
      factoryForV2.registerTypeAdapter(Attachment.class, elementGsonAdaptorV2);
      gsons.put(ProtocolVersion.V2, factoryForV2.create());
      
      robotSerializer = new RobotSerializer(gsons, ProtocolVersion.DEFAULT);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
      
      OAuthAccessor accessor = OAuthFilter.createAccessor(req, url, port);
      waveService.setupOAuth(accessor, rpcUrl);
      
      String apiRequest;
      try {
        // message.readBodyAsString() doesn't work due to a NPE in the OAuth
        // libraries.
        BufferedReader reader = req.getReader();
        apiRequest = reader.readLine();
      } catch (IOException e) {
        LOG.log(Level.WARNING,"Unable to read the incoming request", e);
        throw e;
      }

      LOG.info("Received the following Json: " + apiRequest);
      try {
        operations = robotSerializer.deserializeOperations(apiRequest);
      } catch (InvalidRequestException e) {
        LOG.info("Unable to parse Json to list of OperationRequests: " + apiRequest);
        resp.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Unable to parse Json to list of OperationRequests: " + apiRequest);
        return;
      }
      LOG.info("Operations size: " + operations.size());
      OperationQueue opQueue = new OperationQueue(operations, null);
      String jsonResponse = null;
      try {
        jsonResponse = waveService.makeRpc(opQueue, rpcUrl);
      } catch (OAuthException e1) {
        LOG.warning("OAuthException when constructing the OAuth parameters: " + e1);
        try {
          OAuthUtil.invalidateSession(resp);
          resp.setContentType(JSON_CONTENT_TYPE);
          PrintWriter writer = resp.getWriter();
          writer.append(e1.getMessage());
          writer.flush();
          resp.setStatus(HttpServletResponse.SC_OK);
        } catch (IOException e) {
          LOG.log(Level.SEVERE,"IOException during writing of a response", e);
          throw e;
        }
        resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }
      
      LOG.info("Returning the following Json: " + jsonResponse);

      // Write the response back through the HttpServlet
      try {
        resp.setContentType(JSON_CONTENT_TYPE);
        PrintWriter writer = resp.getWriter();
        writer.append(jsonResponse);
        writer.flush();
        resp.setStatus(HttpServletResponse.SC_OK);
      } catch (IOException e) {
        LOG.log(Level.SEVERE,"IOException during writing of a response", e);
        throw e;
      }
    }
  }