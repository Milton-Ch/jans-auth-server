/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.client;

import io.jans.as.client.util.ClientUtil;
import io.jans.as.model.register.ApplicationType;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.json.JSONObject;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;
import java.util.List;

/**
 * Encapsulates functionality to make Register request calls to an authorization server via REST Services.
 *
 * @author Javier Rojas Blum
 * @author Yuriy Zabrovarnyy
 * @author Yuriy Movchan
 * @version August 20, 2019
 */
public class RegisterClient extends BaseClient<RegisterRequest, RegisterResponse> {

    private static final Logger LOG = Logger.getLogger(RegisterClient.class);

    /**
     * Construct a register client by providing an URL where the REST service is located.
     *
     * @param url The REST service location.
     */
    public RegisterClient(String url) {
        super(url);
    }

    @Override
    public String getHttpMethod() {
        if (getRequest() != null) {
            if (StringUtils.isNotBlank(getRequest().getHttpMethod())) {
                return getRequest().getHttpMethod();
            }
            if (getRequest().getRegistrationAccessToken() != null) {
                return HttpMethod.GET;
            }
        }

        return HttpMethod.POST;
    }

    /**
     * Executes the call to the REST service requesting to register and process the response.
     *
     * @param applicationType The application type.
     * @param clientName      The client name.
     * @param redirectUri     A list of space-delimited redirection URIs.
     * @return The service response.
     */
    public RegisterResponse execRegister(ApplicationType applicationType,
                                         String clientName, List<String> redirectUri) {
        setRequest(new RegisterRequest(applicationType, clientName, redirectUri));

        return exec();
    }

    public RegisterResponse exec() {
        initClientRequest();
        return _exec();
    }

    @Deprecated
    public RegisterResponse exec(ClientExecutor clientExecutor) {
        this.clientRequest = new ClientRequest(getUrl(), clientExecutor);
        return _exec();
    }

    private RegisterResponse _exec() {
        try {
            // Prepare request parameters
            clientRequest.setHttpMethod(getHttpMethod());

            // POST - Client Register, PUT - update client
            if (getHttpMethod().equals(HttpMethod.POST) || getHttpMethod().equals(HttpMethod.PUT)) {
                clientRequest.header("Content-Type", getRequest().getContentType());
                clientRequest.accept(getRequest().getMediaType());

                if (StringUtils.isNotBlank(getRequest().getRegistrationAccessToken())) {
                    clientRequest.header("Authorization", "Bearer " + getRequest().getRegistrationAccessToken());
                }

                JSONObject requestBody = getRequest().getJSONParameters();

                clientRequest.body(MediaType.APPLICATION_JSON, ClientUtil.toPrettyJson(requestBody));
            } else { // GET, Client Read
                clientRequest.accept(MediaType.APPLICATION_JSON);

                if (StringUtils.isNotBlank(getRequest().getRegistrationAccessToken())) {
                    clientRequest.header("Authorization", "Bearer " + getRequest().getRegistrationAccessToken());
                }
            }

            // Call REST Service and handle response

            if (getHttpMethod().equals(HttpMethod.POST)) {
                clientResponse = clientRequest.post(String.class);
            } else if (getHttpMethod().equals(HttpMethod.PUT)) {
                clientResponse = clientRequest.put(String.class);
            } else if (getHttpMethod().equals(HttpMethod.DELETE)) {
                clientResponse = clientRequest.delete(String.class);
            } else { // GET
                clientResponse = clientRequest.get(String.class);
            }
            setResponse(new RegisterResponse(clientResponse));
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        } finally {
            closeConnection();
        }

        return getResponse();
    }
}