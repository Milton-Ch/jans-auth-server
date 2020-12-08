/*
 * Janssen Project software is available under the Apache License (2004). See http://www.apache.org/licenses/ for full text.
 *
 * Copyright (c) 2020, Janssen Project
 */

package io.jans.as.server.uma.authorization;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 21/02/2013
 */

public interface IPolicyExternalAuthorization {

    public boolean authorize(UmaAuthorizationContext authorizationContext);
}
