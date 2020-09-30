/*******************************************************************************
 * Copyright (c) 2019 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.jwt.fat.builder.actions;

import com.ibm.ws.security.fat.common.servers.ServerBootstrapUtils;

import componenttest.rules.repeater.RepeatTestAction;
import componenttest.topology.impl.LibertyServer;

public class RunWithAndWithoutEncryption implements RepeatTestAction {

    protected static Class<?> thisClass = RunWithAndWithoutEncryption.class;

    protected static ServerBootstrapUtils bootstrapUtils = new ServerBootstrapUtils();

    protected String currentID = null;

    public RunWithAndWithoutEncryption(boolean enabled, LibertyServer... servers) {

        if (enabled) {
            currentID = "WithEncryption";
        } else {
            currentID = "WithoutEncryption";
        }

    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void setup() throws Exception {

    }

    @Override
    public String toString() {
        return currentID;
    }

    /*
     * (non-Javadoc)
     *
     * @see componenttest.rules.repeater.RepeatTestAction#getID()
     */
    @Override
    public String getID() {
        if (currentID != null) {
            return currentID;
        } else {
            return toString();
        }
    }

}
