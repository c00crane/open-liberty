/*******************************************************************************
 * Copyright (c) 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.fat.common.jwt.expectations;

import static org.junit.Assert.assertEquals;

import javax.json.JsonValue.ValueType;

import com.ibm.ws.security.fat.common.Constants.CheckType;

import test.common.SharedOutputManager;

public class JwtTokenHeaderExpectationTestHelperClass extends CommonExpectationTestClass {

    private static SharedOutputManager outputMgr = SharedOutputManager.getInstance().trace("com.ibm.ws.security.fat.common.*=all");

    protected static final String SEARCH_KEY = "searchKey";

    /************************************** Helper methods **************************************/

//    protected Expectation createBasicExpectation() {
//        return new JsonObjectExpectation(TEST_ACTION, SEARCH_KEY, ValueType.STRING, SEARCH_FOR_VAL, FAILURE_MESSAGE);
//    }
//
//    protected Expectation createBasicExpectationWithNoAction() {
//        return new JsonObjectExpectation(SEARCH_KEY, ValueType.STRING, SEARCH_FOR_VAL, FAILURE_MESSAGE);
//    }

    protected void verifyHeaderJsonObjectExpectationValues(JwtTokenHeaderExpectation testExp, String expSearchKey, ValueType expValueType, CheckType expCheckType,
                                                           String expStringValue,
                                                           Object expValue, String expFailureMsg) {
        verifyExpectationValues(testExp, null, JwtTokenHeaderExpectation.SEARCH_LOCATION, null, expSearchKey, expStringValue, expFailureMsg);
        assertEquals("Expected ValueType did not macth expected value.", expValueType, testExp.getExpectedValueType());
        assertEquals("Expected CheckType did not match expected value.", expCheckType, testExp.getExpectedCheckType());
        assertEquals("Expected (object) value did not match expected value.", expValue, testExp.getExpectedValue());
    }

    protected String createContentJsonString(String key, Object value) {
        return "{\"number\":1, \"" + key + "\":" + value + ", \"obj\":{}, \"array\":[\"a\",\"b\",\"c\"]}";
    }

    protected String createJwtString(String key, Object value) {
//        return "{\"number\":1, \"" + key + "\":" + value + ", \"obj\":{}, \"array\":[\"a\",\"b\",\"c\"]}" + "." +
//               "{\"number\":1, \"" + key + "\":" + value + ", \"obj\":{}, \"array\":[\"a\",\"b\",\"c\"]}" + "." +
//               "{\"number\":1, \"" + key + "\":" + value + ", \"obj\":{}, \"array\":[\"a\",\"b\",\"c\"]}";
        return "eyJraWQiOiJrZXlpZCIsImFsZyI6IkhTMjU2In0.eyJpc3MiOiJjbGllbnQwMSIsImlhdCI6MTU4OTMyOTQ1MywiZXhwIjoxNTg5MzI5NzUzLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGp3dENvbnN1bWVyIiwic3ViIjoidGVzdHVzZXIiLCJyZWFsbU5hbWUiOiJCYXNpY1JlYWxtIiwidG9rZW5fdHlwZSI6IkJlYXJlciIsImF1ZCI";
    }
}
