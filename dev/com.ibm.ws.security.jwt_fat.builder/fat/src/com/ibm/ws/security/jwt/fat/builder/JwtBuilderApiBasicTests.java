/*******************************************************************************
 * Copyright (c) 2018, 2020 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.jwt.fat.builder;

import java.util.ArrayList;
import java.util.List;

import org.jose4j.jwt.NumericDate;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import com.ibm.json.java.JSONArray;
import com.ibm.json.java.JSONObject;
import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.security.fat.common.CommonSecurityFat;
import com.ibm.ws.security.fat.common.expectations.Expectations;
import com.ibm.ws.security.fat.common.expectations.ResponseFullExpectation;
import com.ibm.ws.security.fat.common.jwt.HeaderConstants;
import com.ibm.ws.security.fat.common.jwt.JwtMessageConstants;
import com.ibm.ws.security.fat.common.jwt.PayloadConstants;
import com.ibm.ws.security.fat.common.jwt.expectations.JwtApiExpectation;
import com.ibm.ws.security.fat.common.jwt.utils.JwtKeyTools;
import com.ibm.ws.security.fat.common.servers.ServerInstanceUtils;
import com.ibm.ws.security.fat.common.utils.CommonExpectations;
import com.ibm.ws.security.fat.common.utils.CommonIOUtils;
import com.ibm.ws.security.fat.common.utils.CommonWaitForAppChecks;
import com.ibm.ws.security.fat.common.utils.SecurityFatHttpUtils;
import com.ibm.ws.security.jwt.fat.builder.actions.JwtBuilderActions;
import com.ibm.ws.security.jwt.fat.builder.actions.JwtBuilderClaimRepeatActions;
import com.ibm.ws.security.jwt.fat.builder.utils.BuilderHelpers;
import com.ibm.ws.security.jwt.fat.builder.validation.BuilderTestValidationUtils;

import componenttest.annotation.ExpectedFFDC;
import componenttest.annotation.Server;
import componenttest.annotation.SkipForRepeat;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.rules.repeater.RepeatTests;
import componenttest.topology.impl.LibertyServer;

/**
 * This is the test class that contains tests for the JWT Builder apis.
 * These tests look a little different from other OIDC/OAUTH tests.
 *
 * The main purpose of the test is:
 * <OL>
 * <LI>We'll use a test application that will invoke the build apis using key/value pairs or a list of keys that we pass to it.
 * The goal of the tests is to test all of the set, claims, fetch, claimFrom, ... apis that are part of the builder. We're
 * including tests that use multiple api's affecting the same claim (so we can confirm that the last update is what the token
 * is built with).
 * <LI>The test app will take the built token and use some of the claim api's to print all of the claims and their values.
 * This is returned to the test which will then validate that the values that we expect exist in the token.
 * <LI>A few of the tests will take the built JWT token and use it to access a protected application on a different server (to
 * show that the built token is valid/usable)
 * </OL>
 *
 **/

@Mode(TestMode.FULL)
@RunWith(FATRunner.class)
public class JwtBuilderApiBasicTests extends CommonSecurityFat {

    @Server("com.ibm.ws.security.jwt_fat.builder")
    public static LibertyServer builderServer;
    @Server("com.ibm.ws.security.jwt_fat.builder.rs")
    public static LibertyServer rsServer;

    // Allow tests to run twice
    // -- once where the builder will process claims as a collection
    // -- once where the builder will process claims individually
    // This allows us to use the same tests with a variety of claims without having to duplicate test cases
    @ClassRule
    public static RepeatTests r = RepeatTests.with(JwtBuilderClaimRepeatActions.asCollection());
    // TODO    public static RepeatTests r = RepeatTests.with(JwtBuilderClaimRepeatActions.asCollection()).andWith(JwtBuilderClaimRepeatActions.asSingle());

    private static final JwtBuilderActions actions = new JwtBuilderActions();
    public static final BuilderTestValidationUtils validationUtils = new BuilderTestValidationUtils();

    public long testExp = 2107268760L;
    public long oldExp = 1443551518L;
    public static String processClaimsAs = "null";
    public static String protectedApp;

    @BeforeClass
    public static void setUp() throws Exception {

        // Start server that will build the JWT Token
        serverTracker.addServer(builderServer);
        ServerInstanceUtils.addPSSAlgSettingToBootstrap(builderServer);
        builderServer.addInstalledAppForValidation(JWTBuilderConstants.JWT_BUILDER_SERVLET);
        builderServer.startServerUsingExpandedConfiguration("server_basicRegistry.xml", CommonWaitForAppChecks.getSecurityReadyMsgs());
        SecurityFatHttpUtils.saveServerPorts(builderServer, JWTBuilderConstants.BVT_SERVER_1_PORT_NAME_ROOT);

        // start server to run protected app - make sure we can use the JWT Token that we produce
        serverTracker.addServer(rsServer);
        ServerInstanceUtils.addHostNameAndAddrToBootstrap(rsServer);
        ServerInstanceUtils.addPSSAlgSettingToBootstrap(rsServer);
        rsServer.addInstalledAppForValidation(JWTBuilderConstants.HELLOWORLD_APP);
        rsServer.startServerUsingExpandedConfiguration("rs_server_orig.xml", CommonWaitForAppChecks.getSecurityReadyMsgs());
        SecurityFatHttpUtils.saveServerPorts(rsServer, JWTBuilderConstants.BVT_SERVER_2_PORT_NAME_ROOT);

        protectedApp = SecurityFatHttpUtils.getServerUrlBase(rsServer) + "helloworld/rest/helloworld";

        if (FATSuite.runAsCollection) {
            processClaimsAs = JWTBuilderConstants.AS_COLLECTION;
        } else {
            processClaimsAs = JWTBuilderConstants.AS_SINGLE;
        }

    }

    /**************************************************************
     * Test Builder create specific Tests
     **************************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified config (defaultJWT - no config, just use default values)
     * <LI>Do NOT run any of the api's to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with the default values
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that no "set" api's were invoked
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_create_id_defaultJWT() throws Exception {

        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderServer);
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_CREATE_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_create(_testName, builderServer, null);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified config (defaultJWT - no config, just use default values)
     * <LI>Run the subject api to update the builder
     * <LI>generate a JWT token
     * <LI>Invoke a protected App using the generated token to show that it is valid
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with the default values
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that the subject "set" api was invoked
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * <LI>The output from the protected app
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_create_id_defaultJWT_consumeToken() throws Exception {

        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderServer);
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.SUBJECT, "user2");
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, null, testSettings);
        validationUtils.validateResult(response, expectations);

        //        Page appResponse = actions.invokeProtectedAppWithJwtTokenAsParm(_testName, response, protectedApp);
        // Try to use the JWT Token created by the builder - it can be passed in the header
        // as well as - as a parm - we'll pass in the header in this test - another test will pass as a parm
        // the method will pull the JWT Token from the builder response
        Page appResponse = actions.invokeProtectedAppWithJwtTokenInHeader(_testName, response, protectedApp);

        Expectations appExpectations = new Expectations();
        appExpectations.addExpectations(CommonExpectations.successfullyReachedUrl(protectedApp));
        validationUtils.validateResult(appResponse, appExpectations);
    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Attempt to create a builder using the specified config - the config does NOT exist
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should NOT be created
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that the configId could not be found
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_create_id_notExist() throws Exception {

        Expectations expectations = new Expectations();
        expectations.addExpectations(CommonExpectations.successfullyReachedUrl(SecurityFatHttpUtils.getServerUrlBase(builderServer) + JWTBuilderConstants.JWT_BUILDER_CREATE_ENDPOINT));
        expectations.addExpectation(new ResponseFullExpectation(JWTBuilderConstants.STRING_MATCHES, JwtMessageConstants.CWWKS6008E_BUILD_ID_UNKNOWN + ".+someBadBuilderId", "Response did not show the expected failure."));

        Page response = actions.invokeJwtBuilder_create(_testName, builderServer, "someBadBuilderId");
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Attempt to create a builder using a config Id of <null>
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should NOT be created
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that the configId was not valid
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_create_id_null() throws Exception {

        Expectations expectations = new Expectations();
        expectations.addExpectations(CommonExpectations.successfullyReachedUrl(SecurityFatHttpUtils.getServerUrlBase(builderServer) + JWTBuilderConstants.JWT_BUILDER_CREATE_ENDPOINT));
        expectations.addExpectation(new ResponseFullExpectation(JWTBuilderConstants.STRING_MATCHES, JwtMessageConstants.CWWKS6008E_BUILD_ID_UNKNOWN + ".+null", "Response did not show the expected failure."));

        Page response = actions.invokeJwtBuilder_create(_testName, builderServer, JWTBuilderConstants.NULL_STRING);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Attempt to create a builder using a config Id of ""
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should NOT be created
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that the configId was not valid
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_create_id_empty() throws Exception {

        Expectations expectations = new Expectations();
        expectations.addExpectations(CommonExpectations.successfullyReachedUrl(SecurityFatHttpUtils.getServerUrlBase(builderServer) + JWTBuilderConstants.JWT_BUILDER_CREATE_ENDPOINT));
        expectations.addExpectation(new ResponseFullExpectation(JWTBuilderConstants.STRING_MATCHES, JwtMessageConstants.CWWKS6008E_BUILD_ID_UNKNOWN + ".+\\[\\]", "Response did not show the expected failure."));

        Page response = actions.invokeJwtBuilder_create(_testName, builderServer, JWTBuilderConstants.EMPTY_STRING);
        validationUtils.validateResult(response, expectations);

    }

    /**************************************************************
     * Test Builder update/set claims specific Tests
     **************************************************************/
    /***************************************************** Test audience ****************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the audience api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to audience
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "audience"
     * <LI>The failure messages from our attempt to invoke "audience"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_audience_nullList() throws Exception {

        String builderId = "jwt1";

        JSONArray parmarray = new JSONArray();
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6009E_INVALID_CLAIM, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);
    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the audience api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updates to audience
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "audience"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_audience_one() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderServer);
        expectationSettings.put(PayloadConstants.ISSUER, builderId);

        JSONArray parmarray = new JSONArray();
        parmarray.add("Client02");
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the audience api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updates to audience
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "audience"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_audience_multiple() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONArray parmarray = new JSONArray();
        parmarray.add("Client04");
        parmarray.add("Client05");
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the audience api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updates to audience (with duplicates removed)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "audience"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_audience_duplicates() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONArray parmarray = new JSONArray();
        parmarray.add("Client04");
        parmarray.add("Client05");
        parmarray.add("Client04");
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_CONTAIN, "Client04, Client05, Client04", "Found duplicate values in Audience"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_CONTAIN, "Client04, Client04, Client05", "Found duplicate values in Audience"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_CONTAIN, "Client05, Client04, Client04", "Found duplicate values in Audience"));

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the audience api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updates to audience (should have mixed case versions of the same string as they really are
     * different)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "audience"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_audience_duplicates_caseSensitive() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONArray parmarray = new JSONArray();
        parmarray.add("Client04");
        parmarray.add("Client05");
        parmarray.add("client04");
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the audience api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updates to audience (there should be NO null entry in the audience)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "audience"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_audience_nullListEntry() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONArray parmarray = new JSONArray();
        parmarray.add("Client04");
        parmarray.add(null);
        parmarray.add("Client05");
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the audience api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updates to audience (there should be NO empty entry in the audience)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "audience"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_audience_emptyListEntry() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONArray parmarray = new JSONArray();
        parmarray.add("Client04");
        parmarray.add("");
        parmarray.add("Client05");
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /*****************************************************
     * Test expirationTime
     ****************************************************/

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the expirationTime api to update the builder
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updates to expiration (exp should be set to 2107268760)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "expirationTime"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_expirationTime() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.EXPIRATION_TIME, testExp);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the expirationTime api to update the builder with a bad value (value in the past)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to expiration (value should be currentTime + expiry time)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "expirationTime"
     * <LI>The failure messages from our attempt to invoke "expirationTime"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_expirationTime_inThePast() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.EXPIRATION_TIME, oldExp);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6042E_BAD_EXP_TIME, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the expirationTime api to update the builder with a bad value (value of zero)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to expiration (value should be currentTime + expiry time)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "expirationTime"
     * <LI>The failure messages from our attempt to invoke "expirationTime"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_expirationTime_zero() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.EXPIRATION_TIME, NumericDate.fromSeconds(0L).getValue());

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6042E_BAD_EXP_TIME, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the expirationTime api to update the builder with a bad value (value of -2)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to expiration (value should be currentTime + expiry time)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "expirationTime"
     * <LI>The failure messages from our attempt to invoke "expirationTime"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_expirationTime_negative() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.EXPIRATION_TIME, NumericDate.fromSeconds(-2L).getValue());

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6042E_BAD_EXP_TIME, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***************************************************** Test notBefore ****************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the notBefore api to update the builder with a good value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated notBefore (value should be )
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "notBefore"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_notBefore() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.NOT_BEFORE, NumericDate.fromSeconds(2106325918L).getValue());
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the notBefore api to update the builder with a bad value (value of zero)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to notBefore (value should NOT be set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "notBefore"
     * <LI>The failure messages from our attempt to invoke "notBefore"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_notBefore_zero() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.NOT_BEFORE, NumericDate.fromSeconds(0L).getValue());

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6018E_CLAIM_MUST_BE_GT_ZERO, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the notBefore api to update the builder with a bad value (value of -2L)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to notBefore (value should NOT be set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "notBefore"
     * <LI>The failure messages from our attempt to invoke "notBefore"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_notBefore_negative() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.NOT_BEFORE, NumericDate.fromSeconds(-2L).getValue());

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6018E_CLAIM_MUST_BE_GT_ZERO, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***************************************************** Test jwtId ****************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a config with jti set to false)
     * <LI>Run the jwtId api to update the builder with a value of false
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated jwtId (value should false/no jti set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "jwtId"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_jwtId_cfgFalse_apiFalse() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.JWT_ID, false);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_MATCHES, JWTBuilderConstants.JWT_CLAIM + PayloadConstants.JWT_ID + ".*null.*", "jti was NOT found and should have been"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_MATCH, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + "\\{" + ".*\"" + PayloadConstants.JWT_ID + "\".*\\}", "jti was found in the list of claims and should NOT have been"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_MATCH, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + JWTBuilderConstants.JWT_GETALLCLAIMS + JWTBuilderConstants.JWT_CLAIM_KEY + PayloadConstants.JWT_ID + ".*", "The jti claim was found and should NOT have been"));

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a config with jti set to false)
     * <LI>Run the jwtId api to update the builder with a value of true
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated jwtId (value should true/jti is set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "jwtId"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_jwtId_cfgFalse_apiTrue() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.JWT_ID, true);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_MATCH, JWTBuilderConstants.JWT_CLAIM + PayloadConstants.JWT_ID + ".*null.*", "jti was found and should NOT have been"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_MATCHES, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + "\\{" + ".*\"" + PayloadConstants.JWT_ID + "\".*\\}", "jti was NOT found in the list of claims"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_MATCHES, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + JWTBuilderConstants.JWT_GETALLCLAIMS + JWTBuilderConstants.JWT_CLAIM_KEY + PayloadConstants.JWT_ID + ".*", "The jti claim was NOT found and should have been"));

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a config with jti set to true)
     * <LI>Run the jwtId api to update the builder with a value of true
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated jwtId (value should true/jti is set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "jwtId"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_jwtId_cfgTrue_apiTrue() throws Exception {

        String builderId = "jwt_jtiTrue";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.JWT_ID, true);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_MATCH, JWTBuilderConstants.JWT_CLAIM + PayloadConstants.JWT_ID + ".*null.*", "jti was found and should NOT have been"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_MATCHES, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + "\\{" + ".*\"" + PayloadConstants.JWT_ID + "\".*\\}", "jti was NOT found in the list of claims"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_MATCHES, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + JWTBuilderConstants.JWT_GETALLCLAIMS + JWTBuilderConstants.JWT_CLAIM_KEY + PayloadConstants.JWT_ID + ".*", "The jti claim was NOT found and should have been"));

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a config with jti set to true)
     * <LI>Run the jwtId api to update the builder with a value of false
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated jwtId (value should false/no jti set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "jwtId"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_jwtId_cfgTrue_apiFalse() throws Exception {

        String builderId = "jwt_jtiTrue";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.JWT_ID, false);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_MATCHES, JWTBuilderConstants.JWT_CLAIM + PayloadConstants.JWT_ID + ".*null.*", "jti was NOT found and should have been"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_MATCH, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + "\\{" + ".*\"" + PayloadConstants.JWT_ID + "\".*\\}", "jti was found in the list of claims and should NOT have been"));
        expectations.addExpectation(new JwtApiExpectation(JWTBuilderConstants.STRING_DOES_NOT_MATCH, JWTBuilderConstants.JWT_CLAIM + JWTBuilderConstants.JWT_JSON + JWTBuilderConstants.JWT_GETALLCLAIMS + JWTBuilderConstants.JWT_CLAIM_KEY + PayloadConstants.JWT_ID + ".*", "The jti claim was found and should NOT have been"));

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***************************************************** Test subject ****************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the subject api to update the builder with a good value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated subject (value should be user2)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "subject"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_subject_validUser() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.SUBJECT, "user2");
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the subject api to update the builder with a bad value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated subject (value should be someOtherUser)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "subject"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_subject_invalidUser() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.SUBJECT, "someOtherUser");
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the subject api to update the builder with a bad value (value is <null>)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to subject (there should be no value set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "subject"
     * <LI>The failure messages from our attempt to invoke "subject"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_subject_null() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.SUBJECT, null);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6009E_INVALID_CLAIM, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the subject api to update the builder with a bad value (value is "")
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to subject (there should be no value set)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "subject"
     * <LI>The failure messages from our attempt to invoke "subject"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_subject_emptyUser() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.SUBJECT, "");

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6009E_INVALID_CLAIM, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***************************************************** Test issuer ****************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the issuer api to update the builder with a good value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated issuer (value should be "someIssuer")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "issuer"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_issuer_validIssuer() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.ISSUER, "someIsser");
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the issuer api to update the builder with a bad value (value is <null>)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to issuer (the value should be https://<hostname>:<secureport>/jwt/<configId>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "issuer"
     * <LI>The failure messages from our attempt to invoke "issuer"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_issuer_null() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.ISSUER, null);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6009E_INVALID_CLAIM, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the issuer api to update the builder with a bad value (value is "")
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to issuer (the value should be https://<hostname>:<secureport>/jwt/<configId>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "issuer"
     * <LI>The failure messages from our attempt to invoke "issuer"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @SkipForRepeat(JwtBuilderClaimRepeatActions.SingleID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_issuer_empty() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.ISSUER, "");

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6009E_INVALID_CLAIM, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***************************************************** Test claim ****************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (value should be someClaim:someValue)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_one() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put("someClaim", "someValue");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (claims should contain someClaim:someValue anotherClaim:anotherValue
     * stillOneMoreClaim:stillOneMoreValue)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_multiple() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put("someClaim", "someValue");
        claimsToSet.put("anotherClaim", "anotherValue");
        claimsToSet.put("stillOneMoreClaim", "stillOneMoreValue");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (claims should contain azp:someParty)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_azp_causeItsSpecial() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.AUTHORIZED_PARTY, "someParty");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a bad value (value is <null>)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have any updates to claim
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    // test is validating that a null collection fails appropriately, so, skip if adding single claim (key,value) pairs
    //    @SkipForRepeat(JwtBuilderClaimRepeatActions.CollectionID)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_null() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        String msgId = null;
        if (processClaimsAs.equals(JWTBuilderConstants.AS_COLLECTION)) {
            // message received when null map passed
            msgId = JwtMessageConstants.CWWKS6021E_CLAIMS_ARE_NOT_VALID;
        } else {
            // message received when key value is null
            msgId = JwtMessageConstants.CWWKS6015E_INVALID_CLAIM;
        }
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, msgId, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a bad value (List of key:values, one value is <null>)
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have any updated claims with valid claims prior to the null (check for someClaim:someValue and no
     * more claims)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_nullValueInList() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put("someClaim", "someValue");
        claimsToSet.put("anotherClaim", null);
        claimsToSet.put("stillOneMoreClaim", "stillOneMoreValue");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6009E_INVALID_CLAIM, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    //    //chc@Test
    //    public void JwtBuilderAPIBasicTests_claim_nullKeyInList() throws Exception {  }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with an empty value (List of key:values, one value is "")
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have any updated claims with valid claims (check for someClaim:someValue
     * anotherClaim: stillOneMoreClaim:stillOneMoreValue)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_emptyValueInList() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put("someClaim", "someValue");
        claimsToSet.put("anotherClaim", "");
        claimsToSet.put("stillOneMoreClaim", "stillOneMoreValue");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a bad value (List of key:values, one key is "")
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have any updated claims with valid claims prior to the null (check for someClaim:someValue and no
     * more claims)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_emptyKeyInList() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put("someClaim", "someValue");
        claimsToSet.put("", "anotherValue");
        claimsToSet.put("stillOneMoreClaim", "stillOneMoreValue");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (exp) (claim should contain exp:2107268760)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_exp_long() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.EXPIRATION_TIME, testExp);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a value of an invalid type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should not update claim (exp) (claim should contain exp:<current time + expiry>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token (reflecting values showing that the failure did NOT mangle the builder contents)
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_exp_String() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.EXPIRATION_TIME, Long.toString(testExp));
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6019E_BAD_DATA_TYPE, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);
    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (iat) (claim should contain iat:<approx current time)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_iat_long() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.ISSUED_AT, BuilderHelpers.setNowLong() + Long.valueOf(5 * 60));
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a value of an invalid type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should not update claim (iat) (claim should contain iat:<current time>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token (reflecting values showing that the failure did NOT mangle the builder contents)
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_iat_String() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.ISSUED_AT, Long.toString(BuilderHelpers.setNowLong() + Long.valueOf(5 * 60)));
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6019E_BAD_DATA_TYPE, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (nbf) (claim should contain nbf:<approx current time>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_nbf_long() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.NOT_BEFORE, BuilderHelpers.setNowLong() + Long.valueOf(5 * 60));
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);
    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a value of an invalid type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should not update claim (nbf) (claims should NOT contain nbf)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token (reflecting values showing that the failure did NOT mangle the builder contents)
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_nbf_String() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.NOT_BEFORE, Long.toString(BuilderHelpers.setNowLong() + Long.valueOf(5 * 60)));
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6019E_BAD_DATA_TYPE, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (iss) (claim should contain iss:JohnQIssuer)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_iss_String() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.ISSUER, "JohnQIssuer");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a value of an invalid type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should not update claim (iss) (claim should contain iss:<https://<hostname>:<port>/jwt/<configId>>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token (reflecting values showing that the failure did NOT mangle the builder contents)
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_iss_Long() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.ISSUER, testExp);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6019E_BAD_DATA_TYPE, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (token_type) (claim should contain token_type:myType)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_token_type_String() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.TOKEN_TYPE, "myType");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a value of an invalid type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should not update claim (token_type) (claim should contain token_type:Bearer)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token (reflecting values showing that the failure did NOT mangle the builder contents)
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_token_type_Long() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.TOKEN_TYPE, testExp);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6019E_BAD_DATA_TYPE, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (sub) (claim should contain sub:buddy)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_sub_String() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.SUBJECT, "buddy");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a value of an invalid type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should not update claim (sub) (claim should NOT contain sub)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token (reflecting values showing that the failure did NOT mangle the builder contents)
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_sub_Long() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.SUBJECT, testExp);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6019E_BAD_DATA_TYPE, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (jti) (claim should contain jti:lJ7GKhJCLrY5y5BL)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_jti_String() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.JWT_ID, "lJ7GKhJCLrY5y5BL");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a value of an invalid type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should not update claim (jti) (claims should NOT contain jti)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The failure messages from our attempt to invoke "claim"
     * <LI>The content of the returned token (reflecting values showing that the failure did NOT mangle the builder contents)
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @ExpectedFFDC({ "com.ibm.ws.security.jwt.internal.JwtTokenException" })
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_jti_Long() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.JWT_ID, testExp);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6020E_CAN_NOT_CAST, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);
    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (alg) (claim should contain alg:BS256)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    // TODO - this is creating an alg claim in the payload, not updating the alg in the header - with the tooling, it will be funky to add expectations
    // for this case - does it really show anything???
    //    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_alg_String() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(HeaderConstants.ALGORITHM, "BS256");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the claim api to update the builder with a good value of the correct type
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated claim (kid) (claim should contain kid:983457399)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "claim"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claim_kid_String() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // key_id is really a header attribute, but, we're add a claim to the payload with a value, so, we can't use the
        // normal tooling to add an expectation for it.  We won't add it to the settings that we build the expectations from
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(HeaderConstants.KEY_ID, "983457399");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectations = BuilderHelpers.updateClaimExpectationsForJsonAttribute(expectations, JWTBuilderConstants.JWT_CLAIM, HeaderConstants.KEY_ID, claimsToSet.get(HeaderConstants.KEY_ID));

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***************************************************** Test remove ****************************************************/
    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove method actually removes the specified claim
     * <LI>Remove an "extra" claim that we've previously added
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "extra" claim should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_extraClaim() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        // add an extra claim
        claimsToSet.put("extraClaim", "myValue");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add("extraClaim");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove method actually removes the specified claim
     * <LI>Remove an "extra" claim that we have NOT added
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "extra" claim should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_nonExistant_extraClaim() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json array.  Add that array into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add("extraClaim");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove method actually removes the specified claim
     * <LI>Remove default claim "exp"
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "exp" claim should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_defaultClaim_exp() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        // add an extra claim
        claimsToSet.put(PayloadConstants.EXPIRATION_TIME, testExp);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.EXPIRATION_TIME);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove method actually removes the specified claim
     * <LI>Remove default claim "iss"
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "iss" claim should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_defaultClaim_iss() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.ISSUER);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove method actually removes the specified claim
     * <LI>Remove default claim "iat"
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "iat" claim should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_defaultClaim_iat() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.ISSUED_AT);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove method actually removes the specified claim
     * <LI>Remove default claim "token_type"
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "token_type" claim should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_defaultClaim_tokenType() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.TOKEN_TYPE);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove fails when we try to remove <null>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The claims in the token should NOT have been altered
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_null() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(null);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that the remove fails when we try to remove ""
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The claims in the token should NOT have been altered
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_empty() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add("");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that nbf set via the notBefore api is removed when the remove api is called for nbf
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "nbf" claim is added and is then removed and should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_apiClaim_nbf() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        // add an extra claim
        claimsToSet.put(PayloadConstants.NOT_BEFORE, 2106325918L);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.NOT_BEFORE);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Test that sub set via the subject api is removed when the remove api is called for sub
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "sub" claim is added and is then removed and should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_apiClaim_sub() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims to remove into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        JSONObject claimsToSet = new JSONObject();
        // add an extra claim
        claimsToSet.put(PayloadConstants.SUBJECT, "user2");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.SUBJECT);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that aud set via the audience api is removed when the remove api is called for aud
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "aud" claim is added and is then removed and should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_apiClaim_aud() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        JSONArray parmarray = new JSONArray();
        parmarray.add("Client02");
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.AUDIENCE, parmarray);
        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.AUDIENCE);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Test that jti set via the jwtId api is removed when the remove api is called for jti
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The "jti" claim is added and is then removed and should NOT exist in the JWT Token
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_remove_apiClaim_jti() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.JWT_ID, true);

        JSONArray claimsToRemove = new JSONArray();
        claimsToRemove.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_REMOVE_API, claimsToRemove);

        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    public String getBaseToken(String builderId) throws Exception {

        Page response = actions.invokeJwtBuilder_create(_testName, builderServer, builderId);
        String jwtToken = BuilderHelpers.extractJwtTokenFromResponse(response, JWTBuilderConstants.BUILT_JWT_TOKEN);
        Log.info(thisClass, _testName, "Token From Response: " + jwtToken);
        return jwtToken;

    }

    /*****************************************************
     * Test various claimsFrom
     ****************************************************/
    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and create a JWT Token (in the servlet)
     * <LI>In the same server instance, use <config2> to create another builder.
     * <LI>Use the claimsFrom api to load all claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains all of the claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtToken_allClaims() throws Exception {

        String baseBuilderId = "altJwt1";
        // The test code can't really convert the jwt string into the jwt token, so, tell the
        // test app to create a jwt token from another jwt builder config
        // use that as the source for the claimFrom call.
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_PARAM_BUILDER_ID, baseBuilderId);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_TOKEN);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using one builder), then create a builder for another builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        // extract the first jwt token from the output and use that to create expectations.  We'll compare the content of the second token
        // to that of the first (since everything from the original token was obtained via claimFrom(<jwtToken>), they should be the same
        String jwtToken = BuilderHelpers.extractJwtTokenFromResponse(response, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM + ": ");
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, baseSettings, builderServer);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the 3 part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load all claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains all of the claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_allClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, baseSettings, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, jwtToken);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the encoded payload of the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load all claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains all of the claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_encodedPayload_allClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, baseSettings, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass the encoded payload
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getPayload(jwtToken));

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the decoded payload of the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load all claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains all of the claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_decodedPayload_allClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, baseSettings, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass the decoded payload
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getDecodedPayload(jwtToken));

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and create a JWT Token (in the servlet)
     * <LI>In the same server instance, use <config2> to create another builder.
     * <LI>Use the claimsFrom api to load specific claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains the specific claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtToken_specificClaims() throws Exception {

        String baseBuilderId = "altJwt1";
        // The test code can't really convert the jwt string into the jwt token, so, tell the
        // test app to create a jwt token from another jwt builder config
        // use that as the source for the claimFrom call.
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_PARAM_BUILDER_ID, baseBuilderId);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_TOKEN);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using one builder), then create a builder for another builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
        expectationSettings.put("overrideSettings", testSettings);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        // extract the first jwt token from the output and use that to create expectations.  We'll compare the content of the second token
        // to that of the first (since everything from the original token was obtained via claimFrom(<jwtToken>), they should be the same
        String jwtToken = BuilderHelpers.extractJwtTokenFromResponse(response, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM + ": ");
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the 3 part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load specific claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains the specific claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_specificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, jwtToken);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        expectationSettings.put("overrideSettings", testSettings);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the encoded payload of the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load specific claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains the specific claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_encodedPayload_specificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        expectationSettings.put("overrideSettings", testSettings);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the decoded payload of the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load specific claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second returned JWT Token contains the specific claims from the original token
     * </OL>
     *
     * @throws Exception
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_decodedPayload_specificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getDecodedPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        expectationSettings.put("overrideSettings", testSettings);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**************************/
    /**
     * Test Purpose:
     * <OL>
     * <LI>Use <config2> to create a
     * <LI>Use the claimsFrom api to try to load all claims from a null token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtToken_null_allClaims() throws Exception {

        String baseBuilderId = "altJwt1";
        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it the builder id and indicate the form that the jwt should be in when it's passed
        // to the api (it takes JwtToken, or String (the string can be the 3 part token, or the payload
        // only - decoded or encoded
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_PARAM_BUILDER_ID, baseBuilderId);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_TOKEN_NULL);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using one builder), then create a builder for another builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Use <config2> to create a
     * <LI>Use the claimsFrom api to try to load specific claims from a null token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtToken_null_specificClaims() throws Exception {

        String baseBuilderId = "altJwt1";
        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it the builder id and indicate the form that the jwt should be in when it's passed
        // to the api (it takes JwtToken, or String (the string can be the 3 part token, or the payload
        // only - decoded or encoded
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_PARAM_BUILDER_ID, baseBuilderId);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_TOKEN_NULL);
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using one builder), then create a builder for another builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and create a JWT Token (in the servlet)
     * <LI>In the same server instance, use <config2> to create another builder.
     * <LI>Use the claimsFrom api to load a <null> claim from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtToken_nullSpecificClaims() throws Exception {

        String baseBuilderId = "altJwt1";
        // The test code can't really convert the jwt string into the jwt token, so, tell the
        // test app to create a jwt token from another jwt builder config
        // use that as the source for the claimFrom call.
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_PARAM_BUILDER_ID, baseBuilderId);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_TOKEN);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(null);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using one builder), then create a builder for another builder, load all claims from the token into the second builder
        String builderId = "jwt1";

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        // extract the first jwt token from the output and use that to create expectations.  We'll compare the content of the second token
        // to that of the first (since everything from the original token was obtained via claimFrom(<jwtToken>), they should be the same
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and create a JWT Token (in the servlet)
     * <LI>In the same server instance, use <config2> to create another builder.
     * <LI>Use the claimsFrom api to load a "" claim from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtToken_emptySpecificClaims() throws Exception {

        String baseBuilderId = "altJwt1";
        // The test code can't really convert the jwt string into the jwt token, so, tell the
        // test app to create a jwt token from another jwt builder config
        // use that as the source for the claimFrom call.
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_PARAM_BUILDER_ID, baseBuilderId);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_TOKEN);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using one builder), then create a builder for another builder, load all claims from the token into the second builder
        String builderId = "jwt1";

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        // extract the first jwt token from the output and use that to create expectations.  We'll compare the content of the second token
        // to that of the first (since everything from the original token was obtained via claimFrom(<jwtToken>), they should be the same
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and create a JWT Token (in the servlet)
     * <LI>In the same server instance, use <config2> to create another builder.
     * <LI>Use the claimsFrom api to load a non-existant claim from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we do NOT find a claim for the requested claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtToken_nonExistantSpecificClaim() throws Exception {

        String baseBuilderId = "altJwt1";
        // The test code can't really convert the jwt string into the jwt token, so, tell the
        // test app to create a jwt token from another jwt builder config
        // use that as the source for the claimFrom call.
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_PARAM_BUILDER_ID, baseBuilderId);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_TOKEN);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("someClaim");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using one builder), then create a builder for another builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
        expectationSettings.put("overrideSettings", testSettings);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        // extract the first jwt token from the output and use that to create expectations.  We'll compare the content of the second token
        // to that of the first (since everything from the original token was obtained via claimFrom(<jwtToken>), they should be the same
        String jwtToken = BuilderHelpers.extractJwtTokenFromResponse(response, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM + ": ");
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Invoke the builder client servlet passing in the <null> as the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load all claims from the null token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_null_allClaims() throws Exception {

        // don't bother building a token from another build to get claims from - we're testing claimFrom(null)

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass a null string
        String nullString = null;
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, nullString);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Invoke the builder client servlet passing in the <null> as the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load specific claims from the null token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_null_specificClaims() throws Exception {

        // don't bother building a token from another build to get claims from - we're testing claimFrom(null)

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass a null string
        String nullString = null;
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, nullString);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Invoke the builder client servlet passing in the "" as the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load all claims from the empty token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_empty_allClaims() throws Exception {

        // don't bother building a token from another build to get claims from - we're testing claimFrom("")

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass a empty string
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, "");

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);
    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Invoke the builder client servlet passing in the "" as the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load specific claims from the empty token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_empty_specificClaims() throws Exception {

        // don't bother building a token from another build to get claims from - we're testing claimFrom("")

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass a empty string
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, "");
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Invoke the builder client servlet passing in garbage as the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load all claims from the garbae token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    @ExpectedFFDC("org.jose4j.lang.JoseException")
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_garbage_allClaims() throws Exception {

        // don't bother building a token from another builder to get claims from - we're testing claimFrom("foo.foo.foo") (garbage)

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass a empty string
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, "foo.foo.foo");

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /***
     * Test Purpose:
     * <OL>
     * <LI>Invoke the builder client servlet passing in garbage as the token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load all claims from the garbage token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    @ExpectedFFDC("org.jose4j.lang.JoseException")
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_garbage_specificClaims() throws Exception {

        // don't bother building a token from another builder to get claims from - we're testing claimFrom("foo.foo.foo") (garbage)

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6017E_BAD_EMPTY_TOKEN, builderServer);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        // just pass a empty string
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, "foo.foo.foo");
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(PayloadConstants.JWT_ID);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        String builderId = "jwt1";
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the 3 part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load <null> claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_nullSpecificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);

        String builderId = "jwt1";

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, jwtToken);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(null);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the 3 part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load "" claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_emptySpecificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);

        String builderId = "jwt1";

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, jwtToken);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the 3 part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load non-existaint claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_nonExistantSpecificClaim() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, jwtToken);
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("someClaim");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        expectationSettings.put("overrideSettings", testSettings);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the encoded payload part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load <null> claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_encodedPayload_nullSpecificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);

        String builderId = "jwt1";

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(null);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the encoded payload part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load "" claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_encodedPayload_emptySpecificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);

        String builderId = "jwt1";

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the encoded payload part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load non-existant claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_encodedPayload_nonExistantSpecificClaim() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("someClaim");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        expectationSettings.put("overrideSettings", testSettings);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the decoded payload part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load <null> claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_decodedPayload_nullSpecificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);

        String builderId = "jwt1";

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getDecodedPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add(null);
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);
    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the decoded payload part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load "" claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that we get the correct failures trying to run claimFrom
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_decodedPayload_emptySpecificClaims() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);

        String builderId = "jwt1";

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getDecodedPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6015E_INVALID_CLAIM, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);

    }

    /**
     * Test Purpose:
     * <OL>
     * <LI>Create a JWT builder using <config1> and return the JWT Token string.
     * <LI>Invoke the builder client servlet again passing in the decoded payload part token
     * <LI>Have the client use <config2> when it creates the builder.
     * <LI>Use the claimsFrom api to load non-existant claims from the original token
     * <LI>Build another token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>Verify that the second token contains cliams appropriate for the config that the token is based on...
     * </OL>
     *
     * @throws Exception
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_claimsFrom_jwtString_decodedPayload_nonExistantSpecificClaim() throws Exception {

        // build a token using the alternate builder config (we'll get claims from it)
        String baseBuilderId = "altJwt1";
        String jwtToken = getBaseToken(baseBuilderId);
        JSONObject baseSettings = BuilderHelpers.setClaimsFromToken(jwtToken);

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // build settings that will tell the test app how to run/what to pass to the "claimFrom" api
        // give it a flag that says jwt string, and then pass the 3 part jwt token string
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM, JWTBuilderConstants.JWT_BUILDER_ACTION_CLAIM_FROM_JWT_STRING);
        testSettings.put(JWTBuilderConstants.JWT_TOKEN, BuilderHelpers.getDecodedPayload(jwtToken));
        // build a list of claims that we want to use claimFrom with (claims that we want to copy from the original token to the new token)
        JSONArray claimsFrom = new JSONArray();
        claimsFrom.add("someClaim");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIMFROM_API, claimsFrom);

        expectationSettings.put("overrideSettings", testSettings);
        // since we getting all claims in the case, we can base our expectations upon the content of this first token)
        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, baseSettings, builderServer);

        // Now, add any override values - for this test, there are none
        // Invoke the builder app to create a token (using (a second) builder, load all claims from the token into the second builder
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);

        validationUtils.validateResult(response, expectations);
    }

    /***************************************************** Test signWith ****************************************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg HS256/signingKey "useThisToSign")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_HS256_key_string() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a null signingKey value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg HS256/signingKey <null>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_HS256_key_null() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, null);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6036E_INVALID_KEY, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with an empty( "") signingKey value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg HS256/signingKey "")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_HS256_key_empty() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6036E_INVALID_KEY, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a valid signingKey value, but RS256 as sigAlg
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg RS256/signingKey "signWith")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_RS256_key_string() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6037E_INVALID_SIG_ALG, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a valid signingKey value, but <null> as sigAlg
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg <null>/signingKey "signWith")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_null_key_string() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, null);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6037E_INVALID_SIG_ALG, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a valid signingKey value, but "" as sigAlg
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg ""/signingKey "signWith")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_empty_key_string() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, "");
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6037E_INVALID_SIG_ALG, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a valid signingKey value, but "someNonAlg" as sigAlg
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg someNonAlg/signingKey "signWith")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_garbage_key_string() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, "someNonAlg");
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6037E_INVALID_SIG_ALG, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg RS256/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_RS256_key_privKey() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg RS384/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_RS384_key_privKey() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS384);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg RS512/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_RS512_key_privKey() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS512);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg ES256/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_ES256_key_privKey() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_ES256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg ES384/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_ES384_key_privKey() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_ES384);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg ES512/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_ES512_key_privKey() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_ES512);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg PS256/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_PS256_key_privKey() throws Exception {

        // TODO - need to add code to handle non-Java 11 case handling - it may/may not make sense depending on whether we can get through the test client to actually call the builder with the alg set to PS256
        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_PS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg PS384/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_PS384_key_privKey() throws Exception {

        // TODO - need to add code to handle non-Java 11 case handling - it may/may not make sense depending on whether we can get through the test client to actually call the builder with the alg set to PS384
        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_PS384);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value to generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg PS512/signingKey <privateKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_PS512_key_privKey() throws Exception {

        // TODO - need to add code to handle non-Java 11 case handling - it may/may not make sense depending on whether we can get through the test client to actually call the builder with the alg set to PS512
        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_ES512);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg HS384/signingKey "useThisToSign")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_HS384_key_string() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS384);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a good value generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have updated signWith (value should be created from sigALg HS512/signingKey "useThisToSign")
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_HS512_key_string() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS512);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    // TODO - should add cases where we specify one alg, and then point to the private key of another alg - need runtime updates before this can be done.

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a bad value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value should be created from sigALg RS256/signingKey <publicKey>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_RS256_key_publicKey() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PUBLIC_KEY_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6036E_INVALID_KEY, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with <null> signingKey value
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg RS256/signingKey <null>)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_RS256_key_null() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS256);
        testSettings.put(JWTBuilderConstants.SHARED_KEY, null);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6036E_INVALID_KEY, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a valid signingKey value, but <null> as sigAlg
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg <null>/signingKey privateKey)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_null_key_privKey() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, null);
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6037E_INVALID_SIG_ALG, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a valid signingKey value, but "" as sigAlg
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg ""/signingKey privateKey)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_empty_key_privKey() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, "");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6037E_INVALID_SIG_ALG, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run the signWith api to update the builder with a valid signingKey value, but "someNonAlg" as sigAlg
     * <LI>generate a JWT token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should NOT have updated signWith (value failed due to sigALg "someNonAlg"/signingKey privateKey)
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking "signWith"
     * <LI>The failure messages from our attempt to invoke "signWith"
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * </UL>
     * </OL>
     */
    //chc@Test
    public void JwtBuilderAPIBasicTests_signWith_sigAlg_garbage_key_privKey() throws Exception {

        String builderId = "jwt1";

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(HeaderConstants.ALGORITHM, "someNonAlg");
        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);

        Expectations expectations = BuilderHelpers.createBadBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, JwtMessageConstants.CWWKS6037E_INVALID_SIG_ALG, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

    }

    /*************************** Test multiple settings and consume Token ***************************/
    /**
     * <p>
     * Test Purpose:
     * <OL>
     * <LI>Create a builder using the specified configId (a generic config used for most tests)
     * <LI>Run a variety of the api's to update the builder
     * <LI>generate a JWT token
     * <LI>Invoke a protected app using the generated JWT Token
     * </OL>
     * <P>
     * Expected Results:
     * <OL>
     * <LI>The builder should be created with default values as there is not much defined in the specified config
     * <LI>The builder should have been updated
     * <LI>The JWT Token should be created based on the builder
     * <LI>The JWT Token will be used to display the claim values
     * <LI>The JWT Token will be used to generate a JWT JSON String and this will be returned
     * <LI>The test case will validate the content of:
     * <UL>
     * <LI>The messages logged indicating that we were invoking various set apis
     * <LI>The content of the returned token
     * <LI>The output from running the query apis
     * <LI>The output from invoking the protected app
     * </UL>
     * </OL>
     */
    @Mode(TestMode.LITE)
    //chc@Test
    public void JwtBuilderAPIBasicTests_multiple_apis_and_consumeToken() throws Exception {

        String builderId = null;
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderServer);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        // set freeform claims into a json object.  Add that object into the json object of things to set
        JSONObject testSettings = new JSONObject();
        testSettings.put(PayloadConstants.SUBJECT, "testuser");
        testSettings.put(PayloadConstants.EXPIRATION_TIME, testExp);
        testSettings.put(PayloadConstants.NOT_BEFORE, 1477691420L);
        JSONObject claimsToSet = new JSONObject();
        claimsToSet.put(PayloadConstants.AUTHORIZED_PARTY, "someParty");
        claimsToSet.put("someClaim", "someValue");
        claimsToSet.put("anotherClaim", "anotherValue");
        claimsToSet.put("stillOneMoreClaim", "stillOneMoreValue");
        testSettings.put(JWTBuilderConstants.JWT_BUILDER_CLAIM_API, claimsToSet);
        expectationSettings.put("overrideSettings", testSettings);

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        // Indicate how claims are to be handled (one at a time, or added as a hashmap)
        List<NameValuePair> extraParms = new ArrayList<NameValuePair>();
        extraParms.add(new NameValuePair(JWTBuilderConstants.ADD_CLAIMS_AS, processClaimsAs));
        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, extraParms, testSettings);
        validationUtils.validateResult(response, expectations);

        // Page appResponse = actions.invokeProtectedAppWithJwtTokenInHeader(_testName, response, protectedApp);
        // Try to use the JWT Token created by the builder - it can be passed in the header
        // as well as - as a parm -  in this test we'll pass as a parm - another test will pass in the header
        // the method will pull the JWT Token from the builder response
        Page appResponse = actions.invokeProtectedAppWithJwtTokenAsParm(_testName, response, protectedApp);

        Expectations appExpectations = new Expectations();
        appExpectations.addExpectations(CommonExpectations.successfullyReachedUrl(null, protectedApp));
        validationUtils.validateResult(appResponse, appExpectations);

    }

    /***************************************************** Test encryptWith ****************************************************/
    /**
     * The encryption tests will behave the same as the non-encryption tests - the test app will run the set methods,
     * build, then the get methods - the output from the get methods is what the builder expectations will validate against.
     * When the token is encrypted, the same get methods should/better work... So, we'll be testing that they return
     * the correct results.
     * The app will also run compact on the builder to generated the JWT Token string - when it's encrypted, it'll create
     * a 5 part string (not encrypted, it'll be 3 parts)
     * The encryption tests will decrypt and parse the token to do extra validation on the token!
     *
     **/
    // encryptWith(String  keyManagementAlg,  Key keyManagementKey,  String  contentEncryptionAlg)
    //"RSA-OAEP",  rsaPublicKey, "A256GCM"
    @Test
    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS256_publicKey_A256GCM() throws Exception {

        String builderId = "jwt1";
        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);

        // create settings that will be passed to the test app as well as used to create what to expect in the results
        JSONObject testSettings = new JSONObject();
        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
        //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS256public-key.pem"));
        //        String tempKey = "MIIEogIBAAKCAQEAl66sYoc5HXGHnrtGCMZ6G8zLHnAl+xhP7bOQMmqwEqtwI+yJJG3asvLhJQiizP0cMA317ekJE6VAJ2DBT8g2npqJSXK/IuVQokM4CNp0IIbD66qgVLJ4DS1jzf6GFciJAiGOHztl8ICd7/q0EvuYcwd/sUjTrwRpkLcEH2Z/FE2sh4a82UwyxZkX3ghbZ/3MFtsMjzw0cSqKPUrgGCr4ZcAWZeoye81cLybY5Vb/5/eZfkeBIDwSSssqJRmsNBFs23c+RAymtKaP7wsQw5ATEeI7pe0kiWLpqH4wtsDVyN1C/p+vZJSia0OQJ/z89b5OkmpFC6qGBGxC7eOk71wCJwIDAQABAoIBAAy0O4nxC26U4KgBxWbcwMNtTqHZAMVcDu24uV4Po3mc1EKeAAqGDOgqAYNpisEifebkdHGdr/3uPEZQC0DUYwa7qL33F10j2bINcTcEnO9Qej5VxyHw5K8t2wsYw0A10IvWJaImBm6zRwcfd0+TtPwFZ8OAdwJUm0bcnULIAeLAUZRjqq7pxq89Myjr1l2RHVqGkIzPFYxI/G5Dcb/JSJ8hHqCQHfcNm9+ZV77scvCU3PbUrnKsnpWR2Pb7Ob5GXUWDQ6btO1Fjz8fosbH9A4XMPJC9cFdeu2kX5pqS2UYEJJPYyivS6iai12lRKaC96DI9IxoSxsem/fNIPrH6j7kCgYEA1OcDNUc+HC3VjcN0sxP2aPZSrKqmbzZUuGUyzr81o067vprA0Op+xIdB4v+d6E+MQrZnvQ331Q1zfgVAlKx0UH2Q+YiCWRSPTQFtN1U+aJX2v+gi+eZJuv6DI8SjlXm6iECoqXT90As/y5pk9Jf06k8Ew77RcDcwjM0Whq/xUH0CgYEAtmMgL4lD+YlDuxGfTciacV5hJdteHSBprYA7gzqAb8ttel4h2QBfqmUY/kenv7oCJKiMpIboKYybsX7vfcj/BtNPkjDLofdAqy3E83hcIsYuEQh1R7+jSjBhBFeUO9aOHFt+UkE/42tNOLkIzsWgTkokwS94pKLZal/BIg/JYnMCgYAU0fadWjc3uD+/GlMqRBR/1T7mhdW64HxOgA8E6uwK6WMw059xjs0Q2Q1Xbpn5ovXbfE0OzvPikOsvcsILCAZj7LOlw3TD01/kLvSISbzNq4Sy5bet6phhQgx/DfbVYk8cjf4wfDFqC/+UIKgox0d7NnkHz3xZ1fvYeSHvz/rwXQKBgEp430OJwP+7VLSl1W5lYuq3puNWV299NKlrmuFSme8MGX/Fv/xjcqyY60Oo7o4S3Z0qVYM4ssOEbm5jblbmI3wd/HetBPj1hKpg3fKsSrLISTcbRQgu7/XzGyoyuIxWZ2Cc20+q5PNvdPCcXURQ3cwZ6jgXsiNHe4872hiWaZyRAoGAEBUyzUeBeVhcEPeAv0XY6Ck3xrp/qmZCkTMmT7nVYD1T39Px5hqEmEHEh+gX6zHgh3Ws+UJ1bKoV4oJiygDV78Q74Q/Z/2Bd3FHbG557UZfp47ESNaJMLIRsC7+ak8iU0DBgrEmJm1pwBJXdmfXD4T44Y7jZvN2b2xtyx1fAmUc=";

        //        String encryptKey = getKeyFromFile(builderServer, "p3.pem");
        String encryptKey = JwtKeyTools.getComplexPublicKeyForSigAlg(builderServer, JWTBuilderConstants.SIGALG_RS256);
        String decryptKey = JwtKeyTools.getComplexPrivateKeyForSigAlg(builderServer, JWTBuilderConstants.SIGALG_RS256);
        //        String encryptKey = getKeyFromFile(builderServer, "RS256public-key.pem");
        //        String decryptKey = getKeyFromFile(builderServer, "RS256private-key.pem");
        //        Log.info(thisClass, _testName, "returned key: " + pem);

        //        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        //        pem = pem.replaceAll("-----END (.*)----", "");
        //        pem = pem.replaceAll("\r\n", "");
        //        pem = pem.replaceAll("\n", "");
        //        tempKey = pem.trim();
        //        Log.info(thisClass, _testName, "cleaned up key: " + tempKey);

        //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, tempKey);
        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, encryptKey);
        testSettings.put(JWTBuilderConstants.DECRYPT_KEY, decryptKey);
        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
        //        expectationSettings.put("overrideSettings", testSettings);
        // TODO - update expectations for the encryption settings.

        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);

        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
        validationUtils.validateResult(response, expectations);

        String jwtToken = BuilderHelpers.extractJwtTokenFromResponse(response, JWTBuilderConstants.BUILT_JWT_TOKEN);
        //        jwtToken = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";
        //        jwtToken = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJraWQiOiJxaWhZLW5lVHlKd0tNWG81c29yT3F3bkhCWHpvb2JrakJ3aXlkZnZvVzJzIiwidHlwIjoiSldUIiwiY3R5Ijoiand0In0.GEJjXADkHx-XoXk0LA3jzMNyHmRVpukKjAoFI6szH-s4N7Nu1EimoOQ4JK2N-oqSjt09e4vzDaghYnEUuxJHOOtlxnjA3VZV2S5mniMLwCa9n3rxi97H_sUWx72gP5KnBViXFd8dx0u72klXlJfezKEAQjz2x8WFbNembZDTV1ElU3d8t7UbzIWuLqigOn9aTf1e963QfflRZpgDiTAzSYTWlvSw0v105EpadJtFASMO50mjs2Xw-AIHBoVnkSL6mc5Vh_ipR6Wi8xzv_txe3XxTMi7OiNnytjAdn-PZhbHAEgAstCRNQP7r4FEtvCUaSj6cJridldQrMzPt3mjPEA.qAhweAiitvj0tntY.We-Ot4lfJMpdwTWm5iLxa6VjQ0Fjy5nIiaZxM5NMTqQjK1IOZngrp5NHMSFInbXGb9bztSMMX7ry8kgh4qqrbY274cy-CglJd64eaaHAuH0ubZEO4Lo3eYfvl9B2SXYV_moSPJdt_IfIYmjHmem1h-UUyxhyItCAE5ntN4XyxwnYdv3yae9FW2hrIVTvEW7crVvP4M7gP4Q_sigr1R7hIdvFQyhdbYsdmOezitSEAiFQAEXejMB1VwwxzvhBAQ5ixYk5fzA5eJTF0nOFqV9xMNX981u0iQ9AJGn5VIfrpbGjZyU95xB2H-Bb8oie1LbeNpksNF_gSe27Up2b7pjqYaHY5l6jtWUWyDYypnyPXo5bQzy1TSIFSxCKFN53jR9vpZ37iiZJFnbZwvVR7K0OReka61YEGegm_28w14TvLXyrqoEDEYeyHNfjKvQy_exxJyP8Fv34-9NwIC0VrOcTnnQ3lTCNW3md0sMNoyXKiTzKHj53lyl3IFLZHJ8ohOXmcPEn-ikXV_51QJfADPihQ5OjTD_kszssvQSm0CF3X8709Ih7Zzix7WS_4KMzI8S8QYi5yq18sgBBpWjJg-byr32A_dGZp9NRQcEO6JrHye2rCP2XKKkXBj_ZiTk23U5ODxVkT55_H26rF6FYiBrAh8jY2gno8a0kwqugMZmr89svYhL0VfAjPnhO4CmZvn8kHQzA7_40UDzjLnHA879e4R9gR5xYNv5hV4NBva5orLZD4ewOEO4aWHu3biq0s0a1qZ5KwvVPxHhtlO2YPt2A_eH8vMYhQhCVmO3HXqGRIH4.0xihvEMRgOEfTHB-AmxKpQ";
        validationUtils.validateEncryptedToken(jwtToken, testSettings);
        //        Log.info(thisClass, _testName, JwtTokenForTest.deserialize("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ").toString());
        //
        //        //        Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        //        //        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec("SHA-256", "MGF1",
        //        //                        MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        //        //        decryptionCipher.init(Cipher.DECRYPT_MODE, null, oaepParameterSpec);
        //        //
        //        //        String xyz = "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg";
        //        //        decryptionCipher.
        //        //
        //        Log.info(thisClass, _testName, JwtTokenForTest.fromBase64ToJsonString("OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg"));
        //        //                cek = RSA-OAEP. //.new(key).decrypt(urlsafe_b64decode(xyz), None);
        //        Log.info(thisClass, _testName, JwtTokenForTest.fromBase64ToJsonString("48V1_ALb6US04U3b"));
        //        Log.info(thisClass, _testName, JwtTokenForTest.fromBase64ToJsonString("5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A"));
        //        Log.info(thisClass, _testName, JwtTokenForTest.fromBase64ToJsonString("XFBoMYUZodetZdvTiFvSkQ"));

        //        jwtToken
        //        foo2(jwtToken);
    }

    //    public void foo2(String jwtToken) throws Exception {
    //        JsonWebStructure joseObject = JsonWebStructure.fromCompactSerialization(jwtToken);
    //        String payload;
    //        JwtClaims jwtClaims = null;
    //        LinkedList<JsonWebStructure> joseObjects = new LinkedList<>();
    //        DecryptionKeyResolver decryptionKeyResolver;
    //
    //        if (joseObject instanceof JsonWebSignature) {
    //            JsonWebSignature jws = (JsonWebSignature) joseObject;
    //            payload = jws.getUnverifiedPayload();
    //        } else {
    //            JsonWebEncryption jwe = (JsonWebEncryption) joseObject;
    //            jwe.setDoKeyValidation(false);
    //            final List<JsonWebStructure> nestingContext = Collections.unmodifiableList(joseObjects);
    //                        Key key = decryptionKeyResolver.resolveKey(jwe, nestingContext);
    //            //            jwe.setKey(key);
    ////            jwe.setKey("none");
    //            payload = jwe.getPayload();
    //        }
    //
    //    }

    //    public void foo(String jwtToken) throws Exception {
    //
    //        //        String message = "Well, as of this moment, they're on DOUBLE SECRET PROBATION!";
    //        //
    //        //        // The shared secret or shared symmetric key represented as a octet sequence JSON Web Key (JWK)
    //        //        String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
    //        //        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
    //        //
    //        //        // Create a new Json Web Encryption object
    //        //        JsonWebEncryption senderJwe = new JsonWebEncryption();
    //        //
    //        //        // The plaintext of the JWE is the message that we want to encrypt.
    //        //        senderJwe.setPlaintext(message);
    //        //
    //        //        // Set the "alg" header, which indicates the key management mode for this JWE.
    //        //        // In this example we are using the direct key management mode, which means
    //        //        // the given key will be used directly as the content encryption key.
    //        //        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
    //        //
    //        //        // Set the "enc" header, which indicates the content encryption algorithm to be used.
    //        //        // This example is using AES_128_CBC_HMAC_SHA_256 which is a composition of AES CBC
    //        //        // and HMAC SHA2 that provides authenticated encryption.
    //        //        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
    //        //
    //        //        // Set the key on the JWE. In this case, using direct mode, the key will used directly as
    //        //        // the content encryption key. AES_128_CBC_HMAC_SHA_256, which is being used to encrypt the
    //        //        // content requires a 256 bit key.
    //        //        senderJwe.setKey(jwk.getKey());
    //        //
    //        //        // Produce the JWE compact serialization, which is where the actual encryption is done.
    //        //        // The JWE compact serialization consists of five base64url encoded parts
    //        //        // combined with a dot ('.') character in the general format of
    //        //        // <header>.<encrypted key>.<initialization vector>.<ciphertext>.<authentication tag>
    //        //        // Direct encryption doesn't use an encrypted key so that field will be an empty string
    //        //        // in this case.
    //        //        String compactSerialization = senderJwe.getCompactSerialization();
    //
    //        // Do something with the JWE. Like send it to some other party over the clouds
    //        // and through the interwebs.
    //        //        System.out.println("JWE compact serialization: " + compactSerialization);
    //
    //        JsonWebEncryption receiverJwe = new JsonWebEncryption();
    //        receiverJwe.setCompactSerialization(jwtToken);
    //        //        receiverJwe.setKey(secretKeySpec);
    //        Log.info(thisClass, "foo", "1");
    //        String key = "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDo4lWgnO2opBMp\n" +
    //                "345sI2KRRvq8zt8s45qVul8NG/b/OH1jZdkZX6/H37OW07FnAhJt2MQGJMRxE/hv\n" +
    //                "wa2p3VehXDeBXJMW4KLbHOjhxXGpYCgLboPuNGBcptyYm/mBVO8GmPm95k+6TCHC\n" +
    //                "wExh6ZzqrqlvDVxn8fACQIyL5eS3ncUGehHGr7vxt6m7Z5sq8DgI35PRiZRooLRi\n" +
    //                "RqOsESKhYPcew/4MhhQoRTKl2SYZsBnRbGBJxzLXIiOHYxXPWYYUYlTiz1tuYVmr\n" +
    //                "XFqE4Uq8ltbCbLASFCH/C9m57Xu7a2VH0c+fSbktxLRNOxA6ZANRh3fnyWM3bEld\n" +
    //                "wGsZ+234ybZyEqdTB6ASdDpJMJDrNrACdrChaQkON7pPWb9tZemtijZhCyC46xrx\n" +
    //                "k7QUGgrBPnvwr4rTOBI1Mn3rpPUwf5EGWqCltfRqaiODcFt9q5cn8G7N7mLYKWpi\n" +
    //                "iRbEIVNkOJvoiJQXMk3Do9IyobTROAXiXqQ3GHilvwXNbgOQ9u0zZzv+DdVQso+2\n" +
    //                "Tdrnwn003MPzF7feAU/MMKEu62oo33QY97A+YBnat+wFNxMbWvq45bPmK+zO39/k\n" +
    //                "xLWscjNFSIjCwUq2BNLTtLPRvvnX3wri29WN7qHHWSshu8AG2GfqvEDyYbZdLLKK\n" +
    //                "je96oX6LCTyvgbMC9p9GWWVE3HA9UQIDAQABAoICAQDSXaF7tEX6UDv/VzIP/ObM\n" +
    //                "1JEqfLScl/zLw86YyOoVIbIiV54Ejar7oddYJ2HY6sY689QeuJe6jY+dZBa7mnXO\n" +
    //                "DL8W28kCoWh7BWJYj0Jc/b8ulGYYhreE+jXKpRp8+XvxOb5fC+x5HMxiX9Kfn6df\n" +
    //                "Vuc2qZsPSjzDzAspVEGGm72eXCYylAvyDTYFU1GXN+dmHJAqd1zYJlLLc4PlqpTd\n" +
    //                "sfmIkQKrzXHn7poRtlX0Xl70DjHsc0Q5kV0GrzrEUtoLD8geGbE9xDJ72LDr15br\n" +
    //                "RFY6ynNB4W3UNaA3k45xflG+zof+G1prPYShPvkpxa45t2VYu1IkfmzHg0k77yMm\n" +
    //                "H9fHIKN8eitTZEH1uPBx89Lngmfmer1Ap2aS/PY3w/tL7k37K/NpcCEAvqF7pIEX\n" +
    //                "dDYFGguVp5tVq4tcZMikJmN/1Jpg27AJDoSOA55kMXXXsFYjlTblTaIyf4876Uuc\n" +
    //                "rVi//NPNwgtuzgSM5rrSatEGM9GsV+SZpmmCZxPd8qdH/lvKFbB6eKect6pERlo0\n" +
    //                "h1JqcRcSRo44PamobkqGBPbx2P02FsgxWAu1KLaYCzjYwISzzm1fAVzMSvwT/UYd\n" +
    //                "wIEgB+2ameaB+m+BW8ddK1Bod/C1A8JrkFdJwYXAwqkTGJr+IHFYRNYbcJWo2DFK\n" +
    //                "b86e5LbEjBTqNVIHZiNZAQKCAQEA+UVPlyDO8Ps8XnP86yuM/yTfU+39l1htca18\n" +
    //                "2usJC4qiHNywiFwpyo6Mjdx00XG3ZgDYB/cw7j6YMaWZABXlVV44jITNRAPpfjmd\n" +
    //                "BJvZfbjEEx9uQjh8BQcoyV9atJzIdq8eRyzZXHmjkTLxNbBXdYizSXuxLKU1F8AS\n" +
    //                "fKOjj7fX6oRxOSkMWpV1fJ0OCOciZcg7+3OYdEKvNKqdq+Z38ZdKY10EsJYFdO+N\n" +
    //                "V7jp7qZzO+HHSDF5b9VT3/wdIPy3qHOvz36rtERI0BkF9B+qFXmBdltQe4sxefx/\n" +
    //                "MPSYcQDaTblDwmvus17AeWqiJnWNwUHnVwnV11hsS0Z+mBb3EwKCAQEA7yvG6Kj8\n" +
    //                "EpjgiNAmGce1PQ7BWTb6S07z6z4b9YS8HCgtkKnFBF2DWYPhbTOHu74kLwwlUOEy\n" +
    //                "Qd2Wm6+a8jQ4JFp920eeXn5SJ+k5IsUBGdRjJVhrqY9mXNBEZXx7cjdGRSdENj9X\n" +
    //                "wYQ1ReB0KHSXfJfRPb0AnxdO12oV7JLUMKor/761k6iZaCin6ZDlI3PGw+RApLOD\n" +
    //                "apfGB/5tuDydfTxT6EFynG0alpRZwYzWFeh1S1HBijIkhsDjv5pt28FeRXMH1ckf\n" +
    //                "l62yDMwTs0pLvBYjXeVtYNv8MNAl5PNGPOC+OkzpUHyOV+p7c8ml6Z/y5eY9A0SI\n" +
    //                "/juL9yppllxSiwKCAQEAiNujHSioNeradEleXYflu9f0vdH233dvb3B/Enrk1m9h\n" +
    //                "HlOUoOlpEIs/ZEvb33p95QUllwoC1WuMiAWRgViEN2Cpz4zCXkt/kQv0x6kBumMN\n" +
    //                "VCp3kOgOP3x0yksONAe4kGEJUK6xEHLAeWHsyTtuaVuKhBfjaM2z3rxX6hK2JJwd\n" +
    //                "cecRev6sh7dzb92S7RRp8FQFisMmuv45z8K1GsJIrF4SO4fAoWtcx50Wj0k5Nwww\n" +
    //                "THpjvaFcOSh5CosTOx9Ffrk1l8jGYQz0pTx35lbUPUIe8GqmP45mtcEJ3EkOwUxk\n" +
    //                "jzPengpAXj7xkjgXmuID2E1kxIbj333ux02HB93j/QKCAQByB38oQhkcjMLQt9zS\n" +
    //                "gcLJP5WzgWDIMvZcfBo8bnJ5QjanOCn0sNkE/rmlpOHcAwWhYLsR2qxpdspto8XO\n" +
    //                "IFN8EaDbwUOibbuhx7Iz/5VMyVQT5BpAl1wIeEuDz1vT0sKwCc6dxomCfBQiIqd+\n" +
    //                "+keXYZKjSs9XCnfOgIe/aSm9ogSkRDqyEbpCTM/xreFxi6uCjfq8C9JmKcKC4S1S\n" +
    //                "n6O+p9qha0LHjcUVcdlxTEJt44y4wlvyFYIQtTpgibJDCeh2WCeuJ9vmJywyqcHi\n" +
    //                "w1Nkc3GdPNtvSLLuWu8WP16He+d2SGEcvKXpCKSfSc7OmjHmpmUEf9KI078hspjw\n" +
    //                "1UeNAoIBAGilEJORDnmvSZF9pOKH/s5wQLInOg5LE0lB42YJtZt+UDP+3e66479r\n" +
    //                "7WyeLqDGbH9QOmnt04lI4+SNglx17OKAIgPN+2m9CRHCnvKyZ2abrWZOl62caHSS\n" +
    //                "PScbi/tG+FfA8RLK8cinZPSm5Xhg+0n89knoARlGuJKGLN5aU2FLsC7wJ7q6Pe21\n" +
    //                "EEi7JQDGQupwUy72EEU53NkVOzt+Bmu5wGT0MbRVmoXPD7ii1piIkRKwPsrxqoxS\n" +
    //                "u1vqgZjIAh25boIxARvKQ1aSz2EsMXQ46BggkLphLJduMrCNhdE5/s4dAmZgn7HR\n" +
    //                "/vAXylDo5XtsfTsoYFanx0XVQySnr6k=";
    //        //        receiverJwe.setKey(getPrivateKeyFromString(key));
    //        receiverJwe.setKey("none");
    //        Log.info(thisClass, "foo", "2");
    //
    //        String jwsPayload = receiverJwe.getPlaintextString();
    //        Log.info(thisClass, "foo", "3");
    //
    //        // And do whatever you need to do with the clear text message.
    //        System.out.println("plaintext: " + jwsPayload);
    //
    //        // Create a new JsonWebSignature object
    //        JsonWebSignature jws = new JsonWebSignature();
    //        Log.info(thisClass, "foo", "4");
    //
    //        jws.setCompactSerialization(jwsPayload);
    //        Log.info(thisClass, "foo", "5");
    //
    //        jws.setKey(null);
    //        Log.info(thisClass, "foo", "6");
    //
    //        boolean signatureVerified = jws.verifySignature();
    //        Log.info(thisClass, "foo", "7");
    //
    //        // Do something useful with the result of signature verification
    //        System.out.println("JWS Signature is valid: " + signatureVerified);
    //
    //        // Get the payload, or signed content, from the JWS
    //        String payload = jws.getPayload();
    //        Log.info(thisClass, "foo", "8");
    //
    //        // Do something useful with the content
    //        System.out.println("JWS payload: " + payload);
    //    }
    //
    //    public static RSAPrivateKey getPrivateKeyFromString(String privateKeyPEM) throws IOException, GeneralSecurityException {
    //        //        String privateKeyPEM = key;
    //        //        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
    //        //        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
    //        byte[] encoded = Base64.decodeBase64(privateKeyPEM);
    //        KeyFactory kf = KeyFactory.getInstance("RSA");
    //        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    //        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
    //        return privKey;
    //    }

    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS256_shortPublicKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "short_RS256public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS256_privateKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS512private-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS256_publicKey_A256GCM_signWith_RS256() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS256);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS256public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS256_publicKey_A256GCM_signWith_ES384() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_ES384);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS256public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS256_publicKey_A256GCM_signWith_HS512() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS512);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS256public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS384_publicKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS384public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS384_shortPublicKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "short_RS384public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS384_privateKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS384private-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS384_publicKey_A256GCM_signWith_RS384() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS384);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS384public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS384_publicKey_A256GCM_signWith_ES512() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_ES512);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS384public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS384_publicKey_A256GCM_signWith_HS256() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS256);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS384public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS512_publicKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS512public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS512_shortPublicKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "short_RS512public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS512_privateKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS512private-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS512_publicKey_A256GCM_signWith_RS512() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_RS512);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS512public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS512_publicKey_A256GCM_signWith_ES256() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_ES256);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_PRIVATE_KEY_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS512public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS512_publicKey_A256GCM_signWith_HS384() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(HeaderConstants.ALGORITHM, JWTBuilderConstants.SIGALG_HS384);
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY, "useThisToSign");
    //        testSettings.put(JWTBuilderConstants.SHARED_KEY_TYPE, JWTBuilderConstants.SHARED_KEY_STRING_TYPE);
    //        expectationSettings.put("overrideSettings", testSettings);
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS512public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_Invalid_publicKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, "Some Random string");
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_Invalid_KeyMgmtAlg_RS256_publicKey_A256GCM() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "SomeKeyMgmtAlg");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS256public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "A256GCM");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    @Test
    //    public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_RS256_publicKey_Invalid_ContentEncryptAlg() throws Exception {
    //
    //        String builderId = "jwt1";
    //        JSONObject expectationSettings = BuilderHelpers.setDefaultClaims(builderId);
    //
    //        // create settings that will be passed to the test app as well as used to create what to expect in the results
    //        JSONObject testSettings = new JSONObject();
    //        testSettings.put(JWTBuilderConstants.KEY_MGMT_ALG, "RSA-OAEP");
    //        testSettings.put(JWTBuilderConstants.ENCRYPT_KEY, getKeyFromFile(builderServer, "RS256public-key.pem"));
    //        testSettings.put(JWTBuilderConstants.CONTENT_ENCRYPT_ALG, "SomeContentEncryptAlg");
    //        //        expectationSettings.put("overrideSettings", testSettings);
    //        // TODO - update expectations for the encryption settings.
    //
    //        Expectations expectations = BuilderHelpers.createGoodBuilderExpectations(JWTBuilderConstants.JWT_BUILDER_SETAPIS_ENDPOINT, expectationSettings, builderServer);
    //
    //        Page response = actions.invokeJwtBuilder_setApis(_testName, builderServer, builderId, testSettings);
    //        validationUtils.validateResult(response, expectations);
    //
    //    }
    //
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_RSA_OAEP_sigAlg_RS256_key_string() throws Exception {
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_null_key_string() throws Exception {
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_empty_key_string() throws Exception {
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_garbage_key_string() throws Exception {
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_RS256_key_privKey() throws Exception {
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_RS384_key_privKey() throws Exception {
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_RS512_key_privKey() throws Exception {
    //    //        public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_RS256_key_publicKey() throws Exception {
    //    //    public void JwtBuilderAPIBasicTests_encryptWith_sigAlg_RS256_key_null() throws Exception {

    public static String getKeyFromFile(LibertyServer server, String fileName) throws Exception {

        String fullPathToFile = getDefaultKeyFileLoc(server) + fileName;

        CommonIOUtils cioTools = new CommonIOUtils();
        String key = cioTools.readFileAsString(fullPathToFile);

        Log.info(thisClass, "getKeyFromFile", "Key from file: " + key);
        return key;
    }

    public static String getDefaultKeyFileLoc(LibertyServer server) throws Exception {

        return server.getServerRoot() + "/";
    }
}
