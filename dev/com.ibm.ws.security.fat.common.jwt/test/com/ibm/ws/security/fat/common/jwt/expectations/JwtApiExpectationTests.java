package com.ibm.ws.security.fat.common.jwt.expectations;

import static org.junit.Assert.assertEquals;

import org.jose4j.jwt.NumericDate;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.ws.security.fat.common.jwt.JwtConstants;
import com.ibm.ws.security.fat.common.jwt.expectations.JwtApiExpectation.ValidationMsgType;
import com.ibm.ws.security.fat.common.logging.CommonFatLoggingUtils;

import test.common.SharedOutputManager;

public class JwtApiExpectationTests extends CommonExpectationTestClass {

    CommonFatLoggingUtils utils = new CommonFatLoggingUtils();

    private static SharedOutputManager outputMgr = SharedOutputManager.getInstance().trace("com.ibm.ws.security.fat.common.*=all");

    String claimTypeFailureMsg = "claimType passed to JwtApiExpectation was null - only enum values: SPECIFIC_CLAIM_API, CLAIM_LIST_MEMBER, CLAIM_FROM_LIST, HEADER_CLAIM_FROM_LIST are valid";
    String genericFailureMsg = "Response from test step  did not match expected value.";

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr.captureStreams();
    }

    @Before
    public void before() {
        System.out.println("Entering test: " + testName.getMethodName());
    }

    @After
    public void tearDown() throws Exception {
        System.out.println("Exiting test: " + testName.getMethodName());
        outputMgr.resetStreams();
        mockery.assertIsSatisfied();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        outputMgr.dumpStreams();
        outputMgr.restoreStreams();
    }

    /************************************** Constructors/getters **************************************/

    @Test
    public void test_constructor_2_nullArgs() {
        try {
            String testAction = null;
            String errorId = null;
            String configId = null;

            JwtApiExpectation exp = new JwtApiExpectation(errorId, configId);

            verifyExpectationValues(exp, testAction, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, null, buildErrorSearch(configId, errorId), buildErrorMsg(errorId));

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_2_Args() {
        try {
            String testAction = null;
            String errorId = "errorId";
            String configId = "configId";

            JwtApiExpectation exp = new JwtApiExpectation(errorId, configId);

            verifyExpectationValues(exp, testAction, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, null, buildErrorSearch(configId, errorId), buildErrorMsg(errorId));

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_nullArgs_String() {
        try {
            String testAction = null;
            String checkType = null;
            String searchFor = null;
            String failureMsg = null;

            JwtApiExpectation exp = new JwtApiExpectation(checkType, searchFor, failureMsg);

            verifyExpectationValues(exp, testAction, JwtConstants.RESPONSE_FULL, checkType, null, searchFor, failureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_String() {
        try {
            String testAction = null;
            String checkType = "checkType";
            String searchFor = "searchFor";
            String failureMsg = "failureMsg";

            JwtApiExpectation exp = new JwtApiExpectation(checkType, searchFor, failureMsg);

            verifyExpectationValues(exp, testAction, JwtConstants.RESPONSE_FULL, checkType, null, searchFor, failureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_nullArgs_Object() {
        try {
            String key = null;
            Object value = null;
            ValidationMsgType claimType = null;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key, "Test setup failure", claimTypeFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_SPECIFIC_CLAIM_API() {
        try {
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.SPECIFIC_CLAIM_API;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key, key + ".*" + value.toString(), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_SPECIFIC_CLAIM_API_nulls() {
        try {
            String key = null;
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.SPECIFIC_CLAIM_API;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key, key + ".*" + value, genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_CLAIM_LIST_MEMBER_value_null() {
        try {
            String key = "key";
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.CLAIM_LIST_MEMBER;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonClaimStringFromNull("", key), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_CLAIM_LIST_MEMBER_value_neg1() {
        try {
            String key = "key";
            Object value = "-1";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_LIST_MEMBER;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonClaimStringFromNeg1("", key), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_CLAIM_LIST_MEMBER_value_String() {
        try {
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_LIST_MEMBER;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key,
                                    buildJsonClaimStringFromString("", key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_CLAIM_FROM_LIST_value_null() {
        try {
            String key = "key";
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString("", JwtConstants.JWT_JSON + JwtConstants.JWT_GETALLCLAIMS, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_CLAIM_FROM_LIST_value_neg1() {
        try {
            String key = "key";
            Object value = "-1";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString("", JwtConstants.JWT_JSON + JwtConstants.JWT_GETALLCLAIMS, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_CLAIM_FROM_LIST_value_String() {
        try {
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key,
                                    buildJsonAllClaimString("", JwtConstants.JWT_JSON + JwtConstants.JWT_GETALLCLAIMS, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_HEADER_CLAIM_FROM_LIST_value_null() {
        try {
            String key = "key";
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.HEADER_CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString("", JwtConstants.JWT_TOKEN_HEADER_JSON, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_HEADER_CLAIM_FROM_LIST_value_neg1() {
        try {
            String key = "key";
            Object value = "-1";
            ValidationMsgType claimType = ValidationMsgType.HEADER_CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString("", JwtConstants.JWT_TOKEN_HEADER_JSON, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_3_Args_Object_claimType_HEADER_CLAIM_FROM_LIST_value_String() {
        try {
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.HEADER_CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key,
                                    buildJsonAllClaimString("", JwtConstants.JWT_TOKEN_HEADER_JSON, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_nullArgs() {
        try {
            String prefix = null;
            String key = null;
            Object value = null;
            ValidationMsgType claimType = null;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, null, "Test setup failure", claimTypeFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_SPECIFIC_CLAIM_API() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.SPECIFIC_CLAIM_API;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key, prefix + key + ".*" + value.toString(), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_SPECIFIC_CLAIM_API_nulls() {
        try {
            String prefix = "prefix";
            String key = null;
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.SPECIFIC_CLAIM_API;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key, prefix + key + ".*" + value, genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_CLAIM_LIST_MEMBER_value_null() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.CLAIM_LIST_MEMBER;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonClaimStringFromNull(prefix, key), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_CLAIM_LIST_MEMBER_value_neg1() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = "-1";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_LIST_MEMBER;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonClaimStringFromNeg1(prefix, key), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_CLAIM_LIST_MEMBER_value_String() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_LIST_MEMBER;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key,
                                    buildJsonClaimStringFromString(prefix, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_CLAIM_FROM_LIST_value_null() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString(prefix, JwtConstants.JWT_JSON + JwtConstants.JWT_GETALLCLAIMS, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_CLAIM_FROM_LIST_value_neg1() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = "-1";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString(prefix, JwtConstants.JWT_JSON + JwtConstants.JWT_GETALLCLAIMS, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_CLAIM_FROM_LIST_value_String() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key,
                                    buildJsonAllClaimString(prefix, JwtConstants.JWT_JSON + JwtConstants.JWT_GETALLCLAIMS, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_HEADER_CLAIM_FROM_LIST_value_null() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = null;
            ValidationMsgType claimType = ValidationMsgType.HEADER_CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString(prefix, JwtConstants.JWT_TOKEN_HEADER_JSON, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_HEADER_CLAIM_FROM_LIST_value_neg1() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = "-1";
            ValidationMsgType claimType = ValidationMsgType.HEADER_CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_DOES_NOT_MATCH, key,
                                    buildJsonAllClaimString(prefix, JwtConstants.JWT_TOKEN_HEADER_JSON, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_4_Args_claimType_HEADER_CLAIM_FROM_LIST_value_String() {
        try {
            String prefix = "prefix";
            String key = "key";
            Object value = "value";
            ValidationMsgType claimType = ValidationMsgType.HEADER_CLAIM_FROM_LIST;

            JwtApiExpectation exp = new JwtApiExpectation(prefix, key, value, claimType);

            verifyExpectationValues(exp, null, JwtConstants.RESPONSE_FULL, JwtConstants.STRING_MATCHES, key,
                                    buildJsonAllClaimString(prefix, JwtConstants.JWT_TOKEN_HEADER_JSON, key, value), genericFailureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_6_nullArgs() {
        try {
            String testAction = null;
            String searchLocation = null;
            String checkType = null;
            String searchKey = null;
            String searchFor = null;
            String failureMsg = null;

            JwtApiExpectation exp = new JwtApiExpectation(testAction, searchLocation, checkType, searchKey, searchFor, failureMsg);

            verifyExpectationValues(exp, testAction, searchLocation, checkType, null, searchFor, failureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_6_Args() {
        try {
            String testAction = "testAction";
            String searchLocation = "searchLocation";
            String checkType = "checkType";
            String searchKey = "searchKey";
            String searchFor = "searchFor";
            String failureMsg = "failureMsg";

            JwtApiExpectation exp = new JwtApiExpectation(testAction, searchLocation, checkType, searchKey, searchFor, failureMsg);

            verifyExpectationValues(exp, testAction, searchLocation, checkType, searchKey, searchFor, failureMsg);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    /**************************************** Test Helper methods ******************************/

    @Test
    public void test_buildClaimApiString_nullArgs() {
        try {
            String prefix = null;
            String keyLogName = null;
            String value = null;

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildClaimApiString(prefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildClaimApiString(prefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildClaimApiString_Args_value_String() {
        try {
            String prefix = "prefix";
            String keyLogName = "keyLogName";
            String value = "value";

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildClaimApiString(prefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildClaimApiString(prefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildClaimApiString_Args_value_NumericDate() {
        try {
            String prefix = "prefix";
            String keyLogName = "keyLogName";
            NumericDate value = NumericDate.now();

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildClaimApiString(prefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildClaimApiString(prefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonClaimString_nullArgs() {
        try {
            String prefix = null;
            String keyLogName = null;
            Object value = null;

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonClaimString(prefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonClaimStringFromNull(prefix, keyLogName), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonClaimString_Args_value_neg1() {
        try {
            String prefix = "prefix";
            String keyLogName = "keyLogName";
            Object value = "-1";

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonClaimString(prefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonClaimStringFromNeg1(prefix, keyLogName), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonClaimString_Args_value_String() {
        try {
            String prefix = "prefix";
            String keyLogName = "keyLogName";
            String value = "value";

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonClaimString(prefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonClaimStringFromString(prefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonClaimString_Args_value_NumericDate() {
        try {
            String prefix = "prefix";
            String keyLogName = "keyLogName";
            NumericDate value = NumericDate.now();

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonClaimString(prefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonClaimStringFromString(prefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonAllClaimString_nullArgs() {
        try {
            String prefix = null;
            String subPrefix = null;
            String keyLogName = null;
            Object value = null;

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonAllClaimString(prefix, subPrefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonAllClaimStringFromString(prefix, subPrefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonAllClaimString_Args_value_neg1() {
        try {
            String prefix = "prefix";
            String subPrefix = "subPrefix";
            String keyLogName = "keyLogName";
            Object value = "-1";

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonAllClaimString(prefix, subPrefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonAllClaimStringFromString(prefix, subPrefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonAllClaimString_Args_value_String() {
        try {
            String prefix = "prefix";
            String subPrefix = "subPrefix";
            String keyLogName = "keyLogName";
            String value = "value";

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonAllClaimString(prefix, subPrefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonAllClaimStringFromString(prefix, subPrefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_buildJsonAllClaimString_Args_value_NumericDate() {
        try {
            String prefix = "prefix";
            String subPrefix = "subPrefix";
            String keyLogName = "keyLogName";
            NumericDate value = NumericDate.now();

            JwtApiExpectation exp = new JwtApiExpectation(keyLogName, value, ValidationMsgType.SPECIFIC_CLAIM_API);
            String builtApiString = exp.buildJsonAllClaimString(prefix, subPrefix, keyLogName, value);

            assertEquals("Failure message did not match expected value.", buildJsonAllClaimStringFromString(prefix, subPrefix, keyLogName, value), builtApiString);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    /************************************** Helper methods **************************************/

    private String buildErrorMsg(String insert) {

        return "Response did not show the expected " + insert + " failure.";
    }

    private String buildErrorSearch(String configId, String errorId) {

        return "CWWKS6031E.+" + configId + ".+" + errorId;
    }

    public String buildJsonAllClaimString(String prefix, String subPrefix, String key, Object value) {

        String builtString = null;
        builtString = prefix + subPrefix + ".*" + key + ".*" + value;

        return builtString;
    }

    private String buildJsonClaimStringFromString(String prefix, String key, Object value) {
        String newValue = value.toString().replace("[", "").replace("]", "");

        return prefix + JwtConstants.JWT_JSON + "\\{" + ".*" + key + ".*" + newValue + ".*\\}";
    }

    private String buildJsonClaimStringFromNull(String prefix, String key) {

        return prefix + JwtConstants.JWT_JSON + "\\{" + ".*" + key + ".*" + ":" + ".*null" + ".*\\}";
    }

    private String buildJsonClaimStringFromNeg1(String prefix, String key) {

        return prefix + JwtConstants.JWT_JSON + "\\{" + ".*" + key + ".*" + ":" + ".*\\}";
    }

    private String buildClaimApiString(String prefix, String key, Object value) {

        return prefix + key + ".*" + value;
    }

    private String buildJsonAllClaimStringFromString(String prefix, String subPrefix, String key, Object value) {

        return prefix + subPrefix + ".*" + key + ".*" + value;
    }

}