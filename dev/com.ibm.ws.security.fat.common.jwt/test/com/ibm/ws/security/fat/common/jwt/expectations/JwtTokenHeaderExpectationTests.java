package com.ibm.ws.security.fat.common.jwt.expectations;

import static org.junit.Assert.fail;

import javax.json.JsonValue.ValueType;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.ws.security.fat.common.Constants.CheckType;
import com.ibm.ws.security.fat.common.Constants.JsonCheckType;
import com.ibm.ws.security.fat.common.Constants.ObjectCheckType;
import com.ibm.ws.security.fat.common.Constants.StringCheckType;
import com.ibm.ws.security.fat.common.jwt.utils.JwtTokenBuilderUtils;
import com.ibm.ws.security.fat.common.logging.CommonFatLoggingUtils;

import test.common.SharedOutputManager;

public class JwtTokenHeaderExpectationTests extends JwtTokenHeaderExpectationTestHelperClass {

    CommonFatLoggingUtils utils = new CommonFatLoggingUtils();
    public static final JwtTokenBuilderUtils jwtTokenBuilderUtils = new JwtTokenBuilderUtils();

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

    //null tests
    @Test
    public void test_constructor_allNull_key() {
        try {

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(null);

            verifyHeaderJsonObjectExpectationValues(exp, null, null, JsonCheckType.KEY_EXISTS, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_allNull_key_checkType_value() {
        try {
            Object value = null;
            CheckType checkType = null;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(null, checkType, value);

            verifyHeaderJsonObjectExpectationValues(exp, null, null, checkType, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_allNull_key_valueType() {
        try {
            ValueType valueType = ValueType.NULL;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(null, valueType);

            verifyHeaderJsonObjectExpectationValues(exp, null, valueType, JsonCheckType.VALUE_TYPE, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_allNull_key_valueType_value() {
        try {
            Object value = null;
            ValueType valueType = ValueType.NULL;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(null, valueType, value);

            verifyHeaderJsonObjectExpectationValues(exp, null, valueType, ObjectCheckType.EQUALS, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key() {
        try {
            String searchKey = SEARCH_KEY;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, null, JsonCheckType.KEY_EXISTS, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_checkTypeKeyExists_value() {
        try {
            String searchKey = SEARCH_KEY;
            CheckType checkType = JsonCheckType.KEY_EXISTS;
            Object value = 123L;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, checkType, value);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, null, checkType, null, value, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_checkTypeKeyDoesNotExist_value() {
        try {
            String searchKey = SEARCH_KEY;
            CheckType checkType = JsonCheckType.KEY_DOES_NOT_EXIST;
            Object value = 123L;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, checkType, value);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, null, checkType, null, value, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_checkTypeValueType_value() {
        try {
            String searchKey = SEARCH_KEY;
            CheckType checkType = JsonCheckType.VALUE_TYPE;
            Object value = 123L;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, checkType, value);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, null, checkType, null, value, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_checkType_valueObject() {
        try {
            String searchKey = SEARCH_KEY;
            CheckType checkType = JsonCheckType.KEY_EXISTS;
            Object value = 123L;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, checkType, value);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, null, checkType, null, value, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_checkType_valueString() {
        try {
            String searchKey = SEARCH_KEY;
            CheckType checkType = JsonCheckType.KEY_EXISTS;
            String value = "someValue";

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, checkType, value);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, null, checkType, null, value, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueTypeArray() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.ARRAY;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, JsonCheckType.VALUE_TYPE, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueTypeString() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.STRING;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, JsonCheckType.VALUE_TYPE, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueTypeFalse() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.FALSE;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, JsonCheckType.VALUE_TYPE, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueTypeNumber() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.NUMBER;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, JsonCheckType.VALUE_TYPE, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueTypeObject() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.OBJECT;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, JsonCheckType.VALUE_TYPE, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueTypeTrue() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.TRUE;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, JsonCheckType.VALUE_TYPE, null, null, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueType_valueObject() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.STRING;
            Object value = 123L;

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType, value);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, StringCheckType.EQUALS, null, value, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_constructor_key_valueType_valueString() {
        try {
            String searchKey = SEARCH_KEY;
            ValueType valueType = ValueType.STRING;
            Object value = "someValue";

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType, value);

            verifyHeaderJsonObjectExpectationValues(exp, searchKey, valueType, StringCheckType.EQUALS, null, value, JwtTokenHeaderExpectation.DEFAULT_FAILURE_MSG);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    /******************************** Validation *******************************************/

    // the tests in JsonObjectExpectations validate the "validate" method.  We'll run one test with the validate method for each type of input
    // and focus on testing the overridden readJsonFromContent method
//    @Test
//    public void test_validate_expectFalseType_succeeds() {
//        try {
//            JsonObjectExpectation exp = new JsonObjectExpectation(SEARCH_KEY, ValueType.FALSE);
//            String content = createContentJsonString(SEARCH_KEY, false);
//            exp.validate(content);
//        } catch (Throwable t) {
//            outputMgr.failWithThrowable(testName.getMethodName(), t);
//        }
//    }
// header object contents of differnt type

    @Test
    public void test_validate_nullJwt() {
        try {
            String searchKey = "kid";
            ValueType valueType = ValueType.STRING;
            Object value = "keyid";

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType, value);

            try {
                exp.validate(null);
                fail("Should have thrown an error validating the JSON data but did not.");
            } catch (Throwable e) {
                verifyException(e, exp.getFailureMsg() + ".*java.lang.IllegalStateException: Improperly formatted JWT Token - wrong number of parts.*");
            }
        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_validate_nonJwt() {
        try {
            String searchKey = "kid";
            ValueType valueType = ValueType.STRING;
            Object value = "keyid";

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType, value);
            String jsonString = "123456789 987654321";

            try {
                exp.validate(jsonString);
                fail("Should have thrown an error validating the JSON data but did not.");
            } catch (Throwable e) {
                verifyException(e, exp.getFailureMsg() + ".*java.lang.IllegalStateException: Improperly formatted JWT Token - wrong number of parts.*");
            }
        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    @Test
    public void test_validate_checkTypeDoesNotContain_passes() {
        try {
            String searchKey = "kid";
            ValueType valueType = ValueType.STRING;
            Object value = "keyid";

            JwtTokenHeaderExpectation exp = new JwtTokenHeaderExpectation(searchKey, valueType, value);
            String jsonString = jwtTokenBuilderUtils.buildToken(jwtTokenBuilderUtils.createBuilderWithDefaultClaims(), testName.getMethodName());

            exp.validate(jsonString);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(testName.getMethodName(), t);
        }
    }

    /**************************************** Test Helper methods ******************************/

    /************************************** Helper methods **************************************/

}