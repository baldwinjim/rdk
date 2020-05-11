# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import json
import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::CloudFront::Distribution'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
SQS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'cloudfront':
            return SQS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('SQS_Required_Tags')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def setUp(self):
        pass

    def test_sample(self):
        self.assertTrue(True)

# "RequiredTags":"Environment,Owner,Compliance,Notify,DataClassification,DRTier"

class Scenario1_TagsExist(unittest.TestCase):

    def test_Scenario_1_tags_exist_and_populated(self):
        # tags_list = list of tags to evaluate
        tags_list = {"Environment":"dev","Owner":"test","Compliance":"test","Notify":"test","DataClassification":"low","DRTier":"test","JunkTag":"SomeExtra"}

        ruleParam = '{"RequiredTags":"Environment,Owner,Compliance,Notify,DataClassification,DRTier"}'
        invokingEvent = build_invoking_event("ResouceDiscovered",tags_list)
        lambda_event = build_lambda_configurationchange_event(invoking_event=invokingEvent,rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT','E31V0VAAPINP3I'))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_Scenario_2_tags_present_but_not_populated(self):
        # tags_list = list of tags to evaluate. Removing values from tags
        # Notify and DRTier values set to empty string
        tags_list = {"Environment":"dev","Owner":"test","Compliance":"test","Notify":"","DataClassification":"low","DRTier":""}

        ruleParam = '{"RequiredTags":"Environment,Owner,Compliance,Notify,DataClassification,DRTier"}'
        invokingEvent = build_invoking_event("ResouceDiscovered",tags_list)
        lambda_event = build_lambda_configurationchange_event(invoking_event=invokingEvent,rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT','E31V0VAAPINP3I',annotation="all tags present but not all populated"))
        assert_successful_evaluation(self, response, resp_expected, 1)

class Scenario_2_TagsDoNotExist(unittest.TestCase):

    def test_Scenario_3_missing_tags(self):
        # tags_list = list of tags to evaluate. 
        # Removing 1 tag for test
        tags_list = {"Environment":"dev","Owner":"test","Compliance":"test","Notify":"test","DataClassification":"low"}

        ruleParam = '{"RequiredTags":"Environment,Owner,Compliance,Notify,DataClassification,DRTier"}'
        invokingEvent = build_invoking_event("ResouceDiscovered",tags_list)
        lambda_event = build_lambda_configurationchange_event(invoking_event=invokingEvent,rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT','E31V0VAAPINP3I',annotation="missing tags"))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_Scenario_4_mispelled_tags(self):
        # tags_list = list of tags to evaluate. 
        # Mispelling a tag. Should return NON_COMPLIANT
        tags_list = {"Environment":"dev","Owner":"test","Compliance":"test","Notify":"test","DarraClassification":"low","DRTier":"test"}

        ruleParam = '{"RequiredTags":"Environment,Owner,Compliance,Notify,DataClassification,DRTier"}'
        invokingEvent = build_invoking_event("ResouceDiscovered",tags_list)
        lambda_event = build_lambda_configurationchange_event(invoking_event=invokingEvent,rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT','E31V0VAAPINP3I',annotation="missing tags"))
        assert_successful_evaluation(self, response, resp_expected, 1)


####################
# Helper Functions #
####################

def build_invoking_event(configurationItemStatus, test_tags):

    return json.dumps({
        "configurationItemDiff":"SomeDifference",
        "notificationCreationTime":"SomeTime",
        "messageType":"ConfigurationItemChangeNotification",
        "recordVersion":"SomeVersion",
        "configurationItem":{
            "configurationItemVersion": "1.3",
            "configurationItemCaptureTime": "2019-02-12T02:27:33.663Z",
            "configurationStateId": 1549938453663,
            "awsAccountId": "12345678912",
            "configurationItemStatus": "ResourceDiscovered",
            "resourceType": "AWS::CloudFront::Distribution",
            "resourceId": "E31V0VAAPINP3I",
            "resourceName": "test",
            "ARN": "arn:aws:cloudfront::12345678912:distribution/E31V0VAAPINP3I",
            "awsRegion": "global",
            "availabilityZone": "Not Applicable",
            "configurationStateMd5Hash": "",
            "resourceCreationTime": "2019-02-12T02:27:31.988Z",
            "tags": test_tags
        }
    })

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    if not annotation:
        return {
            'ComplianceType': compliance_type,
            'ComplianceResourceId': compliance_resource_id,
            'ComplianceResourceType': compliance_resource_type
            }
    return {
        'ComplianceType': compliance_type,
        'ComplianceResourceId': compliance_resource_id,
        'ComplianceResourceType': compliance_resource_type,
        'Annotation': annotation
        }

def assert_successful_evaluation(test_class, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        test_class.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(test_class, response, customer_error_code=None, customer_error_message=None):
    if customer_error_code:
        test_class.assertEqual(customer_error_code, response['customerErrorCode'])
    if customer_error_message:
        test_class.assertEqual(customer_error_message, response['customerErrorMessage'])
    test_class.assertTrue(response['customerErrorCode'])
    test_class.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        test_class.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        test_class.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
