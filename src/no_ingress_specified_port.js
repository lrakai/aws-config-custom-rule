//
// Ensure a security group does not allow tcp ingress on a specified port
//

var aws = require('aws-sdk');
var config = new aws.ConfigService();

// Helper function used to validate input
function checkDefined(reference, referenceName) {
    if (!reference) {
        console.log("Error: " + referenceName + " is not defined");
        throw referenceName;
    }
    return reference;
}

// Check whether the the resource has been deleted. If it has, then the evaluation is unnecessary.
function isApplicable(configurationItem, event) {
    checkDefined(configurationItem, "configurationItem");
    checkDefined(event, "event");
    var status = configurationItem.configurationItemStatus;
    var eventLeftScope = event.eventLeftScope;
    return ('OK' === status || 'ResourceDiscovered' === status) && false === eventLeftScope;
}

function createPutEvaluationsRequest(event, configurationItem, compliance) {
    var putEvaluationsRequest = {};

    // Put together the request that reports the evaluation status
    putEvaluationsRequest.Evaluations = [
        {
            ComplianceResourceType: configurationItem.resourceType,
            ComplianceResourceId: configurationItem.resourceId,
            ComplianceType: compliance,
            OrderingTimestamp: configurationItem.configurationItemCaptureTime
        }
    ];
    putEvaluationsRequest.ResultToken = event.resultToken;
    putEvaluationsRequest.TestMode = true;

    return putEvaluationsRequest;
}

function putEvaluations(context, putEvaluationsRequest) {
    // Invoke the Config API to report the result of the evaluation
    config.putEvaluations(putEvaluationsRequest, function (err, data) {
        if (err) {
            context.fail(err);
        } else {
            context.succeed(data);
        }
    });
}

// This is the handler that's invoked by Lambda
exports.handler = function (event, context) {
    event = checkDefined(event, "event");
    var invokingEvent = JSON.parse(event.invokingEvent);
    var ruleParameters = JSON.parse(event.ruleParameters);
    var configurationItem = checkDefined(invokingEvent.configurationItem, "invokingEvent.configurationItem");
    var compliance = 'NOT_APPLICABLE';
    var putEvaluationsRequest = {};

    checkDefined(configurationItem, "configurationItem");
    checkDefined(configurationItem.configuration, "configurationItem.configuration");
    checkDefined(ruleParameters, "ruleParameters");

    if (isApplicable(invokingEvent.configurationItem, event)) {
        // Invoke the compliance checking function.
        compliance = evaluateCompliance(invokingEvent.configurationItem, context);

        // This is where it's determined whether the resource is compliant or not.
        // In this example, we look at the ip permissions of the EC2 security group and determine
        // if it allows ingress traffic on a specified tcp Port. If the Port is open, the 
        // security group is marked non-compliant. Otherwise, it is marked complaint. 
        if ('AWS::EC2::SecurityGroup' !== configurationItem.resourceType) {
            return 'NOT_APPLICABLE';
        }

        groupId = configuration_item["configuration"]["groupId"];

        var ec2 = aws.EC2({ apiVersion: '2016-11-15' });
        var params = {
            DryRun: false,
            GroupIds: [
                groupId
            ]
        };
        ec2.describeSecurityGroups(params, function (err, data) {
            var compliance = 'COMPLIANT';
            if (err) {
                compliance = 'NON_COMPLIANT';
            } else {
                var IpPermissions = data.SecurityGroups[0].IpPermissions;
                for (var i = 0; i < ipPermissions.length; i++) {
                    var ipPermission = ipPermissions[i];
                    // The actual test condition
                    if (ipPermission.IpProtocol === 'tcp'
                        && ipPermission.FromPort >= ruleParameters.port
                        && ipPermission.ToPort <= ruleParameters.port) {
                        compliance = 'NON_COMPLIANT';
                        break;
                    }
                }
            }
            putEvaluationsRequest = createPutEvaluationsRequest(event, configurationItem, compliance);
            putEvaluations(context, putEvaluations);
        });
    } else {
        putEvaluationsRequest = createPutEvaluationsRequest(event, configurationItem, compliance);
        putEvaluations(context, putEvaluations);
    }
};