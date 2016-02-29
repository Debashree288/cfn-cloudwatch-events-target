
var AWS = require('aws-sdk');
var CfnLambda = require('cfn-lambda');

var CWE = new AWS.CloudWatchEvents({apiVersion: '2014-02-03'});

exports.handler = CfnLambda({
  Create: Create,
  Update: Update,
  Delete: Delete,
  TriggersReplacement: ['RuleArn'],
  SchemaPath: [__dirname, 'schema.json']
});

function Create(params, reply) {
  console.log('Received Create, proceed with Upsert: %j', params);
  Upsert(params, reply);
}

function Update(physicalId, params, oldParams, reply) {
  params.RuleTargetId = physicalId;
  console.log('Received Update with same RuleArn, proceed with Upsert: %j', params);
  Upsert(params, reply);
}

function Delete(physicalId, params, reply) {
  console.log('Received Delete: of Id (%s) %j', physicalId, params);
  var payload = {
    Ids: [
      physicalId
    ],
    Rule: ruleNameFromArn(params.RuleArn)
  };
  console.log('About to removeTargets');
  CWE.removeTargets(payload, function(err, data) {
    if (err) {
      console.error('Something went wrong during removeTargets using %j: ', payload);
      console.error('%j', err);
      return reply(err.message || 'UNKNOWN FATAL ERROR');
    }
    if (!data || data.FailedEntryCount) {
      console.error('Something went wrong during removeTargets using %j: ', payload);
      console.error('%j', (data && data.FailedEntries &&
        data.FailedEntries[0]) || { ErrorMessage: 'UNKNOWN FATAL ERROR' });
      return reply((data && data.FailedEntries && 
        data.FailedEntries[0] && data.FailedEntries[0].ErrorMessage) ||
        'UNKNOWN FATAL ERROR');
    }
    console.log('Finished removeTargets using: %j', payload);
    reply(null, physicalId);
  });
}

function ruleNameFromArn(ruleArn) {
  return (ruleArn.match(/([\.\-\w]+)$/) || [])[1] || '';
}

function Upsert(params, reply) {
  params.RuleTargetId = params.RuleTargetId || Date.now().toString();
  var payload = {
    Rule: ruleNameFromArn(params.RuleArn),
    Targets: [
      {
        Arn: params.TargetArn,
        Id: params.RuleTargetId,
        Input: params.Input,
        InputPath: params.InputPath
      }
    ]
  };
  console.log('About to putTargets: %j', payload);
  CWE.putTargets(payload, function(err, data) {
    if (err) {
      console.error('Something went wrong during putTargets using: %j', payload);
      console.error('%j', err);
      return reply(err.message || 'UNKNOWN FATAL ERROR');
    }
    if (!data || data.FailedEntryCount) {
      console.error('Something went wrong during putTargets using: %j', payload);
      console.error('%j', (data && data.FailedEntries &&
        data.FailedEntries[0]) || {ErrorMessage: 'UNKNOWN FATAL ERROR'});
      return reply((data && data.FailedEntries && 
        data.FailedEntries[0] && data.FailedEntries[0].ErrorMessage) ||
        'UNKNOWN FATAL ERROR');
    }
    console.log('Finished putTargets using: %j', payload);
    reply(null, params.RuleTargetId);
  });
}
