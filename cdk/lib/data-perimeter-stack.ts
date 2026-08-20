import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';

export class DataPerimeterStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Production Workload S3 Bucket
    const bucket = new s3.Bucket(this, 'ProdWorkloadBucket', {
      bucketName: 'prod-workload-data-example',
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Lambda Execution Role for Data Processing
    const dataProcessorRole = new iam.Role(this, 'DataProcessorRole', {
      roleName: 'DataProcessorRole',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });

    // VENDOR EXPORT PR SCENARIO:
    // s3:PutObject targeting approved vendor bucket arn:aws:s3:::approved-vendor-analytics/*
    // (Matches Exception ID EXC-2026-04 in policies/exception_manifest.json)
    dataProcessorRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'VendorAnalyticsExportGrant',
        effect: iam.Effect.ALLOW,
        actions: ['s3:PutObject'],
        resources: ['arn:aws:s3:::approved-vendor-analytics/*'],
      })
    );

    // Dummy Lambda Function
    new lambda.Function(this, 'DataProcessorFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => { return "ok"; };'),
      role: dataProcessorRole,
    });
  }
}
