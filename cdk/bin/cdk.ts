#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { DataPerimeterStack } from '../lib/data-perimeter-stack';

const app = new cdk.App();
new DataPerimeterStack(app, 'DataPerimeterStack', {
  env: { account: '123456789012', region: 'us-east-1' },
});
