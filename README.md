# aws-config-custom-rule
AWS Config custom rule using Node.js for the Lambda function.

# Rule Description
The rule check whether ingress on a specified tcp port is being blocked. If the port is open, the evaulation is noncompliant.

# CloudFormation
A CloudFormation template is included to setup the permissions and services required to quickly test the rule in an environment with a noncompliant security group. 
