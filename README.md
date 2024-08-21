# AWS Lambda Deployment using Amazon ECR

This README provides instructions for deploying an AWS Lambda function using Amazon Elastic Container Registry (ECR). This method allows you to use custom runtime environments and larger deployment packages for your Lambda functions.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deployment Steps](#deployment-steps)
3. [Troubleshooting](#troubleshooting)
4. [Best Practices](#best-practices)
5. [Additional Resources](#additional-resources)

## Prerequisites

Before you begin, ensure you have the following:

- AWS CLI installed and configured with appropriate permissions
- Docker installed on your local machine
- Your Lambda function code ready in a local directory
- An Amazon ECR repository created (in this case: `aws-all-inventory`)
- An existing Lambda function (in this case: `v2-aws-all-inventory`)

## Deployment Steps

Follow these steps to deploy your Lambda function:

1. **Authenticate Docker to your Amazon ECR registry**

   ```bash
   aws ecr get-login-password --region ap-south-1 | docker login --username AWS --password-stdin 809555764832.dkr.ecr.ap-south-1.amazonaws.com
   ```

2. **Build your Docker image**

   Navigate to the directory containing your Dockerfile and run:

   ```bash
   docker build -t aws-all-inventory .
   ```

3. **Tag the image**

   ```bash
   docker tag aws-all-inventory:latest 809555764832.dkr.ecr.ap-south-1.amazonaws.com/aws-all-inventory:latest
   ```

4. **Push the image to Amazon ECR**

   ```bash
   docker push 809555764832.dkr.ecr.ap-south-1.amazonaws.com/aws-all-inventory:latest
   ```

5. **Update the Lambda function**

   ```bash
   aws lambda update-function-code \
       --function-name v2-aws-all-inventory \
       --image-uri 809555764832.dkr.ecr.ap-south-1.amazonaws.com/aws-all-inventory:latest \
       --region ap-south-1
   ```

6. **Verify the update**

   ```bash
   aws lambda get-function \
       --function-name v2-aws-all-inventory \
       --region ap-south-1
   ```

## Troubleshooting

- If you encounter permissions issues, ensure your AWS CLI is configured with the correct credentials and that these credentials have the necessary permissions for ECR and Lambda operations.
- If the Lambda function fails to update, check that the ECR image was pushed successfully and that the Lambda function has permission to access the ECR repository.
- For timeout issues during deployment, consider increasing the CLI timeout setting or checking your network connection.

## Best Practices

1. **Version Control**: Use tags for your Docker images to manage different versions of your Lambda function.
2. **Security**: Regularly update base images and dependencies to patch security vulnerabilities.
3. **Testing**: Always test your Lambda function in a non-production environment before deploying to production.
4. **Monitoring**: Set up CloudWatch alarms to monitor the performance and errors of your Lambda function.
5. **Cost Optimization**: Regularly review and optimize the resources allocated to your Lambda function.

## Additional Resources

- [AWS Lambda Developer Guide](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)
- [Amazon ECR User Guide](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html)
- [AWS CLI Command Reference](https://docs.aws.amazon.com/cli/latest/reference/)
