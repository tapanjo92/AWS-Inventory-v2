import boto3
import logging
import xlsxwriter
from datetime import datetime, timezone, timedelta
from io import BytesIO


logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info("Getting the identity of the caller to debug permissions...")
    sts_client = boto3.client('sts')
    identity = sts_client.get_caller_identity()
    logger.info(f"Caller Identity: {identity}")

def lambda_handler(event, context):
    sts_client = boto3.client('sts')
    s3_client = boto3.client('s3')
    sns_client = boto3.client('sns')

    accounts_info = [
        {'arn': None, 'name': 'CPaasS Dev', 'regions': ['ap-south-1', 'us-east-1']},
        {'arn': 'arn:aws:iam::846359169444:role/IN-Cross-Account-Inventory-Role-Axiom-Account', 'name': 'Axion Account', 'regions': ['ap-south-1']},
        {'arn': 'arn:aws:iam::832798019953:role/IN-Cross-Account-Inventory-Role-Shared-Account', 'name': 'Shared Account', 'regions': ['ap-south-1']},
        {'arn': 'arn:aws:iam::132370722109:role/IN-Cross-Account-Inventory-Role-MMX-Account', 'name': 'MMX Account', 'regions': ['ap-south-1', 'us-west-2']},
        {'arn': 'arn:aws:iam::435804161212:role/IN-Cross-Account-Inventory-Role-Kong-Api-Account', 'name': 'Kong Api Account', 'regions': ['ap-south-1','us-west-2']},
        {'arn': 'arn:aws:iam::839039565438:role/IN-Cross-Account-Inventory-Role-VISITIZE', 'name': 'VISITIZE Account', 'regions': ['ap-south-1']},
        {'arn': 'arn:aws:iam::222660732975:role/IN-Cross-Account-Inventory-Role-OL-Prod-Account', 'name': 'OL Account', 'regions': ['ap-south-1']},
        {'arn': 'arn:aws:iam::832798019953:role/IN-Cross-Account-Inventory-Role-Shared-Core-Account', 'name': 'Shared Core', 'regions': ['ap-south-1']},
        {'arn': 'arn:aws:iam::389812040165:role/IN-Cross-Account-Inventory-Role-CCS-AWS-GlobalRapid', 'name': 'Global Rapid Account', 'regions': ['ap-south-1']},
        {'arn': 'arn:aws:iam::381492018207:role/IN-Cross-Account-Inventory-Role-Engage-Account', 'name': 'Engage - Digo', 'regions': ['ap-south-1']},
        {'arn':'arn:aws:iam::992382722583:role/IN-Cross-Account-Inventory-Role-N8N-Account', 'name': 'N8N Account', 'regions': ['ap-south-1']},

    ]

    datestamp = datetime.now().strftime('%Y-%m-%d')
    filename = f'ec2-inventory-{datestamp}.xlsx'
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {'remove_timezone': True})

    for account in accounts_info:
        role_arn = account['arn']
        account_regions = account['regions']

        if role_arn:
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='CrossAccountSession'
            )
            credentials = assumed_role['Credentials']

            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
            )
        else:
            session = boto3.Session()


        for region in account_regions:
            ec2_client = session.client('ec2', region_name=region)
            s3_client = session.client('s3')
            instances = ec2_client.describe_instances()
            s3_buckets = s3_client.list_buckets()
            rds_client = session.client('rds', region_name=region)
            eks_client = session.client('eks', region_name=region)
            lambda_client = session.client('lambda', region_name=region)
            elb_client = session.client('elbv2', region_name=region)
            route53_client = session.client('route53', region_name='us-east-1')
            athena_client = session.client('athena', region_name=region)
            glue_client = session.client('glue', region_name=region)
            efs_client = session.client('efs', region_name=region)
            athena_client = session.client('athena', region_name=region)
            sns_client = session.client('sns', region_name=region)
            sqs_client = session.client('sqs', region_name=region)
            cloudfront_client = session.client('cloudfront')
            dynamodb_client = session.client('dynamodb')
            elasticache_client = session.client('elasticache')
            redshift_client = session.client('redshift')
            emr_client = session.client('emr')
            kinesis_client = session.client('kinesis')
            apigateway_client = session.client('apigateway')
            cloudwatch_client = session.client('cloudwatch')

            vpc_data = parse_vpcs(ec2_client)
            subnet_data = parse_subnets(ec2_client)
            igw_data = parse_igws(ec2_client)
            ec2_data = parse_ec2_instances_data(instances, region)
            enis_data = parse_enis_data(ec2_client, region)
            s3_data = parse_s3_data(s3_client, region)
            rds_data = parse_rds_data(session.client('rds', region_name=region), region)
            eks_data = parse_eks_data(session.client('eks', region_name=region), region)
            lambda_data = parse_lambda_data(lambda_client, region)
            elb_data = parse_elb_data(elb_client, region)
            route53_data = parse_route53_data(route53_client)
            tgw_data = parse_tgw_data(ec2_client)
            tgw_attachments_data = parse_tgw_attachments_data(ec2_client)
            athena_data = parse_athena_data(athena_client)
            glue_data = parse_glue_data(glue_client)
            efs_data = parse_efs_data(efs_client)
            sns_data = parse_sns_data(sns_client)
            sqs_data = parse_sqs_data(sqs_client)
            vpc_data = parse_vpcs(ec2_client)
            subnet_data = parse_subnets(ec2_client)
            igw_data = parse_igws(ec2_client)
            sagemaker_data = parse_sagemaker(session.client('sagemaker', region_name=region))
            vpc_endpoints_data = parse_vpc_endpoints(ec2_client)
            cloudfront_data = parse_cloudfront_data(cloudfront_client)
            dynamodb_data = parse_dynamodb_data(dynamodb_client, region)
            elasticache_data = parse_elasticache_data(elasticache_client, region)
            redshift_data = parse_redshift_data(redshift_client, region)
            emr_data = parse_emr_data(emr_client, region)
            kinesis_data = parse_kinesis_data(kinesis_client, region)
            apigateway_data = parse_apigateway_data(apigateway_client, region)
            cloudwatch_data = parse_cloudwatch_data(cloudwatch_client, region)

            worksheet_name = account['name']
            worksheet = workbook.add_worksheet(f"{worksheet_name}_{region}")
            write_data_to_sheet(worksheet, ec2_data, enis_data, s3_data, rds_data, eks_data, lambda_data, elb_data, route53_data, tgw_data, tgw_attachments_data, athena_data, glue_data, efs_data, sns_data, sqs_data, vpc_data, subnet_data, igw_data, vpc_endpoints_data, sagemaker_data, cloudfront_data, dynamodb_data, elasticache_data, redshift_data, emr_data, kinesis_data, apigateway_data, cloudwatch_data, workbook)


    workbook.close()
    output.seek(0)

    bucket_name = 'kongdev-aws-inventory-test'
    s3_client.upload_fileobj(output, bucket_name, filename)

    presigned_url = s3_client.generate_presigned_url('get_object',
                                                     Params={'Bucket': bucket_name, 'Key': filename},
                                                     ExpiresIn=86400)

    return {"message": f"Notification sent with download link for '{filename}'"}

def parse_ec2_instances_data(instances, region):
    data = []
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            instance_type = instance['InstanceType']
            public_ip = instance.get('PublicIpAddress', 'N/A')
            private_ip = instance.get('PrivateIpAddress', 'N/A')
            state = instance['State']['Name']
            launch_time = instance['LaunchTime'].astimezone(timezone(timedelta(hours=5, minutes=30))).strftime('%Y-%m-%d %H:%M:%S')
            instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
            data.append([region, instance_id, instance_name, instance_type, public_ip, private_ip, state, launch_time])
    return data

def parse_enis_data(ec2_client, region):
    enis = ec2_client.describe_network_interfaces()
    data = []
    for eni in enis['NetworkInterfaces']:
        eni_id = eni['NetworkInterfaceId']
        private_ip = eni.get('PrivateIpAddress', 'N/A')
        public_ip = eni.get('Association', {}).get('PublicIp', 'N/A')
        eni_name = next((tag['Value'] for tag in eni.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
        data.append([region, eni_id, eni_name, private_ip, public_ip])
    return data

def parse_s3_data(s3_client, region):
    data = []
    for bucket in s3_client.list_buckets()['Buckets']:
        bucket_name = bucket['Name']
        try:
            # Get bucket location
            location = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
            # If location is None, it's in us-east-1
            bucket_region = location if location else 'us-east-1'
            
            # Only process buckets in the current region
            if bucket_region == region:
                # Get bucket size
                size_bytes = sum(obj['Size'] for obj in s3_client.list_objects_v2(Bucket=bucket_name).get('Contents', []))
                
                # Convert to MB
                size_mb = size_bytes / (1024 ** 2)
                
                # If size is greater than 1024 MB, convert to GB
                if size_mb > 1024:
                    size_gb = size_mb / 1024
                    size_str = f"{size_gb:.2f} GB"
                else:
                    size_str = f"{size_mb:.2f} MB"
                
                data.append([region, bucket_name, size_str])
        except Exception as e:
            logging.error(f"Error processing bucket {bucket_name}: {str(e)}")
            data.append([region, bucket_name, "Error"])
    return data

def parse_rds_data(rds_client, region):
    data = []
    rds_instances = rds_client.describe_db_instances()
    for db_instance in rds_instances['DBInstances']:
        db_identifier = db_instance['DBInstanceIdentifier']
        db_engine = db_instance['Engine']
        db_status = db_instance['DBInstanceStatus']
        db_endpoint = db_instance.get('Endpoint', {}).get('Address', 'N/A')
        
        # Add node count for multi-AZ and Aurora clusters
        if db_instance.get('MultiAZ', False):
            node_count = 2  # Multi-AZ deployments have 2 nodes
        elif 'aurora' in db_engine.lower():
            # For Aurora, we need to get the cluster info
            cluster_id = db_instance.get('DBClusterIdentifier')
            if cluster_id:
                cluster_info = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)
                node_count = len(cluster_info['DBClusters'][0]['DBClusterMembers'])
            else:
                node_count = 1  # Fallback if we can't determine the cluster size
        else:
            node_count = 1  # Single-AZ deployments have 1 node

        data.append([region, db_identifier, db_engine, db_status, db_endpoint, node_count])
    return data

def parse_eks_data(eks_client, region):
    data = []
    eks_clusters = eks_client.list_clusters()
    for cluster_name in eks_clusters['clusters']:
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        cluster_status = cluster_info['cluster']['status']
        
        # Get nodegroup information
        nodegroups = eks_client.list_nodegroups(clusterName=cluster_name)['nodegroups']
        total_nodes = 0
        for nodegroup in nodegroups:
            nodegroup_info = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup)
            total_nodes += nodegroup_info['nodegroup']['scalingConfig']['desiredSize']
        
        data.append([region, cluster_name, cluster_status, total_nodes])
    return data

def parse_lambda_data(lambda_client, region):
    data = []
    paginator = lambda_client.get_paginator('list_functions')
    for response in paginator.paginate():
        for function in response['Functions']:
            function_name = function['FunctionName']
            # Default to 'Unknown' if 'Runtime' or 'Handler' is not present
            runtime = function.get('Runtime', 'Unknown')
            handler = function.get('Handler', 'Unknown')
            last_modified = function['LastModified']
            data.append([region, function_name, runtime, handler, last_modified])
    return data


def parse_elb_data(elb_client, region):
    data = []
    paginator = elb_client.get_paginator('describe_load_balancers')
    for response in paginator.paginate():
        for elb in response['LoadBalancers']:
            elb_name = elb['LoadBalancerName']
            elb_type = elb['Type']
            elb_scheme = elb['Scheme']
            elb_dns_name = elb['DNSName']
            data.append([region, elb_name, elb_type, elb_scheme, elb_dns_name])
    return data

def parse_route53_data(route53_client):
    data = []
    paginator = route53_client.get_paginator('list_hosted_zones')
    for response in paginator.paginate():
        for zone in response['HostedZones']:
            zone_name = zone['Name']
            record_count = zone['ResourceRecordSetCount']
            data.append(['Global', zone_name, record_count])
    return data

def parse_tgw_data(ec2_client):
    data = []
    tgws = ec2_client.describe_transit_gateways()['TransitGateways']
    for tgw in tgws:
        tgw_id = tgw['TransitGatewayId']
        state = tgw['State']
        creation_time = tgw['CreationTime'].strftime('%Y-%m-%d %H:%M:%S')
        data.append(['Global', tgw_id, state, creation_time])
    return data

def parse_tgw_attachments_data(ec2_client):
    data = []
    attachments = ec2_client.describe_transit_gateway_attachments()['TransitGatewayAttachments']
    for attachment in attachments:
        attachment_id = attachment['TransitGatewayAttachmentId']
        tgw_id = attachment['TransitGatewayId']
        resource_type = attachment['ResourceType']
        state = attachment['State']
        data.append(['Global', attachment_id, tgw_id, resource_type, state])
    return data

def parse_athena_data(athena_client):
    data = []
    response = athena_client.list_work_groups()  # Direct API call without paginator
    for workgroup in response['WorkGroups']:
        workgroup_name = workgroup['Name']
        state = workgroup['State']
        data.append(['Global', workgroup_name, state])
    return data


def parse_glue_data(glue_client):
    data = []
    paginator = glue_client.get_paginator('get_databases')
    for response in paginator.paginate():
        for database in response['DatabaseList']:
            db_name = database['Name']
            db_location = database.get('LocationUri', 'N/A')
            data.append(['Global', db_name, db_location])
    return data

def parse_efs_data(efs_client):
    data = []
    file_systems = efs_client.describe_file_systems()['FileSystems']
    for fs in file_systems:
        fs_id = fs['FileSystemId']
        creation_time = fs['CreationTime'].strftime('%Y-%m-%d %H:%M:%S')
        performance_mode = fs['PerformanceMode']
        data.append(['Global', fs_id, creation_time, performance_mode])
    return data

def parse_nat_data(ec2_client):
    data = []
    nat_gateways = ec2_client.describe_nat_gateways()['NatGateways']
    for nat in nat_gateways:
        nat_id = nat['NatGatewayId']
        state = nat['State']
        creation_time = nat['CreateTime'].strftime('%Y-%m-%d %H:%M:%S')
        subnet_id = nat['SubnetId']
        data.append(['Global', nat_id, state, creation_time, subnet_id])
    return data

def parse_sns_data(sns_client):
    data = []
    response = sns_client.list_topics()
    for topic in response['Topics']:
        topic_arn = topic['TopicArn']
        data.append(['Global', topic_arn])
    return data

def parse_sns_data(sns_client):
    data = []
    response = sns_client.list_topics()
    for topic in response['Topics']:
        topic_arn = topic['TopicArn']
        data.append(['Global', topic_arn])
    return data

def parse_sqs_data(sqs_client):
    data = []
    response = sqs_client.list_queues()
    queue_urls = response.get('QueueUrls', [])  # Use get to avoid KeyError
    for url in queue_urls:
        attributes = sqs_client.get_queue_attributes(QueueUrl=url, AttributeNames=['All'])
        queue_name = url.split('/')[-1]
        creation_date = attributes['Attributes']['CreatedTimestamp']
        data.append(['Global', queue_name, creation_date])
    return data

def parse_vpcs(ec2_client):
    data = []
    vpcs = ec2_client.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        vpc_id = vpc['VpcId']
        cidr = vpc['CidrBlock']
        is_default = vpc['IsDefault']
        data.append(['Global', vpc_id, cidr, is_default])
    return data

def parse_subnets(ec2_client):
    data = []
    subnets = ec2_client.describe_subnets()
    for subnet in subnets['Subnets']:
        subnet_id = subnet['SubnetId']
        vpc_id = subnet['VpcId']
        cidr = subnet['CidrBlock']
        availability_zone = subnet['AvailabilityZone']
        data.append(['Global', subnet_id, vpc_id, cidr, availability_zone])
    return data

def parse_igws(ec2_client):
    data = []
    igws = ec2_client.describe_internet_gateways()
    for igw in igws['InternetGateways']:
        igw_id = igw['InternetGatewayId']
        attached_vpcs = [attachment['VpcId'] for attachment in igw['Attachments'] if 'VpcId' in attachment]
        attached_vpcs_str = ', '.join(attached_vpcs) if attached_vpcs else 'Not attached'
        data.append(['Global', igw_id, attached_vpcs_str])
    return data

def parse_vpc_endpoints(ec2_client):
    data = []
    vpc_endpoints = ec2_client.describe_vpc_endpoints()
    for endpoint in vpc_endpoints['VpcEndpoints']:
        endpoint_id = endpoint['VpcEndpointId']
        service_name = endpoint['ServiceName']
        vpc_id = endpoint['VpcId']
        state = endpoint['State']
        data.append(['Global', endpoint_id, service_name, vpc_id, state])
    return data


def parse_sagemaker(sagemaker_client):
    data = []
    notebooks = sagemaker_client.list_notebook_instances()
    for notebook in notebooks['NotebookInstances']:
        notebook_name = notebook['NotebookInstanceName']
        instance_type = notebook['InstanceType']
        creation_time = notebook['CreationTime'].strftime('%Y-%m-%d %H:%M:%S')
        status = notebook['NotebookInstanceStatus']
        data.append(['Global', notebook_name, instance_type, creation_time, status])
    return data

def parse_cloudfront_data(cloudfront_client):
    data = []
    distributions = cloudfront_client.list_distributions()['DistributionList'].get('Items', [])
    for dist in distributions:
        dist_id = dist['Id']
        domain_name = dist['DomainName']
        enabled = dist['Enabled']
        status = dist['Status']
        data.append(['Global', dist_id, domain_name, enabled, status])
    return data

def parse_dynamodb_data(dynamodb_client, region):
    data = []
    tables = dynamodb_client.list_tables()['TableNames']
    for table_name in tables:
        table_info = dynamodb_client.describe_table(TableName=table_name)['Table']
        status = table_info['TableStatus']
        item_count = table_info['ItemCount']
        size_bytes = table_info['TableSizeBytes']
        data.append([region, table_name, status, item_count, size_bytes])
    return data

def parse_elasticache_data(elasticache_client, region):
    data = []
    clusters = elasticache_client.describe_cache_clusters()['CacheClusters']
    for cluster in clusters:
        cluster_id = cluster['CacheClusterId']
        engine = cluster['Engine']
        status = cluster['CacheClusterStatus']
        node_type = cluster['CacheNodeType']
        data.append([region, cluster_id, engine, status, node_type])
    return data

def parse_redshift_data(redshift_client, region):
    data = []
    clusters = redshift_client.describe_clusters()['Clusters']
    for cluster in clusters:
        cluster_id = cluster['ClusterIdentifier']
        status = cluster['ClusterStatus']
        node_type = cluster['NodeType']
        num_nodes = cluster['NumberOfNodes']
        data.append([region, cluster_id, status, node_type, num_nodes])
    return data

def parse_emr_data(emr_client, region):
    data = []
    clusters = emr_client.list_clusters()['Clusters']
    for cluster in clusters:
        cluster_id = cluster['Id']
        name = cluster['Name']
        status = cluster['Status']['State']
        data.append([region, cluster_id, name, status])
    return data

def parse_kinesis_data(kinesis_client, region):
    data = []
    streams = kinesis_client.list_streams()['StreamNames']
    for stream_name in streams:
        stream_info = kinesis_client.describe_stream(StreamName=stream_name)['StreamDescription']
        status = stream_info['StreamStatus']
        shard_count = stream_info['Shards']
        data.append([region, stream_name, status, len(shard_count)])
    return data

def parse_apigateway_data(apigateway_client, region):
    data = []
    apis = apigateway_client.get_rest_apis()['items']
    for api in apis:
        api_id = api['id']
        name = api['name']
        created_date = api['createdDate'].strftime('%Y-%m-%d %H:%M:%S')
        data.append([region, api_id, name, created_date])
    return data

def parse_cloudwatch_data(cloudwatch_client, region):
    data = []
    alarms = cloudwatch_client.describe_alarms()['MetricAlarms']
    for alarm in alarms:
        alarm_name = alarm['AlarmName']
        state = alarm['StateValue']
        metric_name = alarm.get('MetricName', 'N/A')  # Use get() with a default value
        namespace = alarm.get('Namespace', 'N/A')  # Also use get() for Namespace
        data.append([region, alarm_name, state, metric_name, namespace])
    return data

def write_data_to_sheet(worksheet, ec2_data, enis_data, s3_data, rds_data, eks_data, lambda_data, elb_data, route53_data, tgw_data, tgw_attachments_data, athena_data, glue_data, efs_data, sns_data, sqs_data, vpc_data, subnet_data, igw_data, vpc_endpoints, sagemaker_data, cloudfront_data, dynamodb_data, elasticache_data, redshift_data, emr_data, kinesis_data, apigateway_data, cloudwatch_data, workbook):
    bold_light_blue = workbook.add_format({
        'bold': True, 
        'bg_color': '#ADD8E6',
        'border': 1,
        'align': 'center',
        'valign': 'vcenter'
    })
    bold_light_yellow = workbook.add_format({
        'bold': True, 
        'bg_color': '#FFFFE0',
        'border': 1,
        'align': 'center',
        'valign': 'vcenter'
    })
    data_format = workbook.add_format({
        'border': 1,
        'align': 'left',
        'valign': 'vcenter'
    })

    # Function to write a section
    def write_section(title, headers, data):
        nonlocal row_num
        worksheet.merge_range(row_num, 0, row_num, len(headers) - 1, title, bold_light_blue)
        row_num += 1
        for col, header in enumerate(headers):
            worksheet.write(row_num, col, header, bold_light_yellow)
        row_num += 1
        for item in data:
            for col, value in enumerate(item):
                worksheet.write(row_num, col, value, data_format)
            row_num += 1
        row_num += 1  # Add an extra empty row for spacing

    row_num = 0  # Start from row 0

    # EC2 Instances
    write_section('EC2 Instances', 
                  ['Region', 'EC2 Instance ID', 'EC2 Name', 'Type', 'Public IP', 'Private IP', 'State', 'Launch Time'],
                  ec2_data)

    # Elastic Network Interfaces
    write_section('Elastic Network Interfaces',
                  ['Region', 'ENI ID', 'ENI Name', 'Private IP', 'Public IP'],
                  enis_data)

    # S3 Buckets
    write_section('S3 Buckets',
                  ['Region', 'S3 Bucket Name', 'Size'],
                  s3_data)

    write_section('RDS Instances',
                  ['Region', 'DB Instance ID', 'Engine', 'Status', 'Endpoint', 'Node Count'],
                  rds_data)

    write_section('EKS Clusters',
                  ['Region', 'Cluster Name', 'Status', 'Node Count'],
                  eks_data)

    # Lambda Functions
    write_section('Lambda Functions',
                  ['Region', 'Function Name', 'Runtime', 'Handler', 'Last Modified'],
                  lambda_data)

    # Elastic Load Balancers
    write_section('Elastic Load Balancers',
                  ['Region', 'ELB Name', 'Type', 'Scheme', 'DNS Name'],
                  elb_data)

    # Route 53 Hosted Zones
    write_section('Route 53 Hosted Zones',
                  ['Scope', 'Zone Name', 'Record Count'],
                  route53_data)

    # Transit Gateways
    write_section('Transit Gateways',
                  ['Scope', 'TGW ID', 'State', 'Creation Time'],
                  tgw_data)

    # TGW Attachments
    write_section('TGW Attachments',
                  ['Scope', 'Attachment ID', 'TGW ID', 'Resource Type', 'State'],
                  tgw_attachments_data)

    # Athena Workgroups
    write_section('Athena Workgroups',
                  ['Scope', 'Workgroup Name', 'State'],
                  athena_data)

    # AWS Glue Databases
    write_section('AWS Glue Databases',
                  ['Scope', 'Database Name', 'Location URI'],
                  glue_data)

    # EFS File Systems
    write_section('EFS File Systems',
                  ['Scope', 'FileSystem ID', 'Creation Time', 'Performance Mode'],
                  efs_data)

    # SNS Topics
    write_section('SNS Topics',
                  ['Scope', 'Topic ARN'],
                  sns_data)

    # SQS Queues
    write_section('SQS Queues',
                  ['Scope', 'Queue Name', 'Creation Date'],
                  sqs_data)

    # VPCs
    write_section('VPCs',
                  ['Scope', 'VPC ID', 'CIDR', 'Default'],
                  vpc_data)

    # Subnets
    write_section('Subnets',
                  ['Scope', 'Subnet ID', 'VPC ID', 'CIDR', 'AZ'],
                  subnet_data)

    # Internet Gateways
    write_section('Internet Gateways',
                  ['Scope', 'IGW ID', 'Attached VPCs'],
                  igw_data)

    # Sagemaker
    write_section('Sagemaker',
                  ['Scope', 'Notebook Instance Name', 'Instance Type', 'Status'],
                  sagemaker_data)

    # VPC Endpoints
    write_section('VPC Endpoints',
                  ['Scope', 'Endpoint ID', 'Service Name', 'VPC ID', 'Status'],
                  vpc_endpoints)
    
    write_section('CloudFront Distributions',
                  ['Scope', 'Distribution ID', 'Domain Name', 'Enabled', 'Status'],
                  cloudfront_data)

    # DynamoDB Tables
    write_section('DynamoDB Tables',
                  ['Region', 'Table Name', 'Status', 'Item Count', 'Size (Bytes)'],
                  dynamodb_data)

    # ElastiCache Clusters
    write_section('ElastiCache Clusters',
                  ['Region', 'Cluster ID', 'Engine', 'Status', 'Node Type'],
                  elasticache_data)

    # Redshift Clusters
    write_section('Redshift Clusters',
                  ['Region', 'Cluster ID', 'Status', 'Node Type', 'Node Count'],
                  redshift_data)

    # EMR Clusters
    write_section('EMR Clusters',
                  ['Region', 'Cluster ID', 'Name', 'Status'],
                  emr_data)

    # Kinesis Streams
    write_section('Kinesis Streams',
                  ['Region', 'Stream Name', 'Status', 'Shard Count'],
                  kinesis_data)

    # API Gateway
    write_section('API Gateway',
                  ['Region', 'API ID', 'Name', 'Created Date'],
                  apigateway_data)

    # CloudWatch Alarms
    write_section('CloudWatch Alarms',
                  ['Region', 'Alarm Name', 'State', 'Metric Name', 'Namespace'],
                  cloudwatch_data)

    # Adjust column widths
    for i in range(20):  # Assuming a maximum of 20 columns
        worksheet.set_column(i, i, 20)  # Set each column width to 20
