import boto3
from os.path import expanduser, join as pj
import os

import botocore
from botocore.vendored.requests.packages.urllib3.exceptions import InsecureRequestWarning
botocore.vendored.requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



#proxies = 'http://127.0.0.1:8181'
#credentials = {
#    'aws_access_key_id' : '',
#    'aws_secret_access_key' : ''
# aws_session_token
#}



class LambdaUtil(object):

    def __init__(self, credentials=None, proxies=None, region=None):
        self.config = self.__get_config()
        if not region:
            region = self.config['region']
        if proxies:
            os.environ['HTTP_PROXY'] = proxies
            os.environ['HTTPS_PROXY'] = proxies
        if credentials:
            self.lambda_client = boto3.client('lambda',
                                              region_name=self.config['region'],
                                              verify=False,
                                              **credentials)
        else:
            self.lambda_client = boto3.client('lambda', region_name=self.config['region'], verify=False)


    def __get_config(self):
        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
            if not a.startswith('[') and '=' in a]
        return {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}



class APIGatewayUtil(object):

    def __init__(self, credentials=None, proxies=None, region=None):
        self.config = self.__get_config()
        if not region:
            region = self.config['region']
        if proxies:
            os.environ['HTTP_PROXY'] = proxies
            os.environ['HTTPS_PROXY'] = proxies
        if credentials:
            self.api_client = boto3.client('apigateway',
                                              region_name=self.config['region'],
                                              verify=False,
                                              **credentials)
        else:
            self.api_client = boto3.client('apigateway', region_name=self.config['region'], verify=False)


    def __get_config(self):
        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
            if not a.startswith('[') and '=' in a]
        return {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}





class IAMUtil(object):

    def __init__(self, credentials=None, proxies=None):
        self.config = self.__get_config()
        if proxies:
            os.environ['HTTP_PROXY'] = proxies
            os.environ['HTTPS_PROXY'] = proxies
        if credentials:
            self.iam_client = boto3.client('iam',
                                           region_name=self.config['region'],
                                           verify=False,
                                           **credentials)
        else:
            self.iam_client = boto3.client('iam', region_name=self.config['region'], verify=False)


    def __get_config(self):
        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
            if not a.startswith('[') and '=' in a]
        return {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}


    def list_users(self):
        return self.iam_client.list_users()['Users']



class STSUtil(object):

    def __init__(self, credentials=None, proxies=None):
        self.config = self.__get_config()
        if proxies:
            os.environ['HTTP_PROXY'] = proxies
            os.environ['HTTPS_PROXY'] = proxies
        if credentials:
            self.sts_client = boto3.client('sts',
                                          verify=False,
                                          **credentials)
        else:
            self.sts_client = boto3.client('sts', verify=False)


    def __get_config(self):
        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
            if not a.startswith('[') and '=' in a]
        return {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}


    def get_caller_identity(self):
        things = self.sts_client.get_caller_identity()
        return [ things[a] for a in things.keys() if a in ['Account', 'Arn'] ]




class EC2Util(object):

    def __init__(self, credentials=None, proxies=None, region=None):
        self.config = self.__get_config()
        if not region:
            region = self.config['region']
        if proxies:
            os.environ['HTTP_PROXY'] = proxies
            os.environ['HTTPS_PROXY'] = proxies
        if credentials:
            self.ec2_client = boto3.client('ec2',
                                           region_name=region,
                                           verify=False,
                                           **credentials)
        else:
            self.ec2_client = boto3.client('ec2', region_name=region, verify=False)


    def __get_config(self):
        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
            if not a.startswith('[') and '=' in a]
        return {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}


    def get_snapshots(self):
        things = self.ec2_client.get_caller_identity()
        return [ things[a] for a in things.keys() if a in ['Account', 'Arn'] ]



class S3Util(object):
    '''Code for getting contents of named S3 bucktets'''

    def __init__(self, bucket=None, credentials=None, proxies=None, region=None):
        self.config = self.__get_config()
        if bucket:
            self.bucket = bucket
        if proxies:
            os.environ['HTTP_PROXY'] = proxies
            os.environ['HTTPS_PROXY'] = proxies
        if not region:
            region = self.config['region']
        if credentials:
            self.s3_client = boto3.client('s3',
                                          region_name=region,
                                          verify=False,
                                          **credentials)
        else:
            self.s3_client = boto3.client('s3', region_name=region, verify=False)
        

    def set_bucket(self, bucket):
        '''Set the active bucket to query'''
        self.bucket = bucket



    def ls_buckets(self):
        '''List all the buckets associated with the configured access token'''
        return [a['Name'] for a in self.s3_client.list_buckets()['Buckets']]



    def ls_acl(self, bucket=None):
        if not bucket:
            bucket=self.bucket
        return self.s3_client.get_bucket_acl(Bucket=bucket)


    def __get_config(self):
        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
            if not a.startswith('[') and '=' in a]
        return {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}


    def cp(self, key, data): 
        '''Upload data to a given key'''
        #try:
        self.s3_client.put_object(Bucket=self.bucket, Key=key, Body=data, ServerSideEncryption='AES256')
        #except Exception as e:


    def ls(self, bucket=None):
        '''List bucket contents'''
        if not bucket:
            bucket=self.bucket
        x = self.s3_client.list_objects(Bucket=bucket)
        if x.has_key('Contents'):
            return [ a['Key'] for a in x['Contents']]
        else:
            return []


    def cat(self, key, bucket=None):
        '''Get contents of given object'''
        if not bucket:
            bucket=self.bucket
        return self.s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()


    def rm(self, key, bucket=None):
        '''Delete given object'''
        if not bucket:
            bucket=self.bucket
        self.s3_client.delete_object(Bucket=bucket, Key=key)
    

    def fetch(self, bucket=None, files=None):
        '''Fetches all files in files and saves them to disk'''
        if not bucket:
            bucket=self.bucket
        if not files:
            files = self.ls()
        for fil in files:
            p, fn = os.path.split(fil) # this will break on MS Windows
            if p:
                try:
                    os.makedirs(p)
                except OSError as exc: 
                    if exc.errno == 17 and os.path.isdir(p):
                        pass
            open(fil, 'w').write(self.s3_client.get_object(Bucket=bucket, Key=fil)["Body"].read())




my_bucket = 'secops-dta-test-s3-bucket'
util = S3Util(my_bucket)




#feeds.yml in SCYTHE has feed info and match data for routers
#messageformat defines parsing


