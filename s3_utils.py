import boto3
from os.path import expanduser, join as pj
import os

#import requests
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#import urllib3
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#proxies = 'http://127.0.0.1:8181'



def noInsecureWarning():
    from botocore.vendored.requests.packages.urllib3.exceptions import InsecureRequestWarning
    import botocore
    botocore.vendored.requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



class S3Base(object):

    def __init__(self, proxies=None):
        self.config = self.__get_config()
        if proxies:
            os.environ['HTTP_PROXY'] = proxies
            os.environ['HTTPS_PROXY'] = proxies
	    #self.s3_client = boto3.resource('s3', config=Config(proxies={'http': '127.0.0.1:8181'}), region_name=self.config['region'])
        self.s3_client = boto3.client('s3', region_name=self.config['region'], verify=False)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



    def __get_config(self):

        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
            if not a.startswith('[') and '=' in a]
        config = {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}

        # check environment variables
        if os.environ.has_key('AWS_DEFAULT_REGION'):
            config['region'] = os.environ['AWS_DEFAULT_REGION']
        return config




class S3Util(S3Base):

    def __init__(self, proxies=None):
        super(S3Util, self).__init__(proxies=proxies)


    def list_buckets(self):
        return self.s3_client.list_buckets()["Buckets"]





class S3BucketUtil(S3Base):
    '''Code for playing with an s3 bucket'''

    def __init__(self, bucket, proxies=None):
        super(S3BucketUtil, self).__init__(proxies=proxies)
        self.bucket = bucket



    def cp(self, key, data): 
        '''Upload data to a given key'''
        #try:
        self.s3_client.put_object(Bucket=self.bucket, Key=key, Body=data, ServerSideEncryption='AES256')
        #except Exception as e:


    def ls(self):
        '''List bucket contents'''
        d = self.s3_client.list_objects(Bucket=self.bucket)
        if 'Contents' in d:
            return [ a['Key'] for a in d['Contents']]
        else:
            return []


    def cat(self, key):
        '''Get contents of given object'''
        return self.s3_client.get_object(Bucket=self.bucket, Key=key)["Body"].read()


    def rm(self, key):
        '''Delete given object'''
        self.s3_client.delete_object(Bucket=self.bucket, Key=key)
    


def main():
    #my_bucket = 'secops-dta-test-s3-bucket'
    #util = S3Util(my_bucket)
    pass


# go away annoying warning
noInsecureWarning()

if __name__  == '__main__':
    main()



