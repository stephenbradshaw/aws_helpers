'''AWS configuration parser'''
from os.path import expanduser, join as pj
import boto3
from botocore.exceptions import ClientError



#https://sdbrett.com/BrettsITBlog/2017/01/aws-boto3-describe-vpc/



class AWSConfigReviewer(object):
    '''Class for doing AWS config review'''

    #pylint: disable=E1136

    def __init__(self):
        '''Initialiser'''
        self.awsc_config = self.read_awsclient_config()
        self.ec2 = boto3.resource('ec2', region_name=self.awsc_config['region'])
        self.client = boto3.client('ec2')
        self.rdsclient = boto3.client('rds')
        self.s3client = boto3.client('s3')
        #self.snsclient = boto3.client('sns')
        self.iamclient = boto3.client('iam')
        self.r53client = boto3.client('route53')

        self.remove_ids = False # debugging
        self.check_s3_object_perms = False # can take ages

        self.vpcs = None
        self.subnets = None
        self.instances = None
        self.network_interfaces = None
        self.security_groups = None
        self.network_acls = None
        self.db_instances = None
        self.db_security_groups = None
        self.s3_data = None
        self.s3_data_owner = None
        self.s3_additional_owners = None
        self.dns_zone_data = None
        self.iam_policies = None
        self.iam_policy_attachments = None
        self.iam_groups = None
        self.iam_users = None
        self.iam_roles = None


        self.networkinterfaces_f = [
            'Association',
            'Attachment',
            'MacAddress',
            'Description',
            'SubnetId'
            ]

        self.instances_f = [
            'SubnetId',
            ''
        ]


    def read_awsclient_config(self):
        '''Reads aws command line client config from default location'''
        config_file = [a for a in open(pj(expanduser('~'), '.aws/config')).read().split('\n') \
                    if not a.startswith('[') and '=' in a]
        return {a.split('=', 1)[0]:a.split('=', 1)[1] for a in config_file}




    def __display_filter_w(self, items, fields):
        '''Filter down to only listed fields'''
        newitems = []
        for item in items:
            newitems.append({a:item[a] for a in fields if a in item.keys()})
        return newitems


    def __display_filter_b(self, items, fields):
        '''Filter out listed fields'''
        newitems = []
        for item in items:
            newitems.append({a:item[a] for a in item.keys() if a not in fields})
        return newitems


    def __grouper(self, mainarray, secondary_arrays, keys, names, by_count=False, list_compare=None):
        '''Groups items'''
        out = list(mainarray)
        aco = 0
        for secondary_array in secondary_arrays:
            for item in out:
                if list_compare:
                    dat = [a for a in secondary_array if item[keys[aco]] in a[list_compare[aco]]]
                else:
                    dat = [a for a in secondary_array if a[keys[aco]] == item[keys[aco]]]
                if self.remove_ids:
                    newdat = []
                    for count in xrange(0, len(dat)):
                        newthing = dat[count].copy()
                        newthing.pop(keys[aco])
                        newdat.append(newthing)
                    dat = newdat
                if by_count:
                    item[names[aco]] = len(dat)
                else:
                    item[names[aco]] = dat
            aco += 1
        return out


    def __add_owner(self, owner):
        '''Simple helper function to add owner details for S3 analysis '''
        if not self.s3_additional_owners.has_key(owner['ID']):
            self.s3_additional_owners[owner['ID']] = owner
            self.s3_additional_owners[owner['ID']]['Buckets'] = []
            self.s3_additional_owners[owner['ID']]['Objects'] = []



    def __devolve_references(self, structure, reference_list):
        '''Walk an embedded structure and return value based on a list of references'''
        out = structure
        for ref in reference_list:
            out = out[ref]
        return out


    def __get_dns_data(self):
        '''Get DNS zone data from route53'''
        zones = self.r53client.list_hosted_zones()['HostedZones']
        zdata = []
        for zone in zones:
            newz = zone.copy()
            newz['RecordSets'] = self.r53client.list_resource_record_sets(HostedZoneId=zone['Id'])['ResourceRecordSets']
            zdata.append(newz)
        self.dns_zone_data = zdata


    def __get_all_data(self, func, key, arguments):
        '''Gall all data for functions that truncate using the Marker method'''

        stored = func(**arguments)
        out = stored[key]

        check_trunc = lambda x: (x.has_key('Truncated') and x['Truncated'])

        while check_trunc(stored):
            arguments['Marker'] = stored['Marker']
            stored = func(**arguments)
            out.append(stored[key])

        return out



    def __get_iam_policy_data(self):
        '''Get IAM policy data'''
        
        # get all the policies
        iam_policies = self.__get_all_data(self.iamclient.list_policies, 'Policies', {'Scope': 'Local'})
        
        for policy in iam_policies:
            pvdata = self.__get_all_data(self.iamclient.list_policy_versions, 'Versions', {'PolicyArn': policy['Arn']})
            current_version = [a['VersionId'] for a in pvdata if a['IsDefaultVersion']][0]
            policy['PolicyData'] = self.iamclient.get_policy_version(PolicyArn=policy['Arn'], VersionId=current_version)['PolicyVersion']

        self.iam_policies = iam_policies

        

    def __get_iam_role_data(self):
        '''Get IAM role data'''

        iam_roles = self.__get_all_data(self.iamclient.list_roles, 'Roles', {})
        
        for role in iam_roles:
            role['AttachedPolicies'] = self.__get_all_data(self.iamclient.list_attached_role_policies, 'AttachedPolicies', {'RoleName' : role['RoleName']})
            role[u'RolePolicies'] = []
            role_policies = self.__get_all_data(self.iamclient.list_role_policies, 'PolicyNames', {'RoleName' : role['RoleName']})
            for policy in role_policies:
                pdata = self.iamclient.get_role_policy(RoleName=role['RoleName'], PolicyName=policy)
                policy_dict = {}
                policy_dict['PolicyName'] = policy
                policy_dict['PolicyDocument'] = pdata['PolicyDocument']
                role['RolePolicies'].append(policy_dict)

        self.iam_roles = iam_roles


    def __get_iam_user_data(self):
        '''IAM user data'''

        iam_users = self.__get_all_data(self.iamclient.list_users, 'Users', {})

        for user in iam_users:
            user[u'AttachedPolicies'] = self.__get_all_data(self.iamclient.list_attached_user_policies, 'AttachedPolicies', {'UserName' : user['UserName']})
            user[u'UserPolicies'] = []
            user_policies = self.__get_all_data(self.iamclient.list_user_policies, 'PolicyNames', {'UserName' : user['UserName']})
            for policy in user_policies:
                pdata = self.iamclient.get_user_policy(UserName=user['UserName'], PolicyName=policy)
                policy_dict = {}
                policy_dict['PolicyName'] = policy
                policy_dict['PolicyDocument'] = pdata['PolicyDocument']
                user['UserPolicies'].append(policy_dict)

        self.iam_users = iam_users



    def __get_iam_group_data(self):
        '''IAM group data'''

        iam_groups = self.__get_all_data(self.iamclient.list_groups, 'Groups', {})

        for group in iam_groups:
            group['AttachedPolicies'] = self.__get_all_data(self.iamclient.list_attached_group_policies, 'AttachedPolicies', {'GroupName' : group['GroupName']})
            group['GroupPolicies'] = []
            group_policies = self.__get_all_data(self.iamclient.list_group_policies, 'PolicyNames', {'GroupName' : group['GroupName']})
            for policy in group_policies:
                pdata = self.iamclient.get_group_policy(GroupName=group['GroupName'], PolicyName=policy)
                policy_dict = {}
                policy_dict['PolicyName'] = policy
                policy_dict['PolicyDocument'] = pdata['PolicyDocument']
                group['GroupPolicies'].append(policy_dict)

        self.iam_groups = iam_groups




    def __get_s3_data(self):
        '''Get the S3 config data'''

        updatefreq = 100
        max_results = 100000
        bucket_data = self.s3client.list_buckets()
        self.s3_data = bucket_data['Buckets']
        self.s3_data_owner = bucket_data['Owner']
        self.s3_additional_owners = {}

        bstats = [
            ('get_bucket_acl', 'Grants'),
            ('get_bucket_policy', 'Policy'),
            ('list_objects_v2', 'Contents', -1, 'Key')
        ]

        for bucket in self.s3_data:
            for bstat in bstats:
                func = getattr(self.s3client, bstat[0])
                try:
                    tdata = func(Bucket=bucket['Name'])
                    if tdata.has_key('Owner') and tdata['Owner'].has_key('ID'):
                        if tdata['Owner']['ID'] != self.s3_data_owner['ID']:
                            self.__add_owner(tdata['Owner'])
                            self.s3_additional_owners[tdata['Owner']['ID']]['Buckets'].append(bucket['Name'])
                    if tdata.has_key('IsTruncated') and tdata['IsTruncated']:
                        tstore = []
                        while tdata['IsTruncated'] and len(tstore) < max_results:
                            tstore += tdata[bstat[1]]
                            tdata = func(Bucket=bucket['Name'], StartAfter=self.__devolve_references(tdata, bstat[1:]))
                    else:
                        tstore=tdata[bstat[1]]
                    bucket[bstat[1]] = tstore
                except (ClientError, KeyError):
                    bucket[bstat[1]] = None
            # now the objects
            if self.check_s3_object_perms: 
                if bucket['Contents']:
                    print 'Checking %d object permissions' % (len(bucket['Contents'])) 
                    count = 0
                    for obj in bucket['Contents']:
                        # check owner
                        count += 1
                        if count % updatefreq == 0:
                            print count
                        acl_data = self.s3client.get_object_acl(Bucket=bucket['Name'], Key=obj['Key'])
                        obj['Grants'] = acl_data['Grants']
                        if acl_data.has_key('Owner') and acl_data['Owner'].has_key('ID'):
                            if acl_data['Owner']['ID'] != self.s3_data_owner['ID']:
                                self.__add_owner(acl_data['Owner'])
                                self.s3_additional_owners[acl_data['Owner']['ID']]['Objects'].append([bucket['Name'], obj['Key']])
                        



    def __get_data(self, datatype, key):
        '''Gets data from Amazon'''

        if datatype == 'instances':
            res = self.client.describe_instances()['Reservations']
            if list(set([len(a['Instances']) for a in res])) == [1]:
                self.instances = [a['Instances'][0] for a in res]
            else:
                raise ValueError('Mismatch in instance data')
        elif datatype == 's3_data':
            self.__get_s3_data()
        elif datatype == 'dns_zone_data':
            self.__get_dns_data()
        elif datatype == 'iam_policies':
            self.__get_iam_policy_data()
        elif datatype == 'iam_groups':
            self.__get_iam_group_data()
        elif datatype == 'iam_users':
            self.__get_iam_user_data()
        elif datatype == 'iam_roles':
            self.__get_iam_role_data()
        elif datatype.startswith('db_'):
            func = getattr(self.rdsclient, 'describe_' + datatype)
            setattr(self, datatype, func()[key])
        else:
            func = getattr(self.client, 'describe_' + datatype)
            setattr(self, datatype, func()[key])



    def __map_value(self, dictionaries, key1, match, key2):
        '''Return a given key based on another unique key from list of dictionaries'''
        return [a[key2] for a in dictionaries if a[key1] == match][0]


    def __replace_mapping(self, list1, list2, matchfield):
        '''Replace dictionaries in a list based on a matching unique key'''
        return [b for a in list1 for b in list2 if a[matchfield] == b[matchfield]]



    def __get_required_data(self, requireddata):
        '''Helper/wrapper function for grabbing data from Amazon'''

        keys = {
            'network_interfaces' : 'NetworkInterfaces',
            'security_groups' : 'SecurityGroups',
            'vpcs' : 'Vpcs',
            'subnets' : 'Subnets',
            'network_acls' : 'NetworkAcls',
            'instances' : None,
            's3_data' : None,
            'dns_zone_data' : None, 
            'iam_policies' : None, 
            'iam_users' : None,
            'iam_groups' : None,
            'iam_roles' : None, 
            'db_instances' : 'DBInstances',
            'db_security_groups' : 'DBSecurityGroups'
        }

        for data in requireddata:
            if not getattr(self, data):
                self.__get_data(data, keys[data])



    def check_other_zones(self):
        '''Check other zones for running instances'''
        regions = [a['RegionName'] for a in self.client.describe_regions()['Regions']]
        regions.remove(self.awsc_config['region'])
        out = {}
        for region in regions:
            tclient = boto3.client('ec2', region_name=region)
            out[region] = tclient.describe_instances()['Reservations']
        return out



    def iam_policy_detail(self):
        '''HLS for IAM'''

        required = [
            'iam_policies'
        ]
        self.__get_required_data(required)


        return self.iam_policies


    def iam_user_detail(self):
        '''HLS for IAM'''

        required = [
            'iam_users'
        ]
        self.__get_required_data(required)


        return self.iam_users


    def iam_group_detail(self):
        '''HLS for IAM'''

        required = [
            'iam_groups'
        ]
        self.__get_required_data(required)


        return self.iam_groups


    def iam_role_detail(self):
        '''HLS for IAM'''

        required = [
            'iam_roles'
        ]
        self.__get_required_data(required)


        return self.iam_roles


    def dns_summary(self):
        '''Get DNS data'''

        required = [
            'dns_zone_data'
        ]
        self.__get_required_data(required)

        return self.dns_zone_data



    def vpc_summary(self):
        '''Gets high level summary for vpcs'''

        required = [
            'vpcs',
            'subnets',
            'network_interfaces',
            'instances',
            'db_instances'
        ]
        self.__get_required_data(required)

        vpc_fields = [
            'VpcId',
            'Tags'
        ]

        subnet_fields = [
            'Tags',
            'VpcId',
            'SubnetId'
        ]

        network_interfaces_fields = [
            'SubnetId',
            'Description',
            'Attachment'
        ]

        instance_fields = [
            'KeyName',
            'InstanceId',
            'Tags'
        ]

        db_instances_fields = [
            'DBName',
            'DBSubnetGroup',
            'DBInstanceIdentifier'
        ]


        
        subnets = self.__display_filter_w(self.subnets, subnet_fields)
        network_interfaces = self.__display_filter_w(self.network_interfaces,
                                                     network_interfaces_fields)

        instances = self.__display_filter_w(self.instances, instance_fields)

        for instance in instances:
            instance['Name'] = [a['Value'] for a in instance['Tags'] if a['Key'] == 'Name'][0]

        for networkinterface in network_interfaces:
            if networkinterface['Attachment']:
                try:
                    networkinterface['InstanceId'] = networkinterface['Attachment']['InstanceId']
                except KeyError:
                    networkinterface['InstanceId'] = None
                networkinterface['InstanceOwnerId'] = networkinterface['Attachment']['InstanceOwnerId']

        network_interfaces = self.__grouper(network_interfaces, [instances], [u'InstanceId'], [u'Instances'])
        network_interfaces = self.__display_filter_b(network_interfaces, ['Attachment'])

        db_instances = self.__display_filter_w(self.db_instances, db_instances_fields)
        for db_instance in db_instances:
            db_instance['Subnets'] = [a['SubnetIdentifier'] for a in db_instance['DBSubnetGroup']['Subnets']]

        subnets = self.__grouper(subnets, [network_interfaces], ['SubnetId'], ['NetworkInterfaces'])
        vpcs = self.__display_filter_w(self.vpcs, vpc_fields)

        for subnet in subnets:
            subnet['DBInstances'] = [a for a in db_instances if subnet['SubnetId'] in a['Subnets']]


        return self.__grouper(vpcs,
                              [subnets],
                              [u'VpcId'], [u'Subnets'])





    def vpc_detail(self):
        '''High level summary'''

        required = [
            'subnets',
            'vpcs',
            'network_acls',
            'network_interfaces',
            'instances',
            'db_instances'
        ]
        self.__get_required_data(required)

        subnet_fields = [
            'Tags',
            'VpcId',
            'SubnetId'
        ]

        network_interfaces_fields = [
            'SubnetId',
            'Description',
            'Attachment'
        ]

        instance_fields = [
            'KeyName',
            'State',
            'InstanceId'
        ]

        db_instances_fields = [
            'DBName',
            'DBSubnetGroup'
        ]


        network_acls = list(self.network_acls)
        subnets = self.__display_filter_w(self.subnets, subnet_fields)
        network_interfaces = self.__display_filter_w(self.network_interfaces,
                                                     network_interfaces_fields)

        instances = self.__display_filter_w(self.instances,
                                            instance_fields)

        for networkinterface in network_interfaces:
            if networkinterface['Attachment']:
                try:
                    networkinterface['InstanceId'] = networkinterface['Attachment']['InstanceId']
                except KeyError:
                    networkinterface['InstanceId'] = None
                networkinterface['InstanceOwnerId'] = networkinterface['Attachment']['InstanceOwnerId']

        network_interfaces = self.__grouper(network_interfaces, [instances], [u'InstanceId'], [u'Instances'])
        network_interfaces = self.__display_filter_b(network_interfaces, ['Attachment'])

        db_instances = self.__display_filter_w(self.db_instances, db_instances_fields)
        for db_instance in db_instances:
            db_instance['Subnets'] = [a['SubnetIdentifier'] for a in db_instance['DBSubnetGroup']['Subnets']]

        subnets = self.__grouper(subnets, [network_interfaces], ['SubnetId'], ['NetworkInterfaces'])

        for subnet in subnets:
            subnet['DBInstances'] = [a for a in db_instances if subnet['SubnetId'] in a['Subnets']]


        for network_acl in network_acls:
            for association in network_acl['Associations']:
                association['SubnetTags'] = self.__map_value(subnets,
                                                             'SubnetId',
                                                             association['SubnetId'], 'Tags')


        return self.__grouper(self.vpcs,
                              [subnets, network_acls],
                              [u'VpcId', u'VpcId'], [u'Subnets', u'NetworkAcls'])



    def rds_detail(self):
        '''Summary of RDS instances'''

        required = [
            'db_instances'
        ]

        db_instances_fields = [
            'DBName',
            'DBSubnetGroup',
            'Endpoint',
            'Engine',
            'EngineVersion',
            'StorageEncrypted',
            'VpcSecurityGroups',
            'DBInstanceIdentifier',
            'PubliclyAccessible',
            'IAMDatabaseAuthenticationEnabled'

        ]
        self.__get_required_data(required)


        db_instances = self.__display_filter_w(self.db_instances, db_instances_fields)
        # rds instances linked to interfaces through subnet groups in a vpc
        return db_instances
        


    def instance_detail(self):
        '''HLS of instances'''

        required = [
            'instances',
            'subnets',
            'vpcs',
            'network_acls',
            'network_interfaces',
            'security_groups'
        ]
        self.__get_required_data(required)

        networkinterface_fields = [
            'Description',
            'MacAddress',
            'SubnetId',
            'NetworkInterfaceId',
            'Groups',
            'Association',
            'PrivateDnsName',
            'PrivateIpAddress',
            'PrivateIpAddresses',
            'AvailabilityZone',
            'Attachment',
            'RequesterId',
            'RequesterManaged',
            'Ipv6Addresses',
            'Status'
        ]

        subnet_fields = [
            'Tags',
            'VpcId',
            'SubnetId'
        ]

        instance_fields = [
            'Tags',
            'KeyName',
            'State',
            'VpcId',
            'SubnetId',
            'NetworkInterfaces',
            'InstanceId',
            'AvailabilityZone'
        ]

        securitygroup_fields = [
            'Description',
            'GroupId',
            'GroupName',
            'IpPermissions',
            'IpPermissionsEgress',
            'OwnerId'
        ]

        network_acls = list(self.network_acls)

        subnets = self.__display_filter_w(self.subnets, subnet_fields)

        networkinterfaces = self.__display_filter_w(self.network_interfaces, networkinterface_fields)

        instances = self.__display_filter_w(self.instances, instance_fields)

        securitygroups = self.__display_filter_w(self.security_groups, securitygroup_fields)

        for networkinterface in networkinterfaces:
            networkinterface['Groups'] = self.__replace_mapping(networkinterface['Groups'], securitygroups, 'GroupId')


        for network_acl in network_acls:
            network_acl['SubnetAssociations'] = [a['SubnetId'] for a in network_acl['Associations']]
            for association in network_acl['Associations']:
                association['SubnetTags'] = self.__map_value(subnets,
                                                            'SubnetId',
                                                            association['SubnetId'], 'Tags')

        #instances = self.__grouper(instances, [network_acls], [u'VpcId',], [ u'NetworkAcls'])


        for instance in instances:
            instance['VpcTags'] = self.__map_value(self.vpcs, 'VpcId', instance['VpcId'], 'Tags')
            instance['Name'] = [a['Value'] for a in instance['Tags'] if a['Key'] == 'Name'][0]
            instance['SubnetTags'] = self.__map_value(subnets, 'SubnetId', instance['SubnetId'], 'Tags')
            instance['NetworkInterfaces'] = self.__replace_mapping(instance['NetworkInterfaces'], networkinterfaces, 'NetworkInterfaceId')

        instances = self.__grouper(instances, [network_acls], [u'SubnetId'], [ u'NetworkAcls'], list_compare=['SubnetAssociations'])


        return instances


    def s3bucket_high_level_summary(self):
        '''HLS s3 buckets'''

        self.__get_required_data(['s3_data'])
        return self.s3_data



    def networkinterface_high_level_summary(self):
        '''HLS of network interfaces'''

        required = [
            'network_interfaces',
            'security_groups',
            'instances'
        ]
        self.__get_required_data(required)

        securitygroup_fields = [
            'Description',
            'GroupId',
            'GroupName'
        ]

        instance_fields = [
            'KeyName',
            'State',
            'InstanceId'
        ]

        securitygroups = self.__display_filter_w(self.security_groups, securitygroup_fields)

        instances = self.__display_filter_w(self.instances, instance_fields)

        networkinterfaces = list(self.network_interfaces)

        for networkinterface in networkinterfaces:
            if networkinterface['Attachment']:
                try:
                    networkinterface['InstanceId'] = networkinterface['Attachment']['InstanceId']
                except KeyError:
                    networkinterface['InstanceId'] = None
                networkinterface['InstanceOwnerId'] = networkinterface['Attachment']['InstanceOwnerId']
            networkinterface['Groups'] = self.__replace_mapping(networkinterface['Groups'], securitygroups, 'GroupId')

        return self.__grouper(networkinterfaces, [instances], [u'InstanceId'], [u'Instances'])



    def subnet_high_level_summary(self):
        '''HLS subnets'''

        required = [
            'instances',
            'subnets',
            'vpcs',
            'network_interfaces',
            'db_instances'
        ]

        self.__get_required_data(required)

        subnet_fields = [
            'CidrBlock',
            'SubnetId',
            'Tags',
            'VpcId'
        ]

        networkinterface_fields = [
            'Description',
            'MacAddress',
            'SubnetId',
            'NetworkInterfaceId'
        ]

        instance_fields = [
            'KeyName',
            'State',
            'VpcId',
            'SubnetId',
            'NetworkInterfaces',
        ]

        db_instances_fields = [
            'DBName',
            'DBSubnetGroup'
        ]

        subnets = self.__display_filter_w(self.subnets, subnet_fields)
        db_instances = self.__display_filter_w(self.db_instances, db_instances_fields)
        networkinterfaces = self.__display_filter_w(self.network_interfaces, networkinterface_fields)
        instances = self.__display_filter_w(self.instances, instance_fields)

        for db_instance in db_instances:
            db_instance['Subnets'] = [a['SubnetIdentifier'] for a in db_instance['DBSubnetGroup']['Subnets']]

        for instance in instances:
            instance['VpcTags'] = self.__map_value(self.vpcs, 'VpcId', instance['VpcId'], 'Tags')
            instance['NetworkInterfaces'] = self.__replace_mapping(instance['NetworkInterfaces'], networkinterfaces, 'NetworkInterfaceId')

        for subnet in subnets:
            subnet['VpcTags'] = self.__map_value(self.vpcs, 'VpcId', subnet['VpcId'], 'Tags')
            subnet['DBInstances'] = [a for a in db_instances if subnet['SubnetId'] in a['Subnets']]

        return self.__grouper(subnets, [instances, networkinterfaces], [u'SubnetId', u'SubnetId'], [u'Instances', u'NetworkInterfaces'])






awsc = AWSConfigReviewer()