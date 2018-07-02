#!/usr/bin/env python
''' Stuff'''
import aws_config_parser
import boto3
from os.path import expanduser, join as pj

if not 'awsc' in locals():
    awsc = aws_config_parser.AWSConfigReviewer()



headsep = '-' * 20
sep = '=' * 20



def group_print(group, rels):
    '''Pretty print security group'''
    exk = [ a for a in group.keys() if a not in ['IpPermissions', 'IpPermissionsEgress']]
    for key in exk:
        print '%s : %s' %(key, group[key])
    print 'IpPermissions:'
    for perms in group['IpPermissions']:
        for key in perms:
            print '  %s : %s' %(key, ex_print(perms[key], rels))
        print
    print 'IpPermissionsEgress:'
    for perms in group['IpPermissionsEgress']:
        for key in perms:
            print '  %s : %s' %(key, ex_print(perms[key], rels))
        print
    print


def ex_print(item, reps=None):
    if isinstance(item, str):
        return item
    elif isinstance(item, list):
        return '( ' + ','.join([ex_print(a, reps) for a in item]) + ' )'
    elif isinstance(item, dict):
        #reps = {'GroupId' : sec_group_id}
        if reps and [a for a in item.keys() if a in reps.keys()]:
            #import pdb
            #pdb.set_trace()
            get_item = lambda i, k: i[k] + ' {' + reps[k][i[k]] + '}' if k in reps else i[k]
        else:
            get_item = lambda i, k: i[k]
        return '; '.join(['%s: %s' %(a, ex_print(get_item(item, a), reps)) for a in item.keys()])
    elif isinstance(item, int):
        return str(item)
    else:
        return item


def create_dns_map():
    '''Dictionary of route53 DNS records to link to public IPs'''
    out = {}
    dns_data = awsc.dns_summary()
    tdata = [(c['Value'], b['Name']) for a in dns_data for b in a['RecordSets'] if b['Type'] == 'A' for c in b['ResourceRecords']]
    for tda in tdata:
        if not out.has_key(tda[0]):
            out[tda[0]] = []
        out[tda[0]].append(tda[1])
    return out


def summarise_dns_data():
    dns_data = awsc.dns_summary()

    for zone in dns_data:
        print '%s\ns%s\n%s' %(sep, zone['Name'], sep)
        for key in [a for a in zone.keys() if a not in ['RecordSets', 'Name']]:
            print '%s: %s' %(key, zone[key])
        for recordset in zone['RecordSets']:
            for key in recordset:
                print '%s: %s' %(key, ex_print(recordset[key]))
            print
        print



def summarise_hosts(vpc=None):
    '''Prints out a summary of machines'''

    instances = awsc.instance_detail()
    rds_instances = awsc.rds_detail()
    network_acls = awsc.network_acls
    security_groups = awsc.security_groups
    dmap = create_dns_map()
    
    if vpc:
        instances = [a for a in instances if a['VpcId'] == vpc]
        rds_instances = [a for a in rds_instances if vpc == a['DBSubnetGroup']['VpcId'] ]
        print 'Report for VPC: %s' %(vpc)
    

    
    

    print headsep
    for instance in instances:
        if [ni['PrivateIpAddress'] for ni in instance['NetworkInterfaces']]:
            private_ip = ex_print([ni['PrivateIpAddress'] for ni in instance['NetworkInterfaces']])
        if [ni['Association']['PublicIp'] for ni in instance['NetworkInterfaces'] if ni.has_key('Association')]:
            public_ips = [ni['Association']['PublicIp'] for ni in instance['NetworkInterfaces']]
            dns_mappings = None
            if [ a for a in public_ips if a in dmap.keys()]:
                dns_mappings = [dmap[a] for a in public_ips if a in dmap.keys()]
        print '%s,%s,%s,%s,%s,%s' %(instance['Name'], instance['KeyName'], instance['InstanceId'], private_ip, public_ips, dns_mappings)
        
        


def summarise_rds(vpc=None):
    print headsep
    print 'RDS Instances'
    print headsep + '\n'
    for rds_instance in rds_instances:
        print headsep
        print '%s\n%s %s' %(sep, rds_instance['DBName'], rds_instance['Endpoint']['Address'])
        print 'Port: %s' %(rds_instance['Endpoint']['Port'])
        print sep

        #rds_instance['VpcSecurityGroups'] # list of dicts VpcSecurityGroupId



def summarise_host_network_filtering(vpc=None):
    '''Prints out a summary of filtering rules associated with machine and rds instances'''

    instances = awsc.instance_detail()
    rds_instances = awsc.rds_detail()
    network_acls = awsc.network_acls
    security_groups = awsc.security_groups
    dmap = create_dns_map()
    
    if vpc:
        instances = [a for a in instances if a['VpcId'] == vpc]
        rds_instances = [a for a in rds_instances if vpc == a['DBSubnetGroup']['VpcId'] ]
        print 'Report for VPC: %s' %(vpc)
    
    applicable_acls =  [ (instance['InstanceId'],  netacl['NetworkAclId']) for instance in instances for netacl in instance['NetworkAcls']]
    grouped_acls = {}
    
    for acl in applicable_acls:
        if not grouped_acls.has_key(acl[1]):
            grouped_acls[acl[1]] = []
        grouped_acls[acl[1]].append(acl[0])
    
    sec_group_id = {}
    for group in security_groups:
        sec_group_id[group['GroupId']] = group['GroupName']
        

    rels = {'GroupId' : sec_group_id}

    print headsep
    print 'Network ACLs'
    print '(stateless, processed in number order)'
    print headsep
    for acl in grouped_acls.keys():
        entry_data = [a['Entries'] for a in network_acls if a['NetworkAclId'] == acl]
        print 'ACL rules apply to following hosts:'
        for host in grouped_acls[acl]:
            print '%s %s %s' %tuple([[a['Name'],a['KeyName'],a['InstanceId']] for a in instances if a['InstanceId'] == host][0])

        print '\n\nACL Entries:'
        for entry in entry_data:
            entry = sorted(entry, key=lambda x: int(x['RuleNumber']))
            for item in entry:
                for key in item.keys():
                    print '%s: %s' %(key, item[key])
                print

        
    print headsep
    print 'Security Group data by host and rds instance'
    print '(stateful, allow only, all rules processed)'
    print headsep
    for instance in instances:
        print '%s\n%s %s %s' %(sep, instance['Name'], instance['KeyName'], instance['InstanceId'])
        if [ni['PrivateIpAddress'] for ni in instance['NetworkInterfaces']]:
            print '  Private IP: %s' %(ex_print([ni['PrivateIpAddress'] for ni in instance['NetworkInterfaces']]))
        if [ni['Association']['PublicIp'] for ni in instance['NetworkInterfaces'] if ni.has_key('Association')]:
            public_ips = [ni['Association']['PublicIp'] for ni in instance['NetworkInterfaces']]
            print '  Public IP: %s' %(ex_print(public_ips))
            if [ a for a in public_ips if a in dmap.keys()]:
                print '  DNS R53 Mappings: %s ' %(ex_print([dmap[a] for a in public_ips if a in dmap.keys()]))
        print sep
        groups = [group for ni in instance['NetworkInterfaces'] for group in ni['Groups']]
        for group in groups:
            group_print(group, rels)
            
        print 
    print headsep
    print 'RDS Instances'
    print headsep + '\n'
    for rds_instance in rds_instances:
        print headsep
        print '%s\n%s %s' %(sep, rds_instance['DBName'], rds_instance['Endpoint']['Address'])
        print 'Port: %s' %(rds_instance['Endpoint']['Port'])
        print sep
        applicable_sec_groups = [ a['VpcSecurityGroupId'] for a in rds_instance['VpcSecurityGroups']]
        for group in [a for a in security_groups if a['GroupId'] in applicable_sec_groups]:
            group_print(group, rels)
        #rds_instance['VpcSecurityGroups'] # list of dicts VpcSecurityGroupId


def summarise_rds_instances(vpc=None):
    '''Summary of RDS instance information'''
    rdses = awsc.rds_detail()

    if vpc:
        rdses = [a for a in rdses if a['DBSubnetGroup']['VpcId'] == vpc]
        print 'Report for VPC: %s' %(vpc)

    things = [
        'DBName',
        #'DBSubnetGroup',
        'Endpoint',
        'Engine',
        'EngineVersion',
        'StorageEncrypted',
        'VpcSecurityGroups',
        'DBInstanceIdentifier',
        'PubliclyAccessible',
        'IAMDatabaseAuthenticationEnabled'
    ]

    for rds in rdses:
        print '%s\n%s\n%s' %(sep, rds['DBName'], sep)
        for thing in things:
            print '  %s: %s' %(thing, ex_print(rds[thing]))
        print 


def summarise_security_groups(vpc=None):
    '''Summary of security groups matching to hosts and rds instances'''
    instances = awsc.instance_detail()
    rds_instances = awsc.rds_detail()
    security_groups = awsc.security_groups


    if vpc:
        instances = [a for a in instances if a['VpcId'] == vpc]
        rds_instances = [a for a in rds_instances if vpc == a['DBSubnetGroup']['VpcId'] ]
        security_groups = [a for a in security_groups if a['VpcId'] == vpc]
        print 'Report for VPC: %s' %(vpc)

    
    sec_group_id = {}
    group_instance_map = {}
    group_rds_map = {}
    for group in security_groups:
        sec_group_id[group['GroupId']] = group['GroupName']
        group_instance_map[group['GroupId']] = [instance['InstanceId'] for instance in instances if group['GroupId'] in [grp['GroupId'] for ni in instance['NetworkInterfaces'] for grp in ni['Groups']] ]
        group_rds_map[group['GroupId']] = [rds['DBInstanceIdentifier'] for rds in rds_instances if group['GroupId'] in [grp['VpcSecurityGroupId'] for grp in rds['VpcSecurityGroups']] ]

    rels = {'GroupId' : sec_group_id}

    for group in security_groups:
        print headsep
        group_print(group, rels)

        print 'Applicable RDS Instances:'
        for rds in group_rds_map[group['GroupId']]:
            rds_instance = [a for a in rds_instances if a['DBInstanceIdentifier'] == rds][0]
            print '  %s %s' %(rds_instance['DBName'], rds_instance['Endpoint']['Address'])
        
        print '\nApplicable Machine Instances:'
        for inst in group_instance_map[group['GroupId']]:
            instance = [a for a in instances if a['InstanceId'] == inst][0]
            if [ni['PrivateIpAddress'] for ni in instance['NetworkInterfaces']]:
                private = ex_print([ni['PrivateIpAddress'] for ni in instance['NetworkInterfaces']])
            else:
                private = ''
            if [ni['Association']['PublicIp'] for ni in instance['NetworkInterfaces'] if ni.has_key('Association')]:
                public = ex_print([ni['Association']['PublicIp'] for ni in instance['NetworkInterfaces']])
            else:
                public = ''
        
            print '  %s %s %s Prv: %s Pub: %s' %(instance['Name'], instance['KeyName'], instance['InstanceId'], private, public)
        print 




def summarise_vpcs(vpc=None):
    '''Prints out a summary of the vpcs'''
    vpcs = awsc.vpc_summary()

    if vpc:
        vpcs = [a for a in vpcs if a['VpcId'] == vpc]
    

    print 'Account Summary:'
    print 'Total VPCs: %d' %(len(vpcs))
    print 'Total Subnets: %d' %(len([sn  for vpc in vpcs for sn in vpc['Subnets']]))
    print 'Network Interfaces: %d' %(sum([len(sn['NetworkInterfaces']) for vpc in vpcs for sn in vpc['Subnets']]))
    print '  NAT Gateway Interfaces: %d' %(len([ni['Description']  for vpc in vpcs for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] if ni['InstanceOwnerId']=='amazon-aws' and 'NAT Gateway' in ni['Description']]))
    print '  RDS Connected Interfaces: %d' %(len([ni['Description']  for vpc in vpcs for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] if ni['InstanceOwnerId']=='amazon-rds']))
    print '  Machine Instance Connected Interfaces: %d' %(len([ni['Description']  for vpc in vpcs for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] if not ni['InstanceOwnerId'].startswith('amazon')]))
    print 'Machine Instances: %d' %(sum([len(ni['Instances'])  for vpc in vpcs for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] ]))
    print 'RDS Instances: %d' %(len(set([db['DBInstanceIdentifier'] for vpc in vpcs for sn in vpc['Subnets'] for db in sn['DBInstances']])))
    print 


    for vpc in vpcs:
        print 'VPC Summary'
        for tag in vpc['Tags']:
            print '%s: %s' %(tag['Key'], tag['Value'])
        print 'VpcId: %s' %(vpc['VpcId'])
        print 'Subnets: %d' %(len(vpc['Subnets'])) 
        print 'Network interfaces: %d' %(sum([len(sn['NetworkInterfaces']) for sn in vpc['Subnets']]))
        print '  NAT Gateway Interfaces: %d' %(len([ni['Description'] for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] if ni['InstanceOwnerId']=='amazon-aws' and 'NAT Gateway' in ni['Description']]))
        print '  RDS Connected Interfaces: %d' %(len([ni['Description'] for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] if ni['InstanceOwnerId']=='amazon-rds']))
        print '  Machine Instance Connected Interfaces: %d' %(len([ni['Description'] for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] if not ni['InstanceOwnerId'].startswith('amazon')]))
        print 'Machine Instances: %d' %(sum([len(ni['Instances']) for sn in vpc['Subnets'] for ni in sn['NetworkInterfaces'] ]))
        print 'RDS Instances: %d' %(len(set([db['DBInstanceIdentifier'] for sn in vpc['Subnets'] for db in sn['DBInstances']])))

        
        
        print ''


        print 'Subnets:'
        for subnet in vpc['Subnets']:
            for tag in subnet['Tags']:
                print '%s: %s' %(tag['Key'], tag['Value'])
            print 'SubnetId: %s' %(subnet['SubnetId'])
            print 'Network Interfaces'
            for network_int in subnet['NetworkInterfaces']:
                print 'Interface description: %s' %(network_int['Description'])
                if network_int['Instances']:
                    for instance in network_int['Instances']:
                        print '  Instance: %s %s' %(instance['Name'], instance['KeyName'])
            if subnet['DBInstances']:
                print 'Associated DB Instances'
                for dbinstance in subnet['DBInstances']:
                    print 'DB Name: %s' %(dbinstance['DBName'])
            print

        
        




#print [vpc['Tags'] for vpc in vpcs]




