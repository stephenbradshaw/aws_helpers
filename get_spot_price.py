#!/usr/bin/env python
import boto3
import sys
import argparse
import datetime
from dateutil.tz import tzutc

description = 'Simple utility to return a list of the most recent spot prices for all availability zones in a region.'


def get_current_region():
    '''Get the current default region'''
    return boto3.session.Session().region_name


def get_availability_zones(region_name):
    '''Get the availability zones for a given region'''
    boto3.client('ec2',region_name=region_name)
    return [ a['ZoneName'] for a in boto3.client('ec2',region_name=region_name).describe_availability_zones()['AvailabilityZones']]


def get_spot_price(instance_types, region_name=None, products=['Linux/UNIX'], history=1):
    '''Get the most recent spot prices given a set of parameters'''
    if region_name==None:
        region_name=get_current_region()
    
    client=boto3.client('ec2',region_name=region_name)
    availability_zones = get_availability_zones(region_name)
    prices = {}
    for availability_zone in availability_zones:
        if not availability_zone in prices:
            prices[availability_zone] = {}
        for product in products:
            if not product in prices[availability_zone]:
                prices[availability_zone][product] = {}
            for instance_type in instance_types:
                prices[availability_zone][product][instance_type] = []

                # the following is inefficient due to needing multiple api calls, but its the
                # easist way to zero in on a given number of the most recent results for 
                # each combination of parameters
                r=client.describe_spot_price_history(InstanceTypes=[instance_type],
                                                        MaxResults=history,
                                                        ProductDescriptions=[product],
                                                        AvailabilityZone=availability_zone)

                for entry in r['SpotPriceHistory']:
                    prices[availability_zone][product][instance_type].append({ 'SpotPrice': entry['SpotPrice'], 'Timestamp': entry['Timestamp'] })
    return prices



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-i', '--instancetypes',
                        help='comma seperated list of instance types to check (https://aws.amazon.com/ec2/instance-types/). Default:("m3.large")',
                        required=False,
                        action='store')
    parser.add_argument('-r', '--region',
                        help='region to check prices in. Default:(Your default region)',
                        required=False,
                        action='store')
    parser.add_argument('-p', '--products',
                        help='comma seperated list of ec2 products (Windows, SUSE Linux, Linux/UNIX). Default:("Linux/UNIX")',
                        required=False,
                        action='store')
    parser.add_argument('-x', '--history',
                        help='Integer value for the number of most recent spot prices to show',
                        required=False,
                        action='store')
    parser.add_argument('-t', '--timestamp',
                        help='Show timestamp of spot price in output',
                        required=False,
                        action='store_true',
                        default=False)

    
    args = parser.parse_args()
    
    if args.region:
        myargs = {'region_name' : args.region}
    else:
        myargs = {'region_name' : get_current_region()}

    if args.instancetypes:
        myargs['instance_types'] = [ a.lstrip().rstrip() for a in args.instancetypes.split(',') if a ]
    else:
        myargs['instance_types'] = ['m3.large']

    if args.products:
        myargs['products'] = [ a.lstrip().rstrip() for a in args.products.split(',') if a ]

    if args.history:
        try:
            myargs['history'] = int(args.history)
        except:
            raise argparse.ArgumentTypeError("%s must be an integer" % args.history)
        
    sp = get_spot_price(**myargs)

    print 'Region: %s' %(myargs['region_name'])
    if not args.timestamp:
        print '(Most recent entries first)\n'
    else:
        print 

    for key1 in sp:
        print '%s' %(key1)
        for key2 in sp[key1]:
            for key3 in sp[key1][key2]:
                for item in sp[key1][key2][key3]:
                    if args.timestamp:
                        ts = item['Timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                        print '    %s (%s): $%s @ %s' %(key3, key2, item['SpotPrice'], ts)
                    else:
                        print '    %s (%s): $%s' %(key3, key2, item['SpotPrice'])



    