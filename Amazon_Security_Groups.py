#!/usr/bin/python

import pprint 
import collections
import boto.ec2
import requests

current_rule_list=[]
ec2_region="Chose region for example: us-west-2"
AWS_ID='<AWS_ID>'
AWS_SECRET_KEY='<AWS_KEY>'


SecurityGroupRule = collections.namedtuple("SecurityGroupRule", ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])

Group1= [
	#Exmaple : SecurityGroupRule("tcp", "443", "443", "0.0.0.0/0", None)
]

SECURITY_GROUPS = [("Group Name in Amazon", Group1)]


def get_or_create_security_group(c, group_name, description=""):
    groups = [g for g in c.get_all_security_groups() if g.name == group_name]
    group = groups[0] if groups else None
    if not group:
        print "Creating group '%s'..."%(group_name,)
        group = c.create_security_group(group_name, "A group for %s"%(group_name,))
    return group

def modify_sg(c, group, rule, authorize=False, revoke=False):
    src_group = None
    if rule.src_group_name:
        src_group = c.get_all_security_groups([rule.src_group_name,])[0]

    if authorize and not revoke:
        print "Authorizing missing rule %s..."%(rule,)
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=src_group)
    elif not authorize and revoke:
        print "Revoking unexpected rule %s..."%(rule,)
        group.revoke(ip_protocol=rule.ip_protocol,
                     from_port=rule.from_port,
                     to_port=rule.to_port,
                     cidr_ip=rule.cidr_ip,
                     src_group=src_group)

def authorize(c, group, rule):
    return modify_sg(c, group, rule, authorize=True)

def revoke(c, group, rule):
    return modify_sg(c, group, rule, revoke=True)

def update_security_group(c, group, expected_rules):
    print 'Updating group "%s"...'%(group.name,)
    print "Expected Rules:"
    pprint.pprint(expected_rules)

    current_rules = []
    for rule in group.rules:
        if not rule.grants[0].cidr_ip:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              "0.0.0.0/0",
                              rule.grants[0].name)
        else:
            for grants in rule.grants:
                current_rule_list.append(SecurityGroupRule(rule.ip_protocol,
                                  rule.from_port,
                                  rule.to_port,
                                  grants.cidr_ip,
                                  None))
        for current_rule in current_rule_list:
            if current_rule not in expected_rules:
                revoke(c, group, current_rule)
            else:
                current_rules.append(current_rule)

    print "Current Rules:"
    pprint.pprint(current_rules)

    for rule in expected_rules:
        if rule not in current_rules:
            authorize(c, group, rule)

def create_security_groups():
    c = boto.ec2.connect_to_region(ec2_region, aws_access_key_id=AWS_ID, aws_secret_access_key=AWS_SECRET_KEY)
    for group_name, rules in SECURITY_GROUPS:
        group = get_or_create_security_group(c, group_name)
        update_security_group(c, group, rules)

def main():
    create_security_groups()

if __name__=="__main__":
    main()
