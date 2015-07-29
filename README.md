# Amazon Manage Security Groups

Please note that 
Amazon has some limitation on the available number of rules.
For more information please go to:
http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html

To execute the script please insert the following credentials: 

ec2_region="Chose region according to regions in EC2 for example: us-west-2"

Insert the AWS_ID and the SECRET_Key generated from IAM:

AWS_ID = '\<AWS_ID\>'

AWS_SECRET_KEY = '\<AWS_KEY\>'




Crete at least 1 security group containing at least 1 rule:

Group1= [

	#Example : SecurityGroupRule("tcp", "443", "443", "0.0.0.0/0", None)
	
]

###SecurityGroupRule format:

["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])


ip_protocol : tcp/udp

from_port: specify port

to_port: specify port ( Usually the same as from_port)

cidr_ip: IP which includes subnet mask

src_group_name: Reference to a different "security group name" inside EC2 at the same region ( Gives access to the whole group)  




If you wish to manage more than one Group please create more lists:

For example:

Group2= [

	SecurityGroupRule("tcp", "443", "443", "0.0.0.0/0", None),
	
	SecurityGroupRule("tcp", "8080", "8080", "0.0.0.0/0", None),
	
	SecurityGroupRule("tcp", "22", "22", "2.1.1.0/0", None)
	
]


Please note that you should specify each group in the SECURITY_GROUPS List:

For example:

SECURITY_GROUPS = [("Group Name in EC2", Group1), ("Security_Group2_amazon", Group2)]

The script will create the security group at the desired region, if it doesn't exist. 
If the group already exists, it will update the rules. Previous rules won't be saved and will be wiped out. 
