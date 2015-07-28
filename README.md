# Amazon Manage Security Groups

Please note that amazon has some limitation on the ammount of rules.
For more inforamtion:
http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html

To execute the script plese insert the following credentials: 
ec2_region="Chose region for example: us-west-2"

Insert the ID and a SECRET Key generated from IAM:

AWS_ID = '\<AWS_ID\>'

AWS_SECRET_KEY = '\<AWS_KEY\>'


Crete at least 1 security group with at least 1 rule:

Group1= [

	#Example : SecurityGroupRule("tcp", "443", "443", "0.0.0.0/0", None)
	
]

SecurityGroupRule format:

["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])


ip_protocol : tcp/udp
from_port: specify port
to_port: specify port ( Usually the same as from_port)
cidr_ip: IP that includes subnet
src_group_name: Another "security group name" in amazon ( Access to the whole group)  

If you wish to add more than one Group pleese create more lists:
For example:

Group2= [

	SecurityGroupRule("tcp", "443", "443", "0.0.0.0/0", None),
	
	SecurityGroupRule("tcp", "8080", "8080", "0.0.0.0/0", None),
	
	SecurityGroupRule("tcp", "22", "22", "2.1.1.0/0", None)
	
]


In addition you should specify each group in the SECURITY_GROUPS list:

SECURITY_GROUPS = [("Group Name in EC2", Group1), ("Security_Group2_amazon", Group2)]

The script will automaticaly create the security group at the desired region, if it doesn't exist. 
If the group exists it will update the rules. Previous rules won't be saved and will be wiped out. 
