# Cross Account Role Audit


**About** <br>
_cross-accnt-role-audit.py_ script generates an excel file as output which has role details across all the AWS accounts present in the organization. The script first assumes a role in the management account to get the list of AWS accounts. It then assumes a role in each member account one by one and lists out all the roles present in the account along with the policies attached to the role, trust relationship, cross account access details etc.

**Sample Output** <br>
Account ID  |	Account Name | Role Name | Policy | Trust Relationship | X Access
----------- |----------------|-----------|--------|-------------------|---------------------
*********266|    Dev         |     role1 |['policy1'] | [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::*********371:root'}, 'Action': 'sts:AssumeRole', 'Condition': {}}] | ['arn:aws:iam::*********294:root']
*********371|    Test         |     role2 |['policy2, policy5'] | [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::*********257:root'}, 'Action': 'sts:AssumeRole', 'Condition': {}}] | ['arn:aws:iam::*********372:root']
*********468|    QA         |     role3 |['policy3'] | [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::*********862:root'}, 'Action': 'sts:AssumeRole', 'Condition': {}}] | ['arn:aws:iam::*********294:root']

<br>
**Prerequisites** <br>
1. MNGMT_ACCNT_ROLE<br>
Create a role with appropriate policy in all the member accounts. This role should have trust relationship with the Security Tooling account or some other account which is used to run the python script. The script assumes this role to get all the list of member accounts present in the organization.<br>
2. MEMBER_ACCNT_ROLE<br>
Create a role with appropriate policy in all the member accounts. This role should have trust relationship with the Security Tooling account or some other account which is used to run the python script. The script assumes this role to get the role details.<br>

**Installation** <br>
Clone the repo and install the following dependencies - boto3, pandas and openpyxl <br>

**Required Configuration** <br>
MNGMT_ACCNT_ID = "000000000000" --Account number of the management account. <br><br>
MNGMT_ACCNT_ROLE = "list-accounts-role" --Role in the management account to get AWS account list. It should have trust relationship to the Security-Tooling or some other account from where we are running our python script.<br><br>
MEMBER_ACCNT_ROLE = "read-only-role" --Role deployed in all the member accounts (child accounts) with trust relationship to the Security-Tooling or some other account from where we are running our python script. <br><br>
ROLE_SESSION_NAME = "cross-account-role-audit" --role session name<br>
