# AWS-Automation


**About** <br>
_cross-account-role-details.py_ script helps automate the process to fetch IAM roles with cross-account access present across the organization. The script first assumes a role in the management account (Parent account) to get the list of AWS accounts. After getting the account list it assumes a role in each account one by one and lists out all the roles present in the account along with the policies attached to the role trust relationship, cross account access details etc. The final output is an excel file containig the list of cross account roles present across various AWS accounts and other details.

**Sample Output** <br>

Account ID  |	Account Name | Role Name | Policy | Trust Relationship | X Access
----------- |----------------|-----------|--------|-------------------|---------------------
*********266|    Dev         |     role1 |['policy1'] | [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::*********371:root'}, 'Action': 'sts:AssumeRole', 'Condition': {}}] | ['arn:aws:iam::*********294:root']
*********371|    Test         |     role2 |['policy2, policy5'] | [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::*********257:root'}, 'Action': 'sts:AssumeRole', 'Condition': {}}] | ['arn:aws:iam::*********372:root']
*********468|    QA         |     role3 |['policy3'] | [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::*********862:root'}, 'Action': 'sts:AssumeRole', 'Condition': {}}] | ['arn:aws:iam::*********294:root']

<br>

**Installation** <br>
Clone the repo and install the following dependencies - boto3, pandas and openpyxl

**Required Configuration** <br>
MNGMT_ACCNT_ID = "000000000000" --Account number of the management account. <br><br>
MNGMT_ACCNT_ROLE = "list-accounts-role" --Role in the management account to get AWS account list. It should have trust relationship to the Security-Tooling or some other account from where we are running our python script.<br><br>
MEMBER_ACCNT_ROLE = "read-only-role" --Role deployed in all the member accounts (child accounts) with trust relationship to the Security-Tooling or some other account from where we are running our python script. <br><br>
ROLE_SESSION_NAME = "cross-account-role-audit" --role session name<br>
