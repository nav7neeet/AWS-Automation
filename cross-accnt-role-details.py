import logging
import time
import boto3
from botocore.exceptions import ClientError
import pandas

MNGMT_ACCNT_ID = "000000000000"
MNGMT_ACCNT_ROLE = "list-accounts-role"
MEMBER_ACCNT_ROLE = "read-only-role"
ROLE_SESSION_NAME = "cross-account-role-audit"

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def get_role_arn(accnt_id, role_name):
    role_arn = f"arn:aws:iam::{accnt_id}:role/{role_name}"
    return role_arn


def get_client(role_arn, service_name):
    sts_client = boto3.client("sts")
    response = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName=ROLE_SESSION_NAME
    )
    temp_creds = response["Credentials"]

    client = boto3.client(
        service_name,
        aws_access_key_id=temp_creds["AccessKeyId"],
        aws_secret_access_key=temp_creds["SecretAccessKey"],
        aws_session_token=temp_creds["SessionToken"],
    )
    return client


def get_resource(role_arn, service_name):
    client = boto3.client("sts")
    response = client.assume_role(RoleArn=role_arn, RoleSessionName=ROLE_SESSION_NAME)
    temp_creds = response["Credentials"]

    resource = boto3.resource(
        service_name,
        aws_access_key_id=temp_creds["AccessKeyId"],
        aws_secret_access_key=temp_creds["SecretAccessKey"],
        aws_session_token=temp_creds["SessionToken"],
    )
    return resource


def get_accnt_list(organizations):
    accnt_list = []
    paginator = organizations.get_paginator("list_accounts")
    response_iterator = paginator.paginate()

    for response in response_iterator:
        for accnt in response["Accounts"]:
            accnt_list.append({"name": accnt["Name"], "id": accnt["Id"]})

    return accnt_list


def get_roles_list(iam):
    roles_list = []
    for role in iam.roles.all():
        roles_list.append(role)
    return roles_list


def get_role_details(role):
    role_details = {}
    role_details["name"] = role.name
    role_details["trust_relationship"] = role.assume_role_policy_document["Statement"]

    policy_names = []
    attached_policies = role.attached_policies.all()
    for policy in attached_policies:
        policy_names.append(policy.policy_name)

    role_details["policy_names"] = policy_names

    global X_access
    X_access = False
    X_access_list = []

    for statement in role.assume_role_policy_document["Statement"]:
        principal = statement["Principal"]
        if "AWS" in principal:
            X_access = True
            X_access_list.append(principal["AWS"])
        if "Federated" in principal:
            X_access = True
            X_access_list.append(principal["Federated"])

    role_details["X_access_list"] = X_access_list

    if X_access:
        return role_details


def get_data_frame():
    table = []
    columns = [
        "Account ID",
        "Account Name",
        "Role Name",
        "Policy",
        "Trust Relationship",
        "X Access",
    ]
    data_frame = pandas.DataFrame(table, columns=columns)
    return data_frame


def create_table(data_frame, role_details, accnt_id, accnt_name):
    data_frame = pandas.concat(
        [
            data_frame,
            pandas.DataFrame.from_records(
                [
                    {
                        "Account ID": accnt_id,
                        "Account Name": accnt_name,
                        "Role Name": role_details["name"],
                        "Policy": role_details["policy_names"],
                        "Trust Relationship": role_details["trust_relationship"],
                        "X Access": role_details["X_access_list"],
                    }
                ]
            ),
        ]
    )
    return data_frame


def write_to_excel(table):
    file_name = "report.xlsx"
    table.to_excel(file_name)


def main():
    try:
        role_arn = get_role_arn(MNGMT_ACCNT_ID, MNGMT_ACCNT_ROLE)
        # logger.info(role_arn)
        client = get_client(role_arn, "organizations")
        accnt_list = get_accnt_list(client)
        # logger.info(accnt_list)
        data_frame = get_data_frame()

        for accnt in accnt_list:
            print(f'Processing AWS Account: {accnt["id"]}')
            role_arn = get_role_arn(accnt["id"], MEMBER_ACCNT_ROLE)
            try:
                resource = get_resource(role_arn, "iam")
                roles_list = get_roles_list(resource)
                for role in roles_list:
                    role_details = get_role_details(role)
                    if role_details:
                        data_frame = create_table(
                            data_frame, role_details, accnt["id"], accnt["name"]
                        )
            except Exception as error:
                print("")
                # logger.error(f"Failed to assume role: {role_arn} " + str(error))
        write_to_excel(data_frame)

    except ClientError as error:
        logger.error(f"Failed to assume role: {role_arn} " + str(error))
        quit()


if __name__ == "__main__":
    start = time.time()
    main()
    print("Time:", time.time() - start)
