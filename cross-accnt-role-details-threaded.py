import logging
import time
import boto3
from botocore.exceptions import ClientError
import pandas
from concurrent.futures import ThreadPoolExecutor, as_completed

MNGMT_ACCNT_ID = "000000000000"
MNGMT_ACCNT_ROLE = "list-accounts-role"
MEMBER_ACCNT_ROLE = "read-only-role"
ROLE_SESSION_NAME = "cross-account-role-audit"

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def assume_role_mngmt_accnt(role_arn, service_name):
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


def assume_role_member_accnt(role_arn, accnt_id):
    client = boto3.client("sts")
    response = client.assume_role(RoleArn=role_arn, RoleSessionName=ROLE_SESSION_NAME)
    temp_creds = response["Credentials"]

    resource = boto3.resource(
        "iam",
        aws_access_key_id=temp_creds["AccessKeyId"],
        aws_secret_access_key=temp_creds["SecretAccessKey"],
        aws_session_token=temp_creds["SessionToken"],
    )
    return [accnt_id, resource]


def get_accnt_list(organizations):
    accnt_list = []
    paginator = organizations.get_paginator("list_accounts")
    response_iterator = paginator.paginate()

    for response in response_iterator:
        for accnt in response["Accounts"]:
            if accnt["Status"] == "ACTIVE":
                accnt_list.append({"name": accnt["Name"], "id": accnt["Id"]})

    return accnt_list


def get_roles_list(iam, accnt_id):
    roles_list = []
    for role in iam.roles.all():
        roles_list.append(role)
    return [accnt_id, roles_list]


def get_role_details(role, accnt_id):
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
        return [accnt_id, role_details]


def write_to_excel(data):
    data_frame = pandas.DataFrame()
    for item in data:
        temp = []
        temp.append(item[0])
        temp.append(item[1]["name"])
        temp.append(item[1]["policy_names"])
        temp.append(item[1]["trust_relationship"])
        temp.append(item[1]["X_access_list"])
        record = pandas.DataFrame.from_records([temp])
        data_frame = pandas.concat([data_frame, record])

    data_frame.columns = ["ID", "Role", "Policy", "Trust", "X-Access"]
    data_frame.set_index("ID", inplace=True)
    data_frame.to_excel("report-threaded.xlsx")


def main():
    try:
        role_arn = f"arn:aws:iam::{MNGMT_ACCNT_ID}:role/{MNGMT_ACCNT_ROLE}"
        organizations = assume_role_mngmt_accnt(role_arn, "organizations")
        accnt_list = get_accnt_list(organizations)

        with ThreadPoolExecutor() as executor:
            task0 = []
            task1 = []
            task2 = []
            data = []

            for accnt in accnt_list:
                role_arn = f"arn:aws:iam::{accnt['id']}:role/{MEMBER_ACCNT_ROLE}"
                thread = executor.submit(
                    assume_role_member_accnt, role_arn, accnt["id"]
                )
                task0.append(thread)

            for task in as_completed(task0):
                try:
                    accnt_id = task.result()[0]
                    iam_client = task.result()[1]
                    thread = executor.submit(get_roles_list, iam_client, accnt_id)
                    task1.append(thread)
                except Exception as error:
                    logger.error(f"\nFailed to assume role: {role_arn}\n{str(error)}")

            for task in as_completed(task1):
                accnt_id = task.result()[0]
                roles = task.result()[1]
                for role in roles:
                    thread = executor.submit(get_role_details, role, accnt_id)
                    task2.append(thread)

            for task in as_completed(task2):
                if task.result():
                    data.append(task.result())

            write_to_excel(data)

    except ClientError as error:
        logger.error(f"\nFailed to assume role: {role_arn}\n{str(error)}")
        quit()


if __name__ == "__main__":
    start = time.time()
    main()
    print("Time:", time.time() - start)
