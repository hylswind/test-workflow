import time
import logging

WITNDEE_DATA_PREFIX = "WITNESS_DATA="


def load_instance_info(instance_id, boto3_session):
    try:
        instance_info = {"info": None, "attributes": {}}
        ec2_client = boto3_session.client("ec2")

        # get instance information
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance_info["info"] = response["Reservations"][0]["Instances"][0]

        # get instance attributes
        response = ec2_client.describe_instance_attribute(
            Attribute="userData", InstanceId=instance_id)
        instance_info["attributes"]["userData"] = response["UserData"]["Value"]

        return instance_info
    except BaseException as e:
        logging.error(str(e))
        raise Exception("Failed to load instance information.")


def load_instance_witness_data(instance_id, boto3_session):
    try:
        timeout_sec = 120
        start_time = time.time()
        ec2_client = boto3_session.client("ec2")

        # waiting for console output
        while True:
            response = ec2_client.get_console_output(
                InstanceId=instance_id, Latest=True)

            # search wintness data in console output
            if response["Output"]:
                output_lines = response["Output"].splitlines()

                for line in output_lines:
                    find_res = line.find(WITNDEE_DATA_PREFIX)
                    if find_res != -1:
                        return line[find_res + len(WITNDEE_DATA_PREFIX):]

            # stop waiting when the timout is reached
            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout_sec:
                raise Exception("Timeout reached, no console output received.")

            time.sleep(5)
    except BaseException as e:
        logging.error(str(e))
        raise Exception("Failed to load instance witness data.")


def create_instance_tag(instance_id, tag_name, tag_value, boto3_session):
    try:
        ec2_client = boto3_session.client("ec2")
        ec2_client.create_tags(
            Resources=[instance_id,],
            Tags=[{"Key": tag_name, "Value": tag_value},]
        )
    except BaseException as e:
        logging.error(str(e))
        raise Exception("Failed to create instance tag.")
