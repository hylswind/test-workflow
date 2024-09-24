import os
import sys
import json
import email
from email import policy
import base64
import logging
import argparse

import boto3
# from dotenv import load_dotenv

import witness_util
import instance_util

# load_dotenv()

WITNDEE_DATA_PREFIX = "WITNESS_DATA="
ALLOW_INSTANCE_EVENTS = []

logging.basicConfig(level=logging.INFO)


def parse_instance_userdata(userdata):
    try:
        # decode base64 string
        userdata_text = base64.b64decode(userdata).decode("utf-8")

        # parse mime content
        mime_msg = email.message_from_string(
            userdata_text, policy=policy.default)
        mime_parts = []
        for part in mime_msg.walk():
            part_content = part.get_payload(decode=True)
            mime_parts.append({
                "contentType": part.get_content_type(),
                "fileName": part.get_filename(),
                "content": part_content.decode('utf-8') if part_content else None
            })

        # validate multiple part content
        if mime_parts[0]["contentType"] != "multipart/mixed" or mime_parts[0]["fileName"] is not None or mime_parts[0]["content"] is not None:
            raise Exception("Invalid first part of mime userdata.")

        if mime_parts[1]["contentType"] != "text/cloud-config" or mime_parts[1]["fileName"] != "cloud-init.txt" or mime_parts[1]["content"] is None:
            raise Exception("Invalid second part of mime userdata.")

        if mime_parts[2]["contentType"] != "text/x-shellscript" or mime_parts[2]["fileName"] != "server-config.txt" or mime_parts[2]["content"] is None:
            raise Exception("Invalid third part of mime userdata.")

        # parse server config
        server_config_lines = mime_parts[2]["content"].splitlines()

        if server_config_lines[0] != "#!/bin/bash" or server_config_lines[1] != "<<COMMENT" or server_config_lines[-1] != "COMMENT":
            raise Exception("Invalid server config pattern.")

        server_config = json.loads("".join(server_config_lines[2:-1]))

        return mime_parts[1]["content"], server_config
    except BaseException as e:
        logging.error(str(e))
        raise Exception("Failed to parse instance userdata.")


def gen_instance_proof(pubkey):
    pass


def main():
    try:
        # parse arguments
        parser = argparse.ArgumentParser()
        parser.add_argument("region", type=str)
        parser.add_argument("instance_id", type=str)
        args = parser.parse_args()

        # initialize boto3 session
        boto3_session = boto3.Session(
            aws_access_key_id=os.environ["AWS_KEY_ID"],
            aws_secret_access_key=os.environ["AWS_KEY_SECRET"],
            region_name=args.region
        )

        # load instance information and wintness data
        instance_info = instance_util.load_instance_info(
            args.instance_id, boto3_session)
        instance_witness_data = instance_util.load_instance_witness_data(
            args.instance_id, boto3_session)

        # parse multiple part userdata
        cloud_init_text, server_config = parse_instance_userdata(
            instance_info["attributes"]["userData"])

        # witness instance
        witness_util.validate_instance_state(args.instance_id, boto3_session)

        # prepare witness statement
        witness_statement = {
            "amiID": instance_info["info"]["ImageId"],
            "region": args.region,
            "instanceType": instance_info["info"]["InstanceType"],
            "witnessData": instance_witness_data,
            "cloudInit": base64.b64encode(cloud_init_text.encode("utf-8")).decode("utf-8"),
            "serverConfig": base64.b64encode(json.dumps(server_config).encode("utf-8")).decode("utf-8")
        }

        # generate witness proof
        witness_proof = witness_util.gen_witness_proof(witness_statement)

        with open("proof.json", "w") as f:
            json.dump(witness_proof, f)
    except BaseException as e:
        logging.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
