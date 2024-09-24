import os
import time
import uuid
import json
import base64
import hashlib
import logging

import requests
from asn1crypto import tsp, algos

import instance_util

WITNESS_TS_TAG = "WITNESS-TS-TAG"
ALLOWED_INSTANCE_EVENTS = []
TSA_SERVER_URL = "http://timestamp.digicert.com"


def validate_instance_state(instance_id, boto3_session):
    try:
        # add tag as timestamp event on instance
        random_tag_val = uuid.uuid4().hex
        instance_util.create_instance_tag(
            instance_id, WITNESS_TS_TAG, random_tag_val, boto3_session)

        # waiting for the CreateTags event
        cloudtrail_client = boto3_session.client("cloudtrail")

        timeout_sec = 300
        start_time = time.time()

        instance_event_list = None
        create_tag_event_idx = None

        while True:
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        "AttributeKey": "ResourceName",
                        "AttributeValue": instance_id
                    },
                ]
            )

            # sort events by time
            instance_event_list = sorted(
                response["Events"], key=lambda x: x["EventTime"])

            for idx, event in enumerate(instance_event_list):
                if event["EventName"] == "CreateTags":
                    event_detail = json.loads(event["CloudTrailEvent"])
                    tag_item = event_detail["requestParameters"]["tagSet"]["items"][0]
                    if tag_item["key"] == WITNESS_TS_TAG and tag_item["value"] == random_tag_val:
                        create_tag_event_idx = idx
                        break

            if create_tag_event_idx:
                break

            # stop waiting when the timout is reached
            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout_sec:
                raise Exception("Timeout reached, no CreateTags event found.")

            time.sleep(5)

        # check cloudtrail event of instance between runInstance to CreateTags
        for idx, event in enumerate(instance_event_list[:create_tag_event_idx + 1]):
            if idx == 0:
                if event["EventName"] != "RunInstances":
                    raise Exception("Invalid first instance event.")
            elif idx == create_tag_event_idx:
                if event["EventName"] != "CreateTags":
                    raise Exception("Invalid latest instance event.")
            else:
                if event["EventName"] not in ALLOWED_INSTANCE_EVENTS:
                    raise Exception("Disallowed instance event found.")

        # check if the CreateReplaceRootVolumeTask event existed
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {
                    "AttributeKey": "EventName",
                    "AttributeValue": "CreateReplaceRootVolumeTask"
                },
            ],
            StartTime=instance_event_list[0]["EventTime"],
            EndTime=instance_event_list[create_tag_event_idx]["EventTime"],
        )

        for event in sorted(response["Events"], key=lambda x: x["EventTime"]):
            event_detail = json.loads(event["CloudTrailEvent"])
            if event_detail["requestParameters"]["CreateReplaceRootVolumeTaskRequest"]["InstanceId"] == instance_id:
                raise Exception(
                    "CreateReplaceRootVolumeTask event found.")
    except BaseException as e:
        logging.error(str(e))
        raise Exception("Failed to validate instance state.")


def gen_witness_proof(statement):
    try:
        # calculate the statement hash
        statement_hash = hashlib.sha256(json.dumps(
            statement, separators=(',', ':')).encode("utf-8")).hexdigest()

        # request oidc token
        oidc_req_url = f"{os.environ['GH_ID_TOKEN_REQ_URL']}&audience=sugarapple-proof-{statement_hash}"
        oidc_response = requests.get(
            oidc_req_url,
            headers={
                "Authorization": f"bearer {os.environ['GH_ID_TOKEN_REQ_TOKEN']}"}
        )
        statement_proof = oidc_response.json()["value"]

        # request timestamp
        proof_hash = hashlib.sha256(statement_proof).hexdigest()
        tsa_req = tsp.TimeStampReq({
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {
                    "algorithm": "sha256"
                },
                "hashed_message": proof_hash
            },
            "cert_req": True,
        })
        tsa_response = requests.post(
            TSA_SERVER_URL,
            headers={"Content-Type": "application/timestamp-query"},
            data=tsa_req.dump()
        )

        return {
            "statement": statement,
            "proof": statement_proof,
            "timestamp": base64.b64encode(tsa_response.content).decode("utf-8")
        }

    except BaseException as e:
        logging.error(str(e))
        raise Exception("Failed to generate witness proof.")
