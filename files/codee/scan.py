# -*- coding: utf-8 -*-
# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import json
import logging
import os
from urllib.parse import unquote_plus
from distutils.util import strtobool

import boto3
import botocore
import clamav
import metrics
from common import AV_DEFINITION_S3_BUCKET
from common import AV_DEFINITION_S3_PREFIX
from common import AV_DELETE_INFECTED_FILES
from common import AV_PROCESS_ORIGINAL_VERSION_ONLY
from common import AV_SCAN_START_METADATA
from common import AV_SCAN_START_SNS_ARN
from common import AV_SIGNATURE_METADATA
from common import AV_STATUS_CLEAN
from common import AV_STATUS_INFECTED
from common import AV_STATUS_METADATA
from common import AV_STATUS_SNS_ARN
from common import AV_STATUS_SNS_PUBLISH_CLEAN
from common import AV_STATUS_SNS_PUBLISH_INFECTED
from common import AV_TIMESTAMP_METADATA
from common import create_dir
from common import get_timestamp

# Environment variables
infected_notification = os.environ['infected_notification']
infected_sns_topic_arn = os.environ['infected_sns_topic_arn']
scan_start_sns_arn = os.environ['infected_sns_topic_arn']
All_Notification = os.environ['All_Notification']
All_Notification_arn = os.environ['All_Notification_arn']

# env variables for quarantine functionality
quarantine_bucket = os.environ['quarantine_bucket']
is_quarantine = os.environ['is_quarantine']

# Setup logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize S3 client
s3 = boto3.client('s3')

# Function to extract bucket and key from the event
def event_object(event, event_source="s3"):
    # Handle SNS events
    if event_source.upper() == "SNS":
        event = json.loads(event["Records"][0]["Sns"]["Message"])

    # Get records from event
    records = event["Records"]
    if len(records) == 0:
        raise Exception("No records found in event!")
    record = records[0]

    s3_obj = record["s3"]

    # Get the bucket name
    if "bucket" not in s3_obj:
        raise Exception("No bucket found in event!")
    bucket_name = s3_obj["bucket"].get("name", None)

    # Get the key name
    if "object" not in s3_obj:
        raise Exception("No key found in event!")
    key_name = s3_obj["object"].get("key", None)

    if key_name:
        key_name = unquote_plus(key_name)

    # Ensure both bucket and key exist
    if (not bucket_name) or (not key_name):
        raise Exception("Unable to retrieve object from event.\n{}".format(event))

    # Create and return the object
    s3 = boto3.resource("s3")
    return s3.Object(bucket_name, key_name)

# Function to verify S3 object versioning
def verify_s3_object_version(s3, s3_object):
    # Ensure processing only the original version if required
    bucket_versioning = s3.BucketVersioning(s3_object.bucket_name)
    if bucket_versioning.status == "Enabled":
        bucket = s3.Bucket(s3_object.bucket_name)
        versions = list(bucket.object_versions.filter(Prefix=s3_object.key))
        if len(versions) > 1:
            raise Exception(
                "Detected multiple object versions in %s.%s, aborting processing"
                % (s3_object.bucket_name, s3_object.key)
            )
    else:
        # Error if bucket versioning is not enabled
        raise Exception(
            "Object versioning is not enabled in bucket %s" % s3_object.bucket_name
        )

# Function to get local path for S3 object
def get_local_path(s3_object, local_prefix):
    return os.path.join(local_prefix, s3_object.bucket_name, s3_object.key)

# Function to handle actions after scanning the file
def after_scan_action(scan_result, quarantine_bucket, is_quarantine, source_bucket_name, object_key, source):
    s3 = boto3.resource('s3')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    print(f"Inputs for after scan action received: {quarantine_bucket} {is_quarantine} {source_bucket_name} {object_key} {source}")
    
    # If the file is infected and quarantine is enabled, move it to the quarantine bucket
    if scan_result == "INFECTED" and is_quarantine == "True":
        print("Inside after scan lambda if statement")
        try:
            response = s3.meta.client.copy(source, quarantine_bucket, object_key)
            logger.info("File copied to the quarantine bucket successfully!")
            s3.Object(source_bucket_name, object_key).delete()
            return {
                'statusCode': 200,
                'body': f'Deleted object {object_key} from bucket {source_bucket_name}'
            }
        except botocore.exceptions.ClientError as error:
            logger.error("There was an error copying the file to the quarantine bucket and deleting from source bucket")
            print('Error Message: {}'.format(error))

    # If the file is infected and quarantine is disabled, delete the file
    elif scan_result == "INFECTED" and is_quarantine == "false":
        s3.Object(source_bucket_name, object_key).delete()
        return {
            'statusCode': 200,
            'body': f'Deleted object {object_key} from bucket {source_bucket_name}'
        }
    else:
        return {
            'statusCode': 404,
            'body': f'Object {object_key} in bucket {source_bucket_name} does not have the infected tag'
        }

# Function to set antivirus metadata on S3 object
def set_av_metadata(s3_object, scan_result, scan_signature, timestamp):
    content_type = s3_object.content_type
    metadata = s3_object.metadata
    metadata[AV_SIGNATURE_METADATA] = scan_signature
    metadata[AV_STATUS_METADATA] = scan_result
    metadata[AV_TIMESTAMP_METADATA] = timestamp
    s3_object.copy(
        {"Bucket": s3_object.bucket_name, "Key": s3_object.key},
        ExtraArgs={
            "ContentType": content_type,
            "Metadata": metadata,
            "MetadataDirective": "REPLACE",
        },
    )

# Function to set antivirus tags on S3 object
def set_av_tags(s3_client, s3_object, scan_result, scan_signature, timestamp):
    curr_tags = s3_client.get_object_tagging(
        Bucket=s3_object.bucket_name, Key=s3_object.key
    )["TagSet"]
    new_tags = copy.copy(curr_tags)
    for tag in curr_tags:
        if tag["Key"] in [
            AV_SIGNATURE_METADATA,
            AV_STATUS_METADATA,
            AV_TIMESTAMP_METADATA,
        ]:
            new_tags.remove(tag)
    new_tags.append({"Key": AV_SIGNATURE_METADATA, "Value": scan_signature})
    new_tags.append({"Key": AV_STATUS_METADATA, "Value": scan_result})
    new_tags.append({"Key": AV_TIMESTAMP_METADATA, "Value": timestamp})
    s3_client.put_object_tagging(
        Bucket=s3_object.bucket_name, Key=s3_object.key, Tagging={"TagSet": new_tags}
    )

# Function to publish SNS notification when scan starts
def sns_start_scan(sns_client, s3_object, scan_start_sns_arn, timestamp):
    message = {
        "bucket": s3_object.bucket_name,
        "key": s3_object.key,
        "version": s3_object.version_id,
        AV_SCAN_START_METADATA: True,
        AV_TIMESTAMP_METADATA: timestamp,
    }
    sns_client.publish(
        TargetArn=scan_start_sns_arn,
        Message=json.dumps({"default": json.dumps(message)}),
        MessageStructure="json",
    )

# Function to publish SNS notification with scan results
def sns_scan_results(
    sns_client, s3_object, sns_arn, scan_result, scan_signature, timestamp
):
    # Don't publish if scan_result is CLEAN and CLEAN results should not be published
    if scan_result == AV_STATUS_CLEAN and not str_to_bool(AV_STATUS_SNS_PUBLISH_CLEAN):
        return
    # Don't publish if scan_result is INFECTED and INFECTED results should not be published
    if scan_result == AV_STATUS_INFECTED and not str_to_bool(
        AV_STATUS_SNS_PUBLISH_INFECTED
    ):
        return
    message = {
        "bucket": s3_object.bucket_name,
        "key": s3_object.key,
        "version": s3_object.version_id,
        AV_SIGNATURE_METADATA: scan_signature,
        AV_STATUS_METADATA: scan_result,
        AV_TIMESTAMP_METADATA: get_timestamp(),
    }
    sns_client.publish(
        TargetArn=sns_arn,
        Message=json.dumps({"default": json.dumps(message)}),
        MessageStructure="json",
        MessageAttributes={
            AV_STATUS_METADATA: {"DataType": "String", "StringValue": scan_result},
            AV_SIGNATURE_METADATA: {
                "DataType": "String",
                "StringValue": scan_signature,
            },
        },
    )

# Main Lambda handler function
def lambda_handler(event, context):
    s3 = boto3.resource("s3")
    s3_client = boto3.client("s3")
    sns_client = boto3.client("sns")

    # Ninad's added inputs for after_scan_action function
    source_bucket_name = event['Records'][0]['s3']['bucket']['name']
    object_key = event['Records'][0]['s3']['object']['key']
    source = {'Bucket': source_bucket_name, 'Key': object_key}

    # Get some environment variables
    ENV = os.getenv("ENV", "")
    EVENT_SOURCE = os.getenv("EVENT_SOURCE", "S3")
    
    start_time = get_timestamp()
    print("Script starting at %s\n" % (start_time))
    s3_object = event_object(event, event_source=EVENT_SOURCE)
    s3_key = os.path.join(s3_object.bucket_name, s3_object.key)

    # Verify S3 object version if required
    if str_to_bool(AV_PROCESS_ORIGINAL_VERSION_ONLY):
        verify_s3_object_version(s3, s3_object)

    # Publish the start time of the scan
    if AV_SCAN_START_SNS_ARN not in [None, ""]:
        start_scan_time = get_timestamp()
        sns_start_scan(sns_client, s3_object, scan_start_sns_arn, start_scan_time)

    file_path = get_local_path(s3_object, "/tmp")
    create_dir(os.path.dirname(file_path))
    s3_object.download_file(file_path)

    # Download and update ClamAV definitions
    to_download = clamav.update_defs_from_s3(
        s3_client, AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX
    )

    for download in to_download.values():
        s3_path = download["s3_path"]
        local_path = download["local_path"]
        print("Downloading definition file %s from s3://%s" % (local_path, s3_path))
        s3.Bucket(AV_DEFINITION_S3_BUCKET).download_file(s3_path, local_path)
        print("Downloading definition file %s complete!" % (local_path))
    
    # Scan the file with ClamAV
    scan_result, scan_signature = clamav.scan_file(file_path)
    print(
        "Scan of s3://%s resulted in %s\n"
        % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result)
    )

    # Send notification if all scans need to be notified
    if All_Notification == "true":
        print("File is scanned! Send notification.")
        sns_client = boto3.client('sns')
        scan_message = "Scan of s3://%s resulted in %s\n" % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result)
        response = sns_client.publish(
            TopicArn=All_Notification_arn,
            Message=scan_message,
            Subject="Scan File Result"
        )
        print(f"Message sent to SNS Topic: {All_Notification_arn}")

    # Send notification if the file is infected
    if scan_result == "INFECTED" and infected_notification == "true":
        print("File is infected! Send notification.")
        sns_client = boto3.client('sns')
        message = f"File is infected! Send .\nS3 Key: {s3_key}"
        response = sns_client.publish(
            TopicArn=infected_sns_topic_arn,
            Message=message,
            Subject="Infected File Alert"
        )
        print(f"Message sent to SNS Topic: {infected_sns_topic_arn}")

    result_time = get_timestamp()
    # Set the properties on the object with the scan results
    if "AV_UPDATE_METADATA" in os.environ:
        set_av_metadata(s3_object, scan_result, scan_signature, result_time)
    set_av_tags(s3_client, s3_object, scan_result, scan_signature, result_time)

    # Publish the scan results
    if AV_STATUS_SNS_ARN not in [None, ""]:
        sns_scan_results(
            sns_client,
            s3_object,
            AV_STATUS_SNS_ARN,
            scan_result,
            scan_signature,
            result_time,
        )

    metrics.send(
        env=ENV, bucket=s3_object.bucket_name, key=s3_object.key, status=scan_result
    )

    # Delete downloaded file to free up room on re-usable lambda function container
    try:
        os.remove(file_path)
    except OSError:
        pass
    
    print(f"Inputs for after scan action: {scan_result} {quarantine_bucket} {is_quarantine} {source_bucket_name} {object_key} {source}")  

    # Perform action based on the scan result (e.g., quarantine or delete)
    after_scan_action(scan_result, quarantine_bucket, is_quarantine, source_bucket_name, object_key, source)  
    
    stop_scan_time = get_timestamp()
    print("Script finished at %s\n" % stop_scan_time)

# Function to convert string to boolean
def str_to_bool(s):
    return bool(strtobool(str(s)))






# import copy
# import json
# import logging
# import os
# from urllib.parse import unquote_plus
# from distutils.util import strtobool

# import boto3
# import botocore
# import clamav
# import metrics
# from common import AV_DEFINITION_S3_BUCKET
# from common import AV_DEFINITION_S3_PREFIX
# from common import AV_DELETE_INFECTED_FILES
# from common import AV_PROCESS_ORIGINAL_VERSION_ONLY
# from common import AV_SCAN_START_METADATA
# from common import AV_SCAN_START_SNS_ARN
# from common import AV_SIGNATURE_METADATA
# from common import AV_STATUS_CLEAN
# from common import AV_STATUS_INFECTED
# from common import AV_STATUS_METADATA
# from common import AV_STATUS_SNS_ARN
# from common import AV_STATUS_SNS_PUBLISH_CLEAN
# from common import AV_STATUS_SNS_PUBLISH_INFECTED
# from common import AV_TIMESTAMP_METADATA
# from common import create_dir
# from common import get_timestamp

# infected_notification = os.environ['infected_notification']
# infected_sns_topic_arn = os.environ['infected_sns_topic_arn']
# scan_start_sns_arn = os.environ['infected_sns_topic_arn']
# All_Notification= os.environ['All_Notification']
# All_Notification_arn= os.environ['All_Notification_arn']
# #ninad
# quarantine_bucket = os.environ['quarantine_bucket']
# is_quarantine = os.environ['is_quarantine']


# logger = logging.getLogger()
# logger.setLevel(logging.INFO)

# s3 = boto3.client('s3')

# def event_object(event, event_source="s3"):

#     # SNS events are slightly different
#     if event_source.upper() == "SNS":
#         event = json.loads(event["Records"][0]["Sns"]["Message"])

#     # Break down the record
#     records = event["Records"]
#     if len(records) == 0:
#         raise Exception("No records found in event!")
#     record = records[0]

#     s3_obj = record["s3"]

#     # Get the bucket name
#     if "bucket" not in s3_obj:
#         raise Exception("No bucket found in event!")
#     bucket_name = s3_obj["bucket"].get("name", None)

#     # Get the key name
#     if "object" not in s3_obj:
#         raise Exception("No key found in event!")
#     key_name = s3_obj["object"].get("key", None)

#     if key_name:
#         key_name = unquote_plus(key_name)

#     # Ensure both bucket and key exist
#     if (not bucket_name) or (not key_name):
#         raise Exception("Unable to retrieve object from event.\n{}".format(event))

#     # Create and return the object
#     s3 = boto3.resource("s3")
#     return s3.Object(bucket_name, key_name)


# def verify_s3_object_version(s3, s3_object):
#     # validate that we only process the original version of a file, if asked to do so
#     # security check to disallow processing of a new (possibly infected) object version
#     # while a clean initial version is getting processed
#     # downstream services may consume latest version by mistake and get the infected version instead
#     bucket_versioning = s3.BucketVersioning(s3_object.bucket_name)
#     if bucket_versioning.status == "Enabled":
#         bucket = s3.Bucket(s3_object.bucket_name)
#         versions = list(bucket.object_versions.filter(Prefix=s3_object.key))
#         if len(versions) > 1:
#             raise Exception(
#                 "Detected multiple object versions in %s.%s, aborting processing"
#                 % (s3_object.bucket_name, s3_object.key)
#             )
#     else:
#         # misconfigured bucket, left with no or suspended versioning
#         raise Exception(
#             "Object versioning is not enabled in bucket %s" % s3_object.bucket_name
#         )


# def get_local_path(s3_object, local_prefix):
#     return os.path.join(local_prefix, s3_object.bucket_name, s3_object.key)


# # def delete_s3_object(s3_object):
# #     try:
# #         s3_object.delete()
# #     except Exception:
# #         raise Exception(
# #             "Failed to delete infected file: %s.%s"
# #             % (s3_object.bucket_name, s3_object.key)
# #         )
# #     else:
# #         print("Infected file deleted: %s.%s" % (s3_object.bucket_name, s3_object.key))


# #ninad
# def after_scan_action(scan_result,quarantine_bucket,is_quarantine,source_bucket_name,object_key,source ):
#     scan_result = scan_result
#     source_bucket_name = source_bucket_name
#     object_key = object_key
#     source = source
#     quarantine_bucket = quarantine_bucket
#     is_quarantine = is_quarantine

#     s3 = boto3.resource('s3')
#     logger = logging.getLogger()
#     logger.setLevel(logging.INFO)

#     # Get the object's metadata to check for the infected tag

#     print(f"Inputs for after scan action received: {quarantine_bucket} {is_quarantine} {source_bucket_name} {object_key} {source}")
    
#     # response = s3.head_object(Bucket=source_bucket_name, Key=object_key)
#     # metadata = response['Metadata']

#     # Check if the object has the infected tag
#     # if 'infected' in metadata and is_quarantine == True:
#     if scan_result == "INFECTED" and is_quarantine == "True":
        
        
#         # Quarantine the object in another bucket
#         print("Inside after scan lambda if statement")
#         try:
#             response = s3.meta.client.copy(source, quarantine_bucket, object_key)
#             logger.info("File copied to the quarantine bucket successfully!")
#             # Delete the object from source bucket
#             # s3.delete_object(Bucket=source_bucket_name, Key=object_key)
#             s3.Object(source_bucket_name, object_key).delete()
#             return {
#                 'statusCode': 200,
#                 'body': f'Deleted object {object_key} from bucket {source_bucket_name}'
#             }

#         # except boto3.exceptions.ClientError as error:
#         except botocore.exceptions.ClientError as error:
#             logger.error("There was an error copying the file to the quarantine bucket and deleting from source bucket")
#             print('Error Message: {}'.format(error))

#     # elif 'infected' in metadata and is_quarantine == False:
#     elif scan_result == "INFECTED" and is_quarantine == "false":
#         # Delete the object
#         # s3.delete_object(Bucket=source_bucket_name, Key=object_key)
#         s3.Object(source_bucket_name, object_key).delete()
#         return {
#             'statusCode': 200,
#             'body': f'Deleted object {object_key} from bucket {source_bucket_name}'
#         }
#     else:
#         return {
#             'statusCode': 404,
#             'body': f'Object {object_key} in bucket {source_bucket_name} does not have the infected tag'
#         }


# def set_av_metadata(s3_object, scan_result, scan_signature, timestamp):
#     content_type = s3_object.content_type
#     metadata = s3_object.metadata
#     metadata[AV_SIGNATURE_METADATA] = scan_signature
#     metadata[AV_STATUS_METADATA] = scan_result
#     metadata[AV_TIMESTAMP_METADATA] = timestamp
#     s3_object.copy(
#         {"Bucket": s3_object.bucket_name, "Key": s3_object.key},
#         ExtraArgs={
#             "ContentType": content_type,
#             "Metadata": metadata,
#             "MetadataDirective": "REPLACE",
#         },
#     )
    


# def set_av_tags(s3_client, s3_object, scan_result, scan_signature, timestamp):
#     curr_tags = s3_client.get_object_tagging(
#         Bucket=s3_object.bucket_name, Key=s3_object.key
#     )["TagSet"]
#     new_tags = copy.copy(curr_tags)
#     for tag in curr_tags:
#         if tag["Key"] in [
#             AV_SIGNATURE_METADATA,
#             AV_STATUS_METADATA,
#             AV_TIMESTAMP_METADATA,
#         ]:
#             new_tags.remove(tag)
#     new_tags.append({"Key": AV_SIGNATURE_METADATA, "Value": scan_signature})
#     new_tags.append({"Key": AV_STATUS_METADATA, "Value": scan_result})
#     new_tags.append({"Key": AV_TIMESTAMP_METADATA, "Value": timestamp})
#     s3_client.put_object_tagging(
#         Bucket=s3_object.bucket_name, Key=s3_object.key, Tagging={"TagSet": new_tags}
#     )


# def sns_start_scan(sns_client, s3_object, scan_start_sns_arn, timestamp):
#     message = {
#         "bucket": s3_object.bucket_name,
#         "key": s3_object.key,
#         "version": s3_object.version_id,
#         AV_SCAN_START_METADATA: True,
#         AV_TIMESTAMP_METADATA: timestamp,
#     }
#     sns_client.publish(
#         TargetArn=scan_start_sns_arn,
#         Message=json.dumps({"default": json.dumps(message)}),
#         MessageStructure="json",
#     )


# def sns_scan_results(
#     sns_client, s3_object, sns_arn, scan_result, scan_signature, timestamp
# ):
#     # Don't publish if scan_result is CLEAN and CLEAN results should not be published
#     if scan_result == AV_STATUS_CLEAN and not str_to_bool(AV_STATUS_SNS_PUBLISH_CLEAN):
#         return
#     # Don't publish if scan_result is INFECTED and INFECTED results should not be published
#     if scan_result == AV_STATUS_INFECTED and not str_to_bool(
#         AV_STATUS_SNS_PUBLISH_INFECTED
#     ):
#         return
#     message = {
#         "bucket": s3_object.bucket_name,
#         "key": s3_object.key,
#         "version": s3_object.version_id,
#         AV_SIGNATURE_METADATA: scan_signature,
#         AV_STATUS_METADATA: scan_result,
#         AV_TIMESTAMP_METADATA: get_timestamp(),
#     }
#     sns_client.publish(
#         TargetArn=sns_arn,
#         Message=json.dumps({"default": json.dumps(message)}),
#         MessageStructure="json",
#         MessageAttributes={
#             AV_STATUS_METADATA: {"DataType": "String", "StringValue": scan_result},
#             AV_SIGNATURE_METADATA: {
#                 "DataType": "String",
#                 "StringValue": scan_signature,
#             },
#         },
#     )


# def lambda_handler(event, context):
#     s3 = boto3.resource("s3")
#     s3_client = boto3.client("s3")
#     sns_client = boto3.client("sns")
#     #ninad
#       #input required for after_scan_action function
#     source_bucket_name = event['Records'][0]['s3']['bucket']['name']
#     object_key = event['Records'][0]['s3']['object']['key']
#     source = {'Bucket': source_bucket_name, 'Key': object_key}

#     # Get some environment variables
#     ENV = os.getenv("ENV", "")
#     EVENT_SOURCE = os.getenv("EVENT_SOURCE", "S3")
    

#     start_time = get_timestamp()
#     print("Script starting at %s\n" % (start_time))
#     s3_object = event_object(event, event_source=EVENT_SOURCE)
#     s3_key = os.path.join(s3_object.bucket_name, s3_object.key)

#     if str_to_bool(AV_PROCESS_ORIGINAL_VERSION_ONLY):
#         verify_s3_object_version(s3, s3_object)

#     # Publish the start time of the scan
#     if AV_SCAN_START_SNS_ARN not in [None, ""]:
#         start_scan_time = get_timestamp()
#         sns_start_scan(sns_client, s3_object, scan_start_sns_arn, start_scan_time)

#     file_path = get_local_path(s3_object, "/tmp")
#     create_dir(os.path.dirname(file_path))
#     s3_object.download_file(file_path)

#     to_download = clamav.update_defs_from_s3(
#         s3_client, AV_DEFINITION_S3_BUCKET, AV_DEFINITION_S3_PREFIX
#     )

#     for download in to_download.values():
#         s3_path = download["s3_path"]
#         local_path = download["local_path"]
#         print("Downloading definition file %s from s3://%s" % (local_path, s3_path))
#         s3.Bucket(AV_DEFINITION_S3_BUCKET).download_file(s3_path, local_path)
#         print("Downloading definition file %s complete!" % (local_path))
#     scan_result, scan_signature = clamav.scan_file(file_path)
#     print(
#         "Scan of s3://%s resulted in %s\n"
#         % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result)
#     )

#     if All_Notification == "true":
#         print("File is scanned ! Send notification.")
#         sns_client = boto3.client('sns')

#     # Replace 'YOUR_TOPIC_ARN' with the actual ARN of your SNS topic
        

#     # Your message content
#         scan_message = "Scan of s3://%s resulted in %s\n" % (os.path.join(s3_object.bucket_name, s3_object.key), scan_result)

#     # Send message to SNS topic
#         response = sns_client.publish(
#             TopicArn=All_Notification_arn,
#             Message=scan_message,
#             Subject="Scan File Result"
#         )

#     print(f"Message sent to SNS Topic: {All_Notification_arn}")    

#     if scan_result == "INFECTED" and infected_notification == "true":
#         print("File is infected! Send notification.")
#         sns_client = boto3.client('sns')

#     # Replace 'YOUR_TOPIC_ARN' with the actual ARN of your SNS topic
        

#     # Your message content
#         message = message = f"File is infected! Send .\nS3 Key: {s3_key}"

#     # Send message to SNS topic
#         response = sns_client.publish(
#             TopicArn=infected_sns_topic_arn,
#             Message=message,
#             Subject="Infected File Alert"
#         )

#     print(f"Message sent to SNS Topic: {infected_sns_topic_arn}")      

#     result_time = get_timestamp()
#     # Set the properties on the object with the scan results
#     if "AV_UPDATE_METADATA" in os.environ:
#         set_av_metadata(s3_object, scan_result, scan_signature, result_time)
#     set_av_tags(s3_client, s3_object, scan_result, scan_signature, result_time)

#     # Publish the scan results
#     if AV_STATUS_SNS_ARN not in [None, ""]:
#         sns_scan_results(
#             sns_client,
#             s3_object,
#             AV_STATUS_SNS_ARN,
#             scan_result,
#             scan_signature,
#             result_time,
#         )

#     metrics.send(
#         env=ENV, bucket=s3_object.bucket_name, key=s3_object.key, status=scan_result
#     )
#     # Delete downloaded file to free up room on re-usable lambda function container
#     try:
#         os.remove(file_path)
#     except OSError:
#         pass
#     #ninad
#     # if str_to_bool(AV_DELETE_INFECTED_FILES) and scan_result == AV_STATUS_INFECTED:
#         # delete_s3_object(s3_object)
    
#     print(f"Inputs for after scan action: {scan_result} {quarantine_bucket} {is_quarantine} {source_bucket_name} {object_key} {source}")  

#     after_scan_action(scan_result,quarantine_bucket,is_quarantine,source_bucket_name,object_key,source)    
#     # after_scan_action(quarantine_bucket,is_quarantine,source_bucket_name,object_key,source)  
#     stop_scan_time = get_timestamp()
#     print("Script finished at %s\n" % stop_scan_time)


# def str_to_bool(s):
#     return bool(strtobool(str(s)))


# -*- coding: utf-8 -*-
# Upside Travel, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


