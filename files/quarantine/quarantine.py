import boto3
import botocore
import os
import logging


logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')

def lambda_handler(event, context):
    
    quarantine_bucket = os.environ['quarantine_bucket']
    is_quarantine = os.environ['is_quarantine']
    source_bucket_name = event['Records'][0]['s3']['bucket']['name']
    object_key = event['Records'][0]['s3']['object']['key']
    logger.info("Object Key:", object_key)
    source = {'Bucket': source_bucket_name, 'Key': object_key}

    # Get the object's metadata to check for the infected tag
    response = s3.head_object(Bucket=source_bucket_name, Key=object_key)
    metadata = response['Metadata']

    # Check if the object has the infected tag
    if 'infected' in metadata and is_quarantine == True:
        # Quarantine the object in another bucket
        try:
            response = s3.meta.client.copy(source, quarantine_bucket, object_key)
            logger.info("File copied to the quarantine bucket successfully!")
            # Delete the object from source bucket
            s3.delete_object(Bucket=source_bucket_name, Key=object_key)
            return {
                'statusCode': 200,
                'body': f'Deleted object {object_key} from bucket {source_bucket_name}'
            }

        except botocore.exceptions.ClientError as error:
            logger.error("There was an error copying the file to the quarantine bucket and deleting from source bucket")
            print('Error Message: {}'.format(error))
            
            
    elif 'infected' in metadata and is_quarantine == False:
        # Delete the object
        s3.delete_object(Bucket=source_bucket_name, Key=object_key)
        return {
            'statusCode': 200,
            'body': f'Deleted object {object_key} from bucket {source_bucket_name}'
        }
    else:
        return {
            'statusCode': 404,
            'body': f'Object {object_key} in bucket {source_bucket_name} does not have the infected tag'
        }

