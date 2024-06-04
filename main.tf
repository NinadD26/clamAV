provider "aws" {
  # region  = var.aws_region
  region  = "us-east-1"
  profile = "SandboxTeamA"
}

locals {
  clamav_update_name        = "update-clamav-definitions"
  clamav_scan_name          = "scan-bucket-file"
  clamav_definitions_bucket = "clamav-definitions"
  layer_name                = "clamav"
  buckets_to_scan2          = "clamavdemo-apsouth1"
}

# -----------------------------
# Datasources
# -----------------------------

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "update" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.clamav_update_name}",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.clamav_update_name}:*"
    ]
    effect = "Allow"
  }
  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetObject",
      "s3:GetObjectTagging",
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging"
    ]
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.clamav_definitions.bucket}",
      "arn:aws:s3:::${aws_s3_bucket.clamav_definitions.bucket}/*"
    ]
    effect = "Allow"
  }
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "scan" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "sns:*"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.clamav_scan_name}",
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.clamav_scan_name}:*",
      "arn:aws:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*",
      #ninad
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.quarantine_function}:*"
    ]
    effect = "Allow"
  }
  statement {
    actions = [
      "s3:ListBucket",
      "s3:GetObject",
      "s3:GetObjectTagging",
      "s3:GetObjectVersion",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
      "s3:DeleteObject",
      "s3:PutObject"
    ]
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.clamav_definitions.bucket}",
      "arn:aws:s3:::${aws_s3_bucket.clamav_definitions.bucket}/*",
      "arn:aws:s3:::${aws_s3_bucket.output_bucket_name.bucket}/*",
      "arn:aws:s3:::${aws_s3_bucket.output_bucket_name.bucket}"
    ]
    effect = "Allow"
  }
  dynamic "statement" {
    for_each = concat(var.buckets_to_scan, [var.quarantine_bucket])

    content {
      actions = [
        "s3:GetObject",
        "s3:GetObjectTagging",
        "s3:GetObjectVersion",
        "s3:PutObjectTagging",
        "s3:DeleteObject",
        "s3:PutObject",
        "s3:PutObjectVersionTagging",

      ]
      resources = [
        format("arn:aws:s3:::%s", statement.value),
        format("arn:aws:s3:::%s/*", statement.value),
        format("arn:aws:s3:::%s", statement.value),
        format("arn:aws:s3:::%s/*", statement.value)
      ]
      effect = "Allow"
    }
  }
}

# -----------------------------
# Create bucket where will be bases with vulnerability stored
# -----------------------------

resource "aws_s3_bucket" "clamav_definitions" {
  bucket_prefix = local.clamav_definitions_bucket
}


resource "aws_s3_bucket" "buckets_to_scan" {
  count = length(var.buckets_to_scan)

  bucket = var.buckets_to_scan[count.index]

}

# -----------------------------
# Create IAM Roles for the Lambdas
# -----------------------------

resource "aws_iam_role" "update" {
  name = local.clamav_update_name

  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}

resource "aws_iam_policy" "update" {
  name = local.clamav_update_name

  policy = data.aws_iam_policy_document.update.json
}

resource "aws_iam_role_policy_attachment" "update" {
  role       = aws_iam_role.update.name
  policy_arn = aws_iam_policy.update.arn
}

resource "aws_iam_role" "scan" {
  name = local.clamav_scan_name

  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}

resource "aws_iam_policy" "scan" {
  name = local.clamav_scan_name

  policy = data.aws_iam_policy_document.scan.json
}

resource "aws_iam_role_policy_attachment" "scan" {
  role       = aws_iam_role.scan.name
  policy_arn = aws_iam_policy.scan.arn
}

# -----------------------------
# Create Lambdas
# -----------------------------

resource "aws_lambda_layer_version" "this" {
  layer_name          = local.layer_name
  filename            = "${path.module}/files/layer.zip"
  compatible_runtimes = [var.lambda_runtime]

  source_code_hash = base64sha256("${path.module}/files/layer.zip")
}

data "archive_file" "zip_the_python" {
  type        = "zip"
  source_dir  = "${path.module}/files/codee/"
  output_path = "${path.module}/files/codee/code.zip"
}

resource "aws_lambda_function" "update_clamav_definitions" {
  filename         = "${path.module}/files/codee/code.zip"
  function_name    = local.clamav_update_name
  role             = aws_iam_role.update.arn
  handler          = var.update_handler
  source_code_hash = base64sha256("${path.module}/files/codee/")
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.update_memory_size

  layers = [aws_lambda_layer_version.this.id]

  environment {
    variables = {
      AV_DEFINITION_S3_BUCKET = aws_s3_bucket.clamav_definitions.bucket
    }
  }
}

data "archive_file" "zip_the_python_1" {
  type        = "zip"
  source_dir  = "${path.module}/files/codee/"
  output_path = "${path.module}/files/codee/code.zip"
}

resource "aws_lambda_function" "scan_file" {
  filename         = "${path.module}/files/codee/code.zip"
  function_name    = local.clamav_scan_name
  role             = aws_iam_role.scan.arn
  handler          = var.scan_handler
  source_code_hash = base64sha256("${path.module}/files/codee/")
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.scan_memory_size

  layers = [aws_lambda_layer_version.this.id]

  environment {
    variables = {
      AV_DEFINITION_S3_BUCKET = aws_s3_bucket.clamav_definitions.bucket
      infected_notification   = var.infected_notification
      infected_sns_topic_arn  = aws_sns_topic.infected_sns_topic[0].arn
      All_Notification        = var.All_Notification
      # All_Notification_arn =length(aws_sns_topic.All_Notification[0].arn) 
      All_Notification_arn = length(aws_sns_topic.All_Notification) > 0 ? aws_sns_topic.All_Notification[0].arn : ""
      # ninad
      #All_Notification_arn = local.all_notification_arn       
      quarantine_bucket = var.quarantine_bucket
      is_quarantine     = "True"
    }
  }
}

#######################################send notification#####################################



###############################################s3 event for send notification
# -----------------------------
# Create Cloudwatch events with Lambda PErmissions
# -----------------------------
resource "aws_cloudwatch_event_rule" "every_three_hours" {
  name                = var.event_name
  description         = var.event_description
  schedule_expression = var.event_schedule_expression
}

resource "aws_cloudwatch_event_target" "update_clamav_definitions" {
  rule      = aws_cloudwatch_event_rule.every_three_hours.name
  target_id = local.clamav_update_name
  arn       = aws_lambda_function.update_clamav_definitions.arn
}

resource "aws_lambda_permission" "allow_cloudwatch_to_update_antivirus" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = var.lambda_action
  function_name = aws_lambda_function.update_clamav_definitions.function_name
  principal     = var.lambda_update_principal
  source_arn    = aws_cloudwatch_event_rule.every_three_hours.arn
}



resource "aws_lambda_permission" "allow_terraform_bucket" {
  count         = length(var.buckets_to_scan)
  statement_id  = "AllowExecutionFromS3Bucket_${element(var.buckets_to_scan, count.index)}"
  action        = var.lambda_action
  function_name = aws_lambda_function.scan_file.arn
  principal     = var.lambda_scan_principal
  source_arn    = "arn:aws:s3:::${element(var.buckets_to_scan, count.index)}"
}

# -----------------------------
# Allow the S3 bucket to send notifications to the lambda function
# -----------------------------

resource "aws_s3_bucket_notification" "new_file_notification" {
  count  = length(var.buckets_to_scan)
  bucket = element(var.buckets_to_scan, count.index)

  lambda_function {
    id                  = 1
    lambda_function_arn = aws_lambda_function.scan_file.arn
    events              = var.bucket_events
  }
}


###########################################################################

# -----------------------------
# Add a policy to the bucket that prevents download of infected files
# -----------------------------
resource "aws_s3_bucket_policy" "buckets_to_scan" {
  count  = length(var.buckets_to_scan)
  bucket = element(var.buckets_to_scan, count.index)

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "NotPrincipal": {
          "AWS": [
              "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
              "arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.scan.name}/${aws_lambda_function.scan_file.function_name}",
              "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.scan.name}"
          ]
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${element(var.buckets_to_scan, count.index)}/*",
      "Condition": {
          "StringNotEquals": {
              "s3:ExistingObjectTag/av-status": "CLEAN"
          }
      }
    }
  ]
}
POLICY
}

#############################################

# -----------------------------
# Create SNS topic
# -----------------------------
resource "aws_sns_topic" "infected_sns_topic" {
  count = var.infected_notification == "true" ? 1 : 0
  name  = var.infected_notification_sns_name
}

data "aws_iam_policy_document" "my_custom_sns_policy_document" {
  count     = var.infected_notification == "true" ? 1 : 0
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        var.account_id,
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.infected_sns_topic[count.index].arn,
    ]

    sid = "__default_statement_ID"
  }
}

resource "aws_sns_topic_policy" "my_sns_topic_policy" {
  count  = var.infected_notification == "true" ? 1 : 0
  arn    = aws_sns_topic.infected_sns_topic[count.index].arn
  policy = data.aws_iam_policy_document.my_custom_sns_policy_document[count.index].json
}

resource "aws_sns_topic_subscription" "Email_sub" {
  count     = var.infected_notification == "true" ? 1 : 0
  topic_arn = aws_sns_topic.infected_sns_topic[count.index].arn
  protocol  = "email"
  endpoint  = var.email_name
}


resource "aws_sns_topic" "All_Notification" {
  count = var.All_Notification == "true" ? 1 : 0
  name  = var.All_Notification_sns_name
}

data "aws_iam_policy_document" "my_custom_sns_policy_document1" {
  count     = var.All_Notification == "true" ? 1 : 0
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        var.account_id,
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.All_Notification[count.index].arn,
    ]

    sid = "__default_statement_ID"
  }
}

resource "aws_sns_topic_policy" "my_sns_topic_policy1" {
  count  = var.create_resources == "true" ? 1 : 0
  arn    = aws_sns_topic.All_Notification[count.index].arn
  policy = data.aws_iam_policy_document.my_custom_sns_policy_document1[count.index].json
}

resource "aws_sns_topic_subscription" "Email_sub1" {
  count     = var.All_Notification == "true" ? 1 : 0
  topic_arn = aws_sns_topic.All_Notification[count.index].arn
  protocol  = "email"
  endpoint  = var.email_name
}

###################################################

resource "aws_s3_bucket" "output_bucket_name" {
  # count  = var.quarantine_object == "true" ? 1 :0
  bucket = var.quarantine_bucket
}


data "archive_file" "zip_the_python_2" {
  type        = "zip"
  source_dir  = "${path.module}/files/quarantine/"
  output_path = "${path.module}/files/quarantine/quarantine.zip"
}





resource "aws_lambda_function" "quarantine_function" {
  # count            = var.quarantine_object == "true" ? 1 :0
  filename         = data.archive_file.zip_the_python_2.output_path
  function_name    = var.quarantine_function
  role             = aws_iam_role.scan.arn
  handler          = var.scan_handler
  # handler          = var.quarantine_handler
  source_code_hash = base64sha256(data.archive_file.zip_the_python_2.output_path)
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.scan_memory_size

  layers = [aws_lambda_layer_version.this.id]
  environment {
    variables = {
      input_bucket_name = join(",",var.buckets_to_scan)
      quarantine_bucket = var.quarantine_bucket
      is_quarantine     = "True"

    }
  }


}

######################################################

# resource "aws_cloudwatch_event_rule" "every_half_hours" {
#   name                = var.event_name_1
#   description         = var.event_description_1
#   schedule_expression = var.event_schedule_expression_1
# }

# resource "aws_cloudwatch_event_target" "event_target_for_quarantine" {
#   rule      = aws_cloudwatch_event_rule.every_half_hours.name
#   target_id = var.quarantine_function
#   arn       = aws_lambda_function.quarantine_function.arn
# }

# resource "aws_lambda_permission" "allow_cloudwatch_to_trigger_lambda" {
#   statement_id  = "AllowExecutionFromCloudWatch"
#   action        = var.lambda_action
#   function_name = aws_lambda_function.quarantine_function.function_name
#   principal     = var.lambda_update_principal
#   source_arn    = aws_cloudwatch_event_rule.every_half_hours.arn
# }

# resource "aws_lambda_permission" "allow_terraform_bucket-2nd" {
#    count         = length(var.quarantine_function)
#   statement_id  = "AllowExecutionFromS3Bucket_${element(var.quarantine_function, count.index)}"
#   action        = var.lambda_action
#  # function_name = aws_lambda_function.scan_file.arn
#   function_name = aws_lambda_function.quarantine_function.arn
#   principal     = var.lambda_scan_principal
#   source_arn    = "arn:aws:s3:::${element(var.quarantine_function, count.index)}"
# }

######################################################