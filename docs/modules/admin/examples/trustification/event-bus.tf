# IAM

resource "aws_iam_user" "event-bus" {
  name = "event-bus-${var.environment}"
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_access_key" "event-bus" {
  user = aws_iam_user.event-bus.name
}

resource "kubernetes_secret" "event-bus-credentials" {
  metadata {
    name      = "event-bus-credentials"
    namespace = var.namespace
  }

  data = {
    aws_access_key_id     = aws_iam_access_key.storage.id
    aws_secret_access_key = aws_iam_access_key.storage.secret
  }

  type = "Opaque"
}

data "aws_iam_policy_document" "event-bus" {
  statement {
    effect    = "Allow"
    actions   = ["sqs:GetQueueUrl", "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"]
    resources = [for v in local.document_types : "arn:aws:sqs:*:*:${v}-*-${var.environment}"]
  }
}

resource "aws_iam_policy" "event-bus" {
  name        = "event-bus-policy-${var.environment}"
  description = "Policies for event-bus access"
  policy      = data.aws_iam_policy_document.event-bus.json
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_user_policy_attachment" "event-bus-attach" {
  user       = aws_iam_user.event-bus.name
  policy_arn = aws_iam_policy.event-bus.arn
}

# SQS

data "aws_iam_policy_document" "event-bus-queue" {
  for_each = local.document_types

  statement {
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["sqs:SendMessage"]
    resources = ["arn:aws:sqs:*:*:*"]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.stored-topic[each.key].arn]
    }
  }
}

resource "aws_sqs_queue" "stored" {
  for_each = local.document_types

  name                      = "${each.key}-stored-${var.environment}"
  message_retention_seconds = 300
  policy                    = data.aws_iam_policy_document.event-bus-queue[each.key].json
  tags                      = {
    Environment = var.environment
  }
}

resource "aws_sqs_queue" "guac" {
  for_each = local.document_types

  name                      = "${each.key}-guac-${var.environment}"
  message_retention_seconds = 300
  policy                    = data.aws_iam_policy_document.event-bus-queue[each.key].json
  tags                      = {
    Environment = var.environment
  }
}

resource "aws_sqs_queue" "indexed" {
  for_each = local.document_types

  name                      = "${each.key}-indexed-${var.environment}"
  message_retention_seconds = 300
  policy                    = data.aws_iam_policy_document.event-bus-queue[each.key].json
  tags                      = {
    Environment = var.environment
  }
}

resource "aws_sqs_queue" "failed" {
  for_each = local.document_types

  name                      = "${each.key}-failed-${var.environment}"
  message_retention_seconds = 1209600
  policy                    = data.aws_iam_policy_document.event-bus-queue[each.key].json
  tags                      = {
    Environment = var.environment
  }
}

# SNS

data "aws_iam_policy_document" "event-bus-topic" {
  for_each = local.document_types

  statement {
    effect = "Allow"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["SNS:Publish"]
    resources = ["arn:aws:sns:*:*:*"]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.bucket[each.key].arn]
    }
  }
}

resource "aws_sns_topic" "stored-topic" {
  for_each = local.document_types

  name   = "${each.key}-stored-${var.environment}"
  policy = data.aws_iam_policy_document.event-bus-topic[each.key].json
  tags   = {
    Environment = var.environment
  }
}

# S3 -> SNS

resource "aws_s3_bucket_notification" "notification_sns" {
  for_each = local.document_types

  bucket = aws_s3_bucket.bucket[each.key].id

  topic {
    topic_arn = aws_sns_topic.stored-topic[each.key].arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
}

# SNS -> SQS

resource "aws_sns_topic_subscription" "indexer_subscription" {
  for_each = local.document_types

  protocol             = "sqs"
  raw_message_delivery = true
  topic_arn            = aws_sns_topic.stored-topic[each.key].arn
  endpoint             = aws_sqs_queue.stored[each.key].arn
}

resource "aws_sns_topic_subscription" "exporter_subscription" {
  for_each = local.document_types

  protocol             = "sqs"
  raw_message_delivery = true
  topic_arn            = aws_sns_topic.stored-topic[each.key].arn
  endpoint             = aws_sqs_queue.guac[each.key].arn
}
