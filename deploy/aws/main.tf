terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "bombastic" {
  bucket = "bombastic"
  force_destroy = true
}

resource "aws_s3_bucket" "vexination" {
  bucket = "vexination"
  force_destroy = true
}

data "aws_iam_policy_document" "queue" {
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
      values   = [aws_s3_bucket.bombastic.arn, aws_s3_bucket.vexination.arn]
    }
  }
}

resource "aws_s3_bucket_notification" "sbom_notification" {
  bucket = aws_s3_bucket.bombastic.id

  queue {
    queue_arn = aws_sqs_queue.sbom-stored.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
}

resource "aws_s3_bucket_notification" "vex_notification" {
  bucket = aws_s3_bucket.vexination.id

  queue {
    queue_arn = aws_sqs_queue.vex-stored.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
}

resource "aws_sqs_queue" "sbom-stored" {
  name                      = "sbom-stored"
  policy = data.aws_iam_policy_document.queue.json
}

resource "aws_sqs_queue" "sbom-indexed" {
  name                      = "sbom-indexed"
  policy = data.aws_iam_policy_document.queue.json
}

resource "aws_sqs_queue" "sbom-failed" {
  name                      = "sbom-failed"
  policy = data.aws_iam_policy_document.queue.json
}

resource "aws_sqs_queue" "vex-stored" {
  name                      = "vex-stored"
  policy = data.aws_iam_policy_document.queue.json
}

resource "aws_sqs_queue" "vex-indexed" {
  name                      = "vex-indexed"
  policy = data.aws_iam_policy_document.queue.json
}

resource "aws_sqs_queue" "vex-failed" {
  name                      = "vex-failed"
  policy = data.aws_iam_policy_document.queue.json
}
