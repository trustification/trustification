# IAM user

resource "aws_iam_user" "storage" {
  name = "storage-${var.environment}"
  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_access_key" "storage" {
  user = aws_iam_user.storage.name
}

resource "kubernetes_secret" "storage-credentials" {
  metadata {
    name      = "storage-credentials"
    namespace = var.namespace
  }

  data = {
    aws_access_key_id     = aws_iam_access_key.storage.id
    aws_secret_access_key = aws_iam_access_key.storage.secret
  }

  type = "Opaque"
}

data "aws_iam_policy_document" "storage" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [for v in local.document_types : "arn:aws:s3:::${v}-${var.environment}"]
  }
}

resource "aws_iam_policy" "storage" {
  name        = "storage-policy-${var.environment}"
  description = "Policies for storage access"
  policy      = data.aws_iam_policy_document.storage.json
  tags        = {
    Environment = var.environment
  }
}

resource "aws_iam_user_policy_attachment" "storage-attach" {
  user       = aws_iam_user.storage.name
  policy_arn = aws_iam_policy.storage.arn
}

# S3 buckets

resource "aws_s3_bucket" "bucket" {
  for_each = local.document_types

  bucket        = "${each.key}-${var.environment}"
  force_destroy = true
  tags          = {
    Environment = var.environment
  }
}

data "aws_iam_policy_document" "bucket_policy" {
  for_each = local.document_types

  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::${each.key}-${var.environment}/*",
      "arn:aws:s3:::${each.key}-${var.environment}",
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.storage.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "storage-bucket-policy" {
  for_each = local.document_types

  bucket = aws_s3_bucket.bucket[each.key].id
  policy = data.aws_iam_policy_document.bucket_policy[each.key].json
}

