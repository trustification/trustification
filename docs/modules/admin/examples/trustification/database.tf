variable "cluster-vpc-id" {
  type        = string
  description = "The VPC ID of the cluster. Used to connect the RDS instance to the same subnet."
}

data "aws_vpc" "cluster" {
  id = var.cluster-vpc-id
}

data "aws_subnets" "cluster-private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.cluster.id]
  }
  tags = {
    "kubernetes.io/role/internal-elb" = ""
  }
}

resource "aws_db_subnet_group" "database" {
  name       = "database-${var.environment}"
  subnet_ids = data.aws_subnets.cluster-private.ids
}

variable "db-master-user" {
  type        = string
  default     = "postgres"
  description = "Username of the master user of the database"
}

variable "db-user" {
  type        = string
  default     = "guac"
  description = "Username of the guac user of the database"
}

locals {
  # name of the database:
  # > * Must contain 1 to 63 letters, numbers, or underscores.
  # > * Must begin with a letter. Subsequent characters can be letters, underscores, or digits (0-9).
  # > * Can't be a word reserved by the specified database engine
  db-name = "guac_${var.environment}"
}

resource "random_password" "guac-db-admin-password" {
  length  = 32
  # some special characters are limited
  special = false
}

resource "random_password" "guac-db-user-password" {
  length  = 32
  # some special characters are limited
  special = false
}

resource "kubernetes_secret" "postgresql-admin-credentials" {
  metadata {
    name      = "postgresql-admin-credentials"
    namespace = var.namespace
  }

  data = {
    "db.user"     = var.db-master-user
    "db.password" = random_password.guac-db-admin-password.result
    "db.name"     = "postgres"
    "db.port"     = aws_db_instance.guac.port
    "db.host"     = aws_db_instance.guac.address
  }

  type = "Opaque"
}

resource "kubernetes_secret" "postgresql-credentials" {
  metadata {
    name      = "postgresql-credentials"
    namespace = var.namespace
  }

  data = {
    "db.user"     = var.db-user
    "db.password" = random_password.guac-db-user-password.result
    "db.name"     = local.db-name
    "db.port"     = aws_db_instance.guac.port
    "db.host"     = aws_db_instance.guac.address
  }

  type = "Opaque"
}

resource "aws_db_instance" "guac" {

  db_subnet_group_name = aws_db_subnet_group.database.name

  apply_immediately = true

  allocated_storage     = 10
  max_allocated_storage = 100

  db_name             = "postgres"
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.m7g.large"
  username            = var.db-master-user
  password            = random_password.guac-db-admin-password.result
  ca_cert_identifier  = "rds-ca-2019"
  skip_final_snapshot = true

  availability_zone = var.availability-zone
}
