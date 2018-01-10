terraform {
  required_version = "~> 0.11.2"
}

provider "aws" {
  version = "~> 1.6.0"
  region  = "${var.aws_region}"
}
