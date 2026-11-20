#!/bin/bash
# WSTG-CONF-11: one bucket is left world-readable, one is correctly private.
set -eu

awslocal s3api create-bucket --bucket acme-public-assets
awslocal s3api put-public-access-block --bucket acme-public-assets \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
awslocal s3api put-bucket-acl --bucket acme-public-assets --acl public-read
awslocal s3api put-bucket-policy --bucket acme-public-assets --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::acme-public-assets", "arn:aws:s3:::acme-public-assets/*"]
  }]
}'

printf 'id,email,ssn\n1,admin@acme.internal,000-11-2222\n2,alice@acme.internal,000-33-4444\n' \
  | awslocal s3 cp - s3://acme-public-assets/customers.csv
printf 'DB_PASSWORD=Sup3rS3cretPortalPW\n' \
  | awslocal s3 cp - s3://acme-public-assets/portal.env

awslocal s3api create-bucket --bucket acme-private-backups
awslocal s3api put-bucket-acl --bucket acme-private-backups --acl private
printf -- '-- private dump\n' | awslocal s3 cp - s3://acme-private-backups/db-dump.sql

echo "s3 bootstrap complete"