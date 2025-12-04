I have the following call of this opennext module:

module "opennext" {
  source = "github.com/metaltoad/terraform-aws-opennext?ref=main"

  use_tagcache           = true
  prefix                 = "${var.repo_name_short}-${var.environment}" # Prefix for all created resources
  opennext_build_path    = var.opennext_path                           # Path to your .open-next folder
  hosted_zone_id         = ""
  create_route53_records = false
  server_options = {
    package = {
      source_dir = "${var.opennext_path}/server-functions/default"
      output_dir = "${var.opennext_path}/.build/"
    },
    function = {
      runtime                        = "nodejs18.x"
      memory_size                    = 2048
      reserved_concurrent_executions = var.lambda_concurrency["server"]
      timeout                        = 60
    }
    iam_policy = [
      {
        effect    = "Allow"
        actions   = ["s3:GetObject", "s3:PutObject", "s3:ListObjects", "s3:DeleteObject"]
        resources = ["arn:aws:s3:::${var.repo_name_short}-${var.environment}-assets", "arn:aws:s3:::${var.repo_name_short}-${var.environment}-assets/*", ]
      },
    ]
  }

  image_optimization_options = {
    package = {
      source_dir = "${var.opennext_path}/image-optimization-function"
      output_dir = "${var.opennext_path}/.build/"
    },
    function = {
      runtime                        = "nodejs20.x"
      reserved_concurrent_executions = var.lambda_concurrency["image"]
      memory_size                    = 512
      timeout                        = 60
    }
  }
  revalidation_options = {
    package = {
      source_dir = "${var.opennext_path}/revalidation-function"
      output_dir = "${var.opennext_path}/.build/"
    },
    function = {
      runtime                        = "nodejs20.x"
      reserved_concurrent_executions = var.lambda_concurrency["revalidation"]
      memory_size                    = 512
      timeout                        = 60
    }
  }
  warmer_options = {
    package = {
      source_dir = "${var.opennext_path}/warmer-function"
      output_dir = "${var.opennext_path}/.build/"
    },
    function = {
      runtime                        = "nodejs20.x"
      reserved_concurrent_executions = var.lambda_concurrency["warmer"]
      memory_size                    = 512
      timeout                        = 60
    }
  }
  cloudfront = {
    shield_enabled = true
    aliases = [
      var.full_domain
    ]
    assets_paths = [
      "/fonts/*",
      "/wc-player/*",
      "ads.txt",
      "manifest.json",
      "robots.txt",
      "/news/rss",
      "artists.xml",
      "sitemap.xml"
    ]
    acm_certificate_arn = module.cert.cert_arn
    custom_waf = {
      arn = aws_wafv2_web_acl.webacl.arn
    }
  }
}

I need to add the following to this code:

root_redirect = [
  var.root_redirect
]

I will be populating this variable in this .tfvars 

base_domain  = "grammy.com"
full_domain  = "dev.grammy.com"
live_domain  = "dev-live.grammy.com"
route53_role = "arn:aws:iam::892950194893:role/grammy-opennext-allow-route53-role-778879313709"
set_dns      = true
set_password = true
lambda_concurrency = {
  server       = -1
  image        = -1
  revalidation = -1
  warmer       = -1
}
root_redirect = "grammy.staging.ncp.consulting"

This is the main implemantation of this module:

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.14.1"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  aws_region = var.region != null ? var.region : data.aws_region.current.region
}

/**
 * Assets & Cache S3 Bucket
 **/
module "assets" {
  source       = "./modules/opennext-assets"
  region       = local.aws_region
  default_tags = var.default_tags

  prefix                    = "${var.prefix}-assets"
  assets_path               = "${local.opennext_abs_path}/assets"
  cache_path                = "${local.opennext_abs_path}/cache"
  server_function_role_arn  = module.server_function.lambda_role.arn
  static_asset_cache_config = var.static_asset_cache_config
}

resource "aws_dynamodb_table" "tag_cache" {
  count        = var.use_tagcache == true ? 1 : 0
  name         = "${var.prefix}-tagcache"
  hash_key     = "path"
  range_key    = "tag"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "path"
    type = "S"
  }
  attribute {
    name = "tag"
    type = "S"
  }
  attribute {
    name = "revalidatedAt"
    type = "N"
  }
  server_side_encryption {
    enabled = true
  }

  global_secondary_index {
    hash_key           = "path"
    name               = "revalidate"
    non_key_attributes = []
    projection_type    = "ALL"
    range_key          = "revalidatedAt"
    read_capacity      = 0
    write_capacity     = 0
  }
}


/**
 * Next.js Server Function
 **/
module "server_function" {
  source       = "./modules/opennext-lambda"
  region       = local.aws_region
  default_tags = var.default_tags

  prefix = "${var.prefix}-nextjs-server"

  function_name                  = local.server_options.function.function_name
  description                    = local.server_options.function.description
  handler                        = local.server_options.function.handler
  runtime                        = local.server_options.function.runtime
  architectures                  = local.server_options.function.architectures
  memory_size                    = local.server_options.function.memory_size
  timeout                        = local.server_options.function.timeout
  publish                        = local.server_options.function.publish
  dead_letter_config             = local.server_options.function.dead_letter_config
  reserved_concurrent_executions = local.server_options.function.reserved_concurrent_executions
  code_signing_config            = local.server_options.function.code_signing_config
  log_group                      = local.server_options.log_group


  source_dir = local.server_options.package.source_dir
  output_dir = local.server_options.package.output_dir

  vpc_id                       = local.server_options.networking.vpc_id
  subnet_ids                   = local.server_options.networking.subnet_ids
  security_group_ingress_rules = local.server_options.networking.security_group_ingress_rules
  security_group_egress_rules  = local.server_options.networking.security_group_egress_rules

  environment_variables = local.server_options.environment_variables
  iam_policy_statements = local.server_options.iam_policy_statements
}


/**
 * Image Optimization Function
 **/
module "image_optimization_function" {
  source       = "./modules/opennext-lambda"
  region       = local.aws_region
  default_tags = var.default_tags

  prefix = "${var.prefix}-nextjs-image-optimization"

  function_name                  = local.image_optimization_options.function.function_name
  description                    = local.image_optimization_options.function.description
  handler                        = local.image_optimization_options.function.handler
  runtime                        = local.image_optimization_options.function.runtime
  architectures                  = local.image_optimization_options.function.architectures
  memory_size                    = local.image_optimization_options.function.memory_size
  timeout                        = local.image_optimization_options.function.timeout
  publish                        = local.image_optimization_options.function.publish
  dead_letter_config             = local.image_optimization_options.function.dead_letter_config
  reserved_concurrent_executions = local.image_optimization_options.function.reserved_concurrent_executions
  code_signing_config            = local.image_optimization_options.function.code_signing_config
  log_group                      = local.image_optimization_options.log_group

  source_dir = local.image_optimization_options.package.source_dir
  output_dir = local.image_optimization_options.package.output_dir

  vpc_id                       = local.image_optimization_options.networking.vpc_id
  subnet_ids                   = local.image_optimization_options.networking.subnet_ids
  security_group_ingress_rules = local.image_optimization_options.networking.security_group_ingress_rules
  security_group_egress_rules  = local.image_optimization_options.networking.security_group_egress_rules

  environment_variables = local.image_optimization_options.environment_variables
  iam_policy_statements = local.image_optimization_options.iam_policy_statements
}

/**
 * ISR Revalidation Function
 **/
module "revalidation_function" {
  source       = "./modules/opennext-lambda"
  region       = local.aws_region
  default_tags = var.default_tags

  prefix = "${var.prefix}-nextjs-revalidation"

  function_name                  = local.revalidation_options.function.function_name
  description                    = local.revalidation_options.function.description
  handler                        = local.revalidation_options.function.handler
  runtime                        = local.revalidation_options.function.runtime
  architectures                  = local.revalidation_options.function.architectures
  memory_size                    = local.revalidation_options.function.memory_size
  timeout                        = local.revalidation_options.function.timeout
  publish                        = local.revalidation_options.function.publish
  dead_letter_config             = local.revalidation_options.function.dead_letter_config
  reserved_concurrent_executions = local.revalidation_options.function.reserved_concurrent_executions
  code_signing_config            = local.revalidation_options.function.code_signing_config
  log_group                      = local.revalidation_options.log_group

  source_dir = local.revalidation_options.package.source_dir
  output_dir = local.revalidation_options.package.output_dir

  vpc_id                       = local.revalidation_options.networking.vpc_id
  subnet_ids                   = local.revalidation_options.networking.subnet_ids
  security_group_ingress_rules = local.revalidation_options.networking.security_group_ingress_rules
  security_group_egress_rules  = local.revalidation_options.networking.security_group_egress_rules

  environment_variables = local.revalidation_options.environment_variables
  iam_policy_statements = local.revalidation_options.iam_policy_statements
}

/**
 * ISR Revalidation Queue
 **/
module "revalidation_queue" {
  source       = "./modules/opennext-revalidation-queue"
  prefix       = "${var.prefix}-revalidation-queue"
  region       = local.aws_region
  default_tags = var.default_tags

  aws_account_id            = data.aws_caller_identity.current.account_id
  revalidation_function_arn = module.revalidation_function.lambda_function.arn
}

/**
 * Warmer Function
 **/

module "warmer_function" {
  source       = "./modules/opennext-lambda"
  region       = local.aws_region
  default_tags = var.default_tags

  prefix                            = "${var.prefix}-nextjs-warmer"
  create_eventbridge_scheduled_rule = true


  function_name                  = local.warmer_options.function.function_name
  description                    = local.warmer_options.function.description
  handler                        = local.warmer_options.function.handler
  runtime                        = local.warmer_options.function.runtime
  architectures                  = local.warmer_options.function.architectures
  memory_size                    = local.warmer_options.function.memory_size
  timeout                        = local.warmer_options.function.timeout
  publish                        = local.warmer_options.function.publish
  dead_letter_config             = local.warmer_options.function.dead_letter_config
  reserved_concurrent_executions = local.warmer_options.function.reserved_concurrent_executions
  code_signing_config            = local.warmer_options.function.code_signing_config
  log_group                      = local.warmer_options.log_group

  source_dir = local.warmer_options.package.source_dir
  output_dir = local.warmer_options.package.output_dir

  vpc_id                       = local.warmer_options.networking.vpc_id
  subnet_ids                   = local.warmer_options.networking.subnet_ids
  security_group_ingress_rules = local.warmer_options.networking.security_group_ingress_rules
  security_group_egress_rules  = local.warmer_options.networking.security_group_egress_rules

  environment_variables = local.warmer_options.environment_variables
  iam_policy_statements = local.warmer_options.iam_policy_statements
}

/**
 * CloudFront -> CloudWatch Logs
 **/
module "cloudfront_logs" {
  source       = "./modules/cloudfront-logs"
  region       = local.aws_region
  default_tags = var.default_tags

  log_group_name  = "${var.prefix}-cloudfront-logs"
  log_bucket_name = "${var.prefix}-cloudfront-logs"
  retention       = 365
}

/**
 * Next.js CloudFront Distribution
 **/
module "cloudfront" {
  source       = "./modules/opennext-cloudfront"
  prefix       = "${var.prefix}-cloudfront"
  region       = local.aws_region
  default_tags = var.default_tags

  price_class = local.cloudfront.price_class

  shield_enabled = local.cloudfront.shield_enabled

  comment                       = local.cloudfront.comment
  logging_bucket_domain_name    = module.cloudfront_logs.logs_s3_bucket.bucket_regional_domain_name
  assets_origin_access_identity = module.assets.cloudfront_origin_access_identity.cloudfront_access_identity_path

  origins = {
    assets_bucket               = module.assets.assets_bucket.bucket_regional_domain_name
    server_function             = "${module.server_function.lambda_function_url.url_id}.lambda-url.${local.aws_region}.on.aws"
    image_optimization_function = "${module.image_optimization_function.lambda_function_url.url_id}.lambda-url.${local.aws_region}.on.aws"
  }

  aliases               = local.cloudfront.aliases
  acm_certificate_arn   = local.cloudfront.acm_certificate_arn
  assets_paths          = local.cloudfront.assets_paths
  custom_headers        = local.cloudfront.custom_headers
  geo_restriction       = local.cloudfront.geo_restriction
  cors                  = local.cloudfront.cors
  hsts                  = local.cloudfront.hsts
  cache_policy          = local.cloudfront.cache_policy
  remove_headers_config = local.cloudfront.remove_headers_config

  custom_waf                = local.cloudfront.custom_waf
  waf_logging_configuration = local.cloudfront.waf_logging_configuration
}

And this is the implementation of the cloudfront module:

locals {
  server_origin_id             = "${var.prefix}-server-origin"
  assets_origin_id             = "${var.prefix}-assets-origin"
  image_optimization_origin_id = "${var.prefix}-image-optimization-origin"
}

resource "aws_cloudfront_function" "host_header_function" {
  name    = "${var.prefix}-preserve-host"
  runtime = "cloudfront-js-1.0"
  comment = "Next.js Function for Preserving Original Host"
  publish = true
  code    = <<EOF
function handler(event) {
  var request = event.request;
  request.headers["x-forwarded-host"] = request.headers.host;
  return request;
}
EOF
}

data "aws_cloudfront_origin_request_policy" "origin_request_policy" {
  count = var.origin_request_policy == null ? 1 : 0
  name  = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_origin_request_policy" "origin_request_policy" {
  count = var.origin_request_policy == null ? 0 : 1
  name  = "${var.prefix}-origin-request-policy"

  cookies_config {
    cookie_behavior = var.origin_request_policy.cookies_config.cookie_behavior
    cookies {
      items = var.origin_request_policy.cookies_config.items
    }
  }

  headers_config {
    header_behavior = var.origin_request_policy.headers_config.header_behavior

    headers {
      items = concat(
        ["accept", "rsc", "next-router-prefetch", "next-router-state-tree", "x-prerender-revalidate"],
        coalesce(var.origin_request_policy.headers_config.items, [])
      )
    }
  }

  query_strings_config {
    query_string_behavior = var.origin_request_policy.query_strings_config.query_string_behavior
    query_strings {
      items = var.origin_request_policy.query_strings_config.items
    }
  }
}

resource "aws_cloudfront_cache_policy" "cache_policy" {
  name = "${var.prefix}-cache-policy"

  default_ttl = var.cache_policy.default_ttl
  min_ttl     = var.cache_policy.min_ttl
  max_ttl     = var.cache_policy.max_ttl

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = var.cache_policy.enable_accept_encoding_brotli
    enable_accept_encoding_gzip   = var.cache_policy.enable_accept_encoding_gzip

    cookies_config {
      cookie_behavior = var.cache_policy.cookies_config.cookie_behavior

      dynamic "cookies" {
        for_each = var.cache_policy.cookies_config.items != null ? [true] : []

        content {
          items = var.cache_policy.cookies_config.items
        }
      }
    }

    headers_config {
      header_behavior = var.cache_policy.headers_config.header_behavior

      headers {
        items = concat(
          ["accept", "rsc", "next-router-prefetch", "next-router-state-tree", "x-prerender-revalidate"],
          coalesce(var.cache_policy.headers_config.items, [])
        )
      }
    }

    query_strings_config {
      query_string_behavior = var.cache_policy.query_strings_config.query_string_behavior

      dynamic "query_strings" {
        for_each = var.cache_policy.query_strings_config.items != null ? [true] : []

        content {
          items = var.cache_policy.query_strings_config.items
        }
      }
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "response_headers_policy" {
  name    = "${var.prefix}-response-headers-policy"
  comment = "${var.prefix} Response Headers Policy"

  cors_config {
    origin_override                  = var.cors.origin_override
    access_control_allow_credentials = var.cors.allow_credentials

    access_control_allow_headers {
      items = var.cors.allow_headers
    }

    access_control_allow_methods {
      items = var.cors.allow_methods
    }

    access_control_allow_origins {
      items = var.cors.allow_origins
    }
  }

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = var.hsts.access_control_max_age_sec
      include_subdomains         = var.hsts.include_subdomains
      override                   = var.hsts.override
      preload                    = var.hsts.preload
    }
  }

  dynamic "custom_headers_config" {
    for_each = length(var.custom_headers) > 0 ? [true] : []

    content {
      dynamic "items" {
        for_each = toset(var.custom_headers)

        content {
          header   = items.header
          override = items.override
          value    = items.value
        }
      }
    }
  }
  dynamic "remove_headers_config" {
    for_each = length(var.remove_headers_config.items) > 0 ? [true] : []

    content {
      dynamic "items" {
        for_each = toset(var.remove_headers_config.items)

        content {
          header = items.value
        }
      }
    }
  }
}

resource "aws_cloudfront_distribution" "distribution" {
  provider        = aws.global
  price_class     = var.price_class
  enabled         = true
  is_ipv6_enabled = true
  comment         = coalesce(var.comment, "${var.prefix} - CloudFront Distribution for Next.js Application")
  aliases         = var.aliases
  web_acl_id      = try(var.custom_waf.arn, aws_wafv2_web_acl.cloudfront_waf[0].arn, null)

  logging_config {
    include_cookies = false
    # bucket          = module.cloudfront_logs.logs_s3_bucket.bucket_regional_domain_name
    bucket = var.logging_bucket_domain_name
    prefix = length(var.aliases) > 0 ? var.aliases[0] : null
  }

  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }

  restrictions {
    geo_restriction {
      restriction_type = var.geo_restriction.restriction_type
      locations        = var.geo_restriction.locations
    }
  }

  # S3 Bucket Origin
  origin {
    domain_name = var.origins.assets_bucket
    origin_id   = local.assets_origin_id
    origin_path = "/assets"

    s3_origin_config {
      origin_access_identity = var.assets_origin_access_identity
    }

    origin_shield {
      enabled = var.shield_enabled
      origin_shield_region = var.region
    }
  }

  # Server Function Origin
  origin {
    domain_name = var.origins.server_function
    # domain_name = "${module.server_function.lambda_function_url_id}.lambda-url.eu-west-2.on.aws"
    origin_id = local.server_origin_id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    origin_shield {
      enabled = var.shield_enabled
      origin_shield_region = var.region
    }
  }

  # Image Optimization Function Origin
  origin {
    # domain_name = "${module.image_optimization_function.lambda_function_url_id}.lambda-url.eu-west-2.on.aws"
    domain_name = var.origins.image_optimization_function
    origin_id   = local.image_optimization_origin_id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    origin_shield {
      enabled = var.shield_enabled
      origin_shield_region = var.region
    }
  }

  # Behaviour - Hashed Static Files (/_next/static/*)
  ordered_cache_behavior {
    path_pattern     = "/_next/static/*"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.assets_origin_id

    response_headers_policy_id = aws_cloudfront_response_headers_policy.response_headers_policy.id
    cache_policy_id            = aws_cloudfront_cache_policy.cache_policy.id
    origin_request_policy_id = try(
      data.aws_cloudfront_origin_request_policy.origin_request_policy[0].id,
      aws_cloudfront_origin_request_policy.origin_request_policy[0].id
    )

    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern     = "/_next/image"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.image_optimization_origin_id

    response_headers_policy_id = aws_cloudfront_response_headers_policy.response_headers_policy.id
    cache_policy_id            = aws_cloudfront_cache_policy.cache_policy.id
    origin_request_policy_id = try(
      data.aws_cloudfront_origin_request_policy.origin_request_policy[0].id,
      aws_cloudfront_origin_request_policy.origin_request_policy[0].id
    )

    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern     = "/_next/data/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.server_origin_id

    response_headers_policy_id = aws_cloudfront_response_headers_policy.response_headers_policy.id
    cache_policy_id            = aws_cloudfront_cache_policy.cache_policy.id
    origin_request_policy_id = try(
      data.aws_cloudfront_origin_request_policy.origin_request_policy[0].id,
      aws_cloudfront_origin_request_policy.origin_request_policy[0].id
    )

    compress               = true
    viewer_protocol_policy = "redirect-to-https"

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.host_header_function.arn
    }
  }

  ordered_cache_behavior {
    path_pattern     = "/api/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "PATCH", "POST", "DELETE"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.server_origin_id

    response_headers_policy_id = aws_cloudfront_response_headers_policy.response_headers_policy.id
    cache_policy_id            = aws_cloudfront_cache_policy.cache_policy.id
    origin_request_policy_id = try(
      data.aws_cloudfront_origin_request_policy.origin_request_policy[0].id,
      aws_cloudfront_origin_request_policy.origin_request_policy[0].id
    )

    compress               = true
    viewer_protocol_policy = "redirect-to-https"

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.host_header_function.arn
    }
  }

  ordered_cache_behavior {
    path_pattern     = "/favicon.ico"
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.assets_origin_id

    response_headers_policy_id = aws_cloudfront_response_headers_policy.response_headers_policy.id
    cache_policy_id            = aws_cloudfront_cache_policy.cache_policy.id
    origin_request_policy_id = try(
      data.aws_cloudfront_origin_request_policy.origin_request_policy[0].id,
      aws_cloudfront_origin_request_policy.origin_request_policy[0].id
    )

    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  dynamic "ordered_cache_behavior" {
    for_each = toset(var.assets_paths)

    content {
      path_pattern     = ordered_cache_behavior.value
      allowed_methods  = ["GET", "HEAD", "OPTIONS"]
      cached_methods   = ["GET", "HEAD", "OPTIONS"]
      target_origin_id = local.assets_origin_id

      response_headers_policy_id = aws_cloudfront_response_headers_policy.response_headers_policy.id
      cache_policy_id            = aws_cloudfront_cache_policy.cache_policy.id
      origin_request_policy_id = try(
        data.aws_cloudfront_origin_request_policy.origin_request_policy[0].id,
        aws_cloudfront_origin_request_policy.origin_request_policy[0].id
      )

      compress               = true
      viewer_protocol_policy = "redirect-to-https"
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "PATCH", "POST", "DELETE"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.server_origin_id

    response_headers_policy_id = aws_cloudfront_response_headers_policy.response_headers_policy.id
    cache_policy_id            = aws_cloudfront_cache_policy.cache_policy.id
    origin_request_policy_id = try(
      data.aws_cloudfront_origin_request_policy.origin_request_policy[0].id,
      aws_cloudfront_origin_request_policy.origin_request_policy[0].id
    )

    compress               = true
    viewer_protocol_policy = "redirect-to-https"

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.host_header_function.arn
    }
  }
}

I need, when I pass a value instead of Null to the root_redirect, I need the module to create a new origin, cache, and behavior for "/". The origin should be the url passed to root_redirect, the chache should be no managed cache, the name of the origin can be grammy-opennext-development-cloudfront-root-origin