"""Clean fixture: AWS's own canonical example credential pair, already
suppressed by the maintainer with the detect-secrets pragma convention --
anonymized from awslabs/mcp's dynamodb-mcp-server model_validation_utils.py."""


class DynamoDBClientConfig:
    """Configuration for DynamoDB Local client setup."""

    DUMMY_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'  # pragma: allowlist secret
    DUMMY_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'  # pragma: allowlist secret
    DEFAULT_REGION = 'us-east-1'
