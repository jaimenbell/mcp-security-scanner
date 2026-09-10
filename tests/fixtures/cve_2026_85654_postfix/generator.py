# Trimmed verbatim from awslabs/mcp @ 46ca139f27020e1b54b549d136138c6dc3ac84e2 -- the merge of
# PR #4384 (2026-08-13, dynamodb-mcp-server v2.1.6), i.e. the FIXED shape for CVE-2026-85654.
# Path: src/dynamodb-mcp-server/awslabs/dynamodb_mcp_server/cdk_generator/generator.py
# Copyright Amazon.com, Inc. or its affiliates. Apache License, Version 2.0.
# The fix did NOT touch the Environment(...) call: autoescape stays off, which is correct for
# a code template. It escaped the interpolations in templates/stack.ts.j2 and added
# identifier validation in _to_camel_case (elided here). Same trims as the prefix fixture.
"""CDK project generator for DynamoDB data models."""

from jinja2 import Environment, FileSystemLoader
from pathlib import Path


STACK_TEMPLATE_NAME = 'stack.ts.j2'


class CdkGenerator:
    """Generates CDK projects from DynamoDB data model JSON files."""

    def __init__(self):
        """Initialize the generator.

        The templates directory is determined internally based on the module location.
        """
        self.templates_dir = Path(__file__).parent / 'templates'
        self.jinja_env = Environment(  # nosec B701 - Content is NOT HTML and NOT served
            loader=FileSystemLoader(str(self.templates_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
            autoescape=False,
        )
        self.jinja_env.filters['to_camel_case'] = self._to_camel_case
        self.jinja_env.filters['to_pascal_case'] = self._to_pascal_case

    def generate(self, data_model, stack_class_name: str) -> str:
        """Render the stack template. (Upstream writes it to disk and runs `cdk init`.)"""
        template = self.jinja_env.get_template(STACK_TEMPLATE_NAME)
        return template.render(data_model=data_model, stack_class_name=stack_class_name)

    def _to_camel_case(self, table_name: str) -> str:  # body elided; not under test
        return table_name

    def _to_pascal_case(self, table_name: str) -> str:  # body elided; not under test
        return table_name
