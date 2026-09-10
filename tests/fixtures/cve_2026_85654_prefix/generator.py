# Trimmed verbatim from awslabs/mcp @ cdd87a8e28cff01da21387cb7ff444d8d2ffedb4 -- the
# parent of the fix merge, i.e. the VULNERABLE shape behind CVE-2026-85654 / GHSA-35jj-hwvm-792x.
# Path: src/dynamodb-mcp-server/awslabs/dynamodb_mcp_server/cdk_generator/generator.py
# Copyright Amazon.com, Inc. or its affiliates. Apache License, Version 2.0.
# Trims: license header, unrelated imports/methods, and the case-helper bodies. The
# Environment(...) call is byte-for-byte the line the scanner flagged
# (ecoscan-artifacts/report-awslabs_mcp.md, finding 4daab31b00b0).
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
