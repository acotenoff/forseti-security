
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Rules engine for Bucket acls"""
from collections import namedtuple
import itertools
import re

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type.forwarding_rule import ForwardingRule
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc,differing-param-doc
# pylint: disable=missing-yield-type-doc,redundant-returns-doc


LOGGER = log_util.get_logger(__name__)


# TODO: move this to utils since it's used in more that one engine
def escape_and_globify(pattern_string):
    """Given a pattern string with a glob, create actual regex pattern.

    To require > 0 length glob, change the "*" to ".+". This is to handle
    strings like "*@company.com". (THe actual regex would probably be
    ".*@company.com", except that we don't want to match zero-length
    usernames before the "@".)

    Args:
        pattern_string: The pattern string of which to make a regex.

    Returns:
    The pattern string, escaped except for the "*", which is
    transformed into ".+" (match on one or more characters).
    """

    return '^{}$'.format(re.escape(pattern_string).replace('\\*', '.+'))


class ForwardingRuleRulesEngine(bre.BaseRulesEngine):
    """Rules engine for bucket acls"""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path: file location of rules
        """
        super(ForwardingRuleRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self):
        """Build BucketsRuleBook from the rules definition file."""
        self.rule_book = ForwardingRuleRulesBook(self._load_rule_definitions())

    # pylint: disable=arguments-differ
    def find_policy_violations(self, forwarding_rule,
                               force_rebuild=False):
        """Determine whether forwarding rule violates rules."""
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        matched = False
        for rule in resource_rules:
            matched = rule.find_match(forwarding_rule) or matched

        if not matched:
            return self.RuleViolation(
                violation_type='FORWARDING_RULE_VIOLATION',
                load_balancing_scheme=forwarding_rule.load_balancing_scheme,
                target=forwarding_rule.target,
                port_range=forwarding_rule.port_range,
                port=forwarding_rule.ports,
                ip_protocol=forwarding_rule.ip_protocol,
                ip_address=forwarding_rule.ip_address)

        else:
            return []

    # Rule violation.
    # rule_name: string
    # rule_index: int
    # violation_type: FORWARDING_RULE_VIOLATION
    # target: string
    # load_balancing_scheme: string
    # port_range: string
    # port: string
    # ip_protocol: string
    # ip_address: string
    RuleViolation = namedtuple('RuleViolation',
                               [
                                'violation_type', 'target',
                                'load_balancing_scheme', 'port_range',
                                'port', 'ip_protocol', 'ip_address'])

    def add_rules(self, rules):
        """Add rules to the rule book."""
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class ForwardingRuleRulesBook(bre.BaseRuleBook):
    """The RuleBook for bucket acls resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs: rule definitons
        """
        super(ForwardingRuleRulesBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book"""
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def: A dictionary containing rule definition properties.
            rule_index: The index of the rule from the rule definitions.
            Assigned automatically when the rule book is built.

        Raises:

        """

        target = rule_def.get('target')
        mode = rule_def.get('mode')
        load_balancing_scheme = rule_def.get('load_balancing_scheme')
        port_range = rule_def.get('port_range')
        port = rule_def.get('port')
        ip_address = rule_def.get('ip_address')
        ip_protocol = rule_def.get('ip_protocol')
        if (target is None) or (mode is None) or (load_balancing_scheme is None) or\
               ((port_range is None and port is None)) or (ip_address is None) or (ip_protocol is None):
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_def.get('name')))

        rule_def_resource = {'target': target,
                             'mode': mode,
                             'load_balancing_scheme': load_balancing_scheme,
                             'port_range': port_range,
                             'ip_address': ip_address,
                             'ip_protocol': ip_protocol,
                             'port': port, }

        rule = Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rules=rule_def_resource)

        resource_rules = self.resource_rules_map.get(rule_index)
        if not resource_rules:
            self.resource_rules_map[rule_index] = rule

    def get_resource_rules(self):
        """Get all the resource rules for (resource, RuleAppliesTo.*).

        Args:
            resource: The resource to find in the ResourceRules map.

        Returns:
            A list of ResourceRules.
        """
        resource_rules = []

        for resource_rule in self.resource_rules_map:
            resource_rules.append(self.resource_rules_map[resource_rule])

        return resource_rules


class Rule(object):
    """Rule properties from the rule definition file.
    Also finds violations.
    """

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name: Name of the loaded rule
            rule_index: The index of the rule from the rule definitions
            rules: The rules from the file
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    def find_match(self, forwarding_rule):
        """Find forwarding rule policy acl violations in the rule book.

        Args:
            forwarding_rule: forwarding rule resource

        Returns:
            Returns RuleViolation named tuple
        """
        ip_bool = forwarding_rule.ip_address == self.rules['ip_address']
        scheme_bool = forwarding_rule.load_balancing_scheme == self.rules['load_balancing_scheme']
        # only one of port or port range will be populated by the rule
        port_bool = forwarding_rule.port_range == self.rules['port_range'] \
            if self.rules['port_range'] \
            else forwarding_rule.ports == self.rules['port']
        protocol_bool = forwarding_rule.ip_protocol == self.rules['ip_protocol']

        matched = (
            (ip_bool) and
            (scheme_bool) and
            (port_bool) and
            (protocol_bool))
        return matched
