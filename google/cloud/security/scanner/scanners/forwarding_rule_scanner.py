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

"""Scanner for the Bucket acls rules engine."""
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import forwarding_rules_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,differing-param-doc


LOGGER = log_util.get_logger(__name__)


class ForwardingRuleScanner(base_scanner.BaseScanner):
    """Pipeline to forwarding rules  data from DAO"""
    def __init__(self, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
        super(ForwardingRuleScanner, self).__init__(
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp


    def run(self):
        """Runs the data collection."""
        forwarding_rules = forwarding_rules_dao.ForwardingRulesDao().get_forwarding_rules(self.snapshot_timestamp)
        resource_counts = {
            ResourceType.FORWARDING_RULE: len(forwarding_rules),
        }
        return [forwarding_rules], resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, forwarding_rules, rules_engine):
        """Find violations in the policies.

        Args:
            forwarding_rule: Forwarding rule to find violations in
            rules_engine: The rules engine to run.

        Returns:
            A list of violations
        """
        all_violations = []
        LOGGER.info('Finding Forwading Rule violations...')

        for forwarding_rule in list(forwarding_rules):
            LOGGER.debug('%s', forwarding_rule)
            violations = rules_engine.find_policy_violations(
                forwarding_rule)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        print all_violations
        return all_violations
