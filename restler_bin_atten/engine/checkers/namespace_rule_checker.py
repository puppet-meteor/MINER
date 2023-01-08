# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

""" Implements logic for user namespace violation checker. """
from __future__ import print_function

from checkers.checker_base import *

import itertools

from engine.bug_bucketing import BugBuckets
import engine.dependencies as dependencies
import engine.primitives as primitives
from utils.logger import raw_network_logging as RAW_LOGGING
from engine.core.request_utilities import NO_TOKEN_SPECIFIED
from engine.core.request_utilities import NO_SHADOW_TOKEN_SPECIFIED

import engine.core.datacollect as datacollect  # lyu

STATIC_OAUTH_TOKEN = 'static_oauth_token'

class NameSpaceRuleChecker(CheckerBase):
    """ Checker for Namespace rule violations. """
    def __init__(self, req_collection, fuzzing_requests):
        CheckerBase.__init__(self, req_collection, fuzzing_requests)

    def apply(self, rendered_sequence, lock):
        """ Applies check for namespace rule violations.

        @param rendered_sequence: Object containing the rendered sequence information
        @type  rendered_sequence: RenderedSequence
        @param lock: Lock object used to sync more than one fuzzing job
        @type  lock: thread.Lock

        @return: None
        @rtype : None

        """
        if not rendered_sequence.valid:
            return
        self._sequence = rendered_sequence.sequence
        self._custom_mutations = self._req_collection.candidate_values_pool.candidate_values

        # We need more than one user to apply this checker.
        self._authentication_method = self._get_authentication_method()
        if self._authentication_method not\
                in [STATIC_OAUTH_TOKEN, primitives.REFRESHABLE_AUTHENTICATION_TOKEN]:
            return

        self._namespace_rule()

    def _render_original_sequence_start(self, seq):
        """ Helper to re-render the start of the original sequence to create
        the appropriate dynamic objects. Does not send the final target request.

        @param seq: The sequence whose last request we will try to render.
        @type  seq: Sequence Class object.

        @return: None
        @rtype : None

        """
        self._checker_log.checker_print("\nRe-rendering start of original sequence")
        RAW_LOGGING("Re-rendering start of original sequence")

        has_500 = False
        has_400 = False
        has_200 = True

        for request in seq.requests[:-1]:
            rendered_data, parser, list_values, list_values_default, whethergen, datacollect.seq_which = request.render_current_lyu2(self._req_collection.candidate_values_pool, 0)
            rendered_data = seq.resolve_dependencies(rendered_data)
            response = self._send_request(parser, rendered_data)
            request_utilities.call_response_parser(parser, response)
            if response:
                if response.status_code[0] == '2':
                    datacollect.namespace_rule_checker_former_200 += 1
                elif response.status_code[0] == '5':
                    datacollect.namespace_rule_checker_former_500 += 1
                elif response.status_code[0] == '4':
                    datacollect.namespace_rule_checker_former_400 += 1


                if response.status_code[0] == '5':
                    has_500 = True
                    has_200 = False
                elif response.status_code[0] == '4':
                    has_400 = True
                    has_200 = False

                if has_500 and not has_400:
                    datacollect.namespace_rule_checker_part_500 += 1
                elif has_400 and not has_500:
                    datacollect.namespace_rule_checker_part_400 += 1
                elif has_400 and has_500:
                    datacollect.namespace_rule_checker_part_non200 += 1
                elif has_200:
                    datacollect.namespace_rule_checker_part_200 += 1

                if '?' in list_values_default:  # otherwise there is no node to mutate
                    if response.status_code[0] == '2':
                        if whethergen == 1:
                            datacollect.gen200 += 1
                        else:
                            datacollect.nogen200 += 1

                        datacollect.countid += 1
                        tmp_list_values_default = "".join(list_values_default)
                        if len(datacollect.requestid) == 0:
                            datacollect.requestid[tmp_list_values_default] = 0
                        elif tmp_list_values_default  not in datacollect.requestid:
                            datacollect.requestid[tmp_list_values_default] = max(datacollect.requestid.values()) + 1

                        countid = datacollect.countid
                        request_name = datacollect.requestid[tmp_list_values_default]
                        start_loc = datacollect.reverseindex(list_values_default, '?')
                        statelyu = 0
                        tmp_status_code = 'P'
                        for lyui in range(start_loc, len(list_values_default)):
                            if list_values_default[lyui][0] == ' ':
                                break   # finish find node + mutation results in _default

                            if  list_values_default[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values_default[lyui]
                                if tmpnode not in list_values:
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(['deletebylyu']) # operator: delete
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)
                                else:   # tmpnode in prev_list_values
                                    tmplist = []
                                    tmplist2 = []
                                    start_loc2 = list_values.index(tmpnode)
                                    for lyuj in range(start_loc2 + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    for lyuj in range(lyui + 1, len(list_values_default)):
                                        if list_values_default[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist2.append(list_values_default[lyuj])
                                    if tmplist != tmplist2:
                                        tmpset = [countid, request_name]
                                        tmpset.append(tmpnode)  # node
                                        tmpset.append(tmplist)  # mutated value
                                        tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                        datacollect.trainingset.append(tmpset)
                        start_loc = datacollect.reverseindex(list_values, '?')
                        statelyu = 0
                        for lyui in range(start_loc, len(list_values)):
                            if list_values[lyui] == ' ':
                                break  # finish find node + mutation results in prev_list_values

                            if list_values[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values[lyui]
                                if tmpnode not in list_values_default:
                                    tmplist = []
                                    for lyuj in range(lyui + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(tmplist)  # mutated value
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)

                        if datacollect.seq_which == 1:
                            datacollect.seq_gen200 += 1
                        elif datacollect.seq_which == 2:
                            datacollect.seq_nogen200 += 1

                    elif response.status_code[0] == '5':
                        if whethergen == 1:
                            datacollect.gen500 += 1
                        else:
                            datacollect.nogen500 += 1

                        datacollect.countid += 1
                        tmp_list_values_default = "".join(list_values_default)
                        if len(datacollect.requestid) == 0:
                            datacollect.requestid[tmp_list_values_default] = 0
                        elif tmp_list_values_default  not in datacollect.requestid:
                            datacollect.requestid[tmp_list_values_default] = max(datacollect.requestid.values()) + 1

                        countid = datacollect.countid
                        request_name = datacollect.requestid[tmp_list_values_default]
                        start_loc = datacollect.reverseindex(list_values_default, '?')
                        statelyu = 0
                        tmp_status_code = 'E'
                        for lyui in range(start_loc, len(list_values_default)):
                            if list_values_default[lyui][0] == ' ':
                                break   # finish find node + mutation results in _default

                            if  list_values_default[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values_default[lyui]
                                if tmpnode not in list_values:
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(['deletebylyu']) # operator: delete
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)
                                else:   # tmpnode in prev_list_values
                                    tmplist = []
                                    tmplist2 = []
                                    start_loc2 = list_values.index(tmpnode)
                                    for lyuj in range(start_loc2 + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    for lyuj in range(lyui + 1, len(list_values_default)):
                                        if list_values_default[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist2.append(list_values_default[lyuj])
                                    if tmplist != tmplist2:
                                        tmpset = [countid, request_name]
                                        tmpset.append(tmpnode)  # node
                                        tmpset.append(tmplist)  # mutated value
                                        tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                        datacollect.trainingset.append(tmpset)
                        start_loc = datacollect.reverseindex(list_values, '?')
                        statelyu = 0
                        for lyui in range(start_loc, len(list_values)):
                            if list_values[lyui] == ' ':
                                break  # finish find node + mutation results in prev_list_values

                            if list_values[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values[lyui]
                                if tmpnode not in list_values_default:
                                    tmplist = []
                                    for lyuj in range(lyui + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(tmplist)  # mutated value
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)

                                # else tmpnode in prev_list_values_default-> have done

                        if datacollect.seq_which == 1:
                            datacollect.seq_gen500 += 1
                        elif datacollect.seq_which == 2:
                            datacollect.seq_nogen500 += 1

                    elif response.status_code[0] == '4':
                        if datacollect.seq_which == 1:
                            datacollect.seq_gen400 += 1
                        elif datacollect.seq_which == 2:
                            datacollect.seq_nogen400 += 1

        if has_500 and not has_400:
            datacollect.namespace_rule_checker_overall_500 += 1
        elif has_400 and not has_500:
            datacollect.namespace_rule_checker_overall_400 += 1
        elif has_400 and has_500:
            datacollect.namespace_rule_checker_overall_non200 += 1
        elif has_200:
            datacollect.namespace_rule_checker_overall_200 += 1 
             

    def _namespace_rule(self):
        """ Try to hijack objects of @param target_types and use them via
        a secondary attacker user.

        @param target_types: The types of the target object to attemp hijack.
        @type  target_types: Set

        @return: None
        @rtype : None

        """
        # For the target types (target dynamic objects), get the latest
        # values which we know will exist due to the previous rendering.
        # We will later on use these old values atop a new rendering.
        hijacked_values = {}
        consumed_types = self._sequence.consumes
        consumed_types = set(itertools.chain(*consumed_types))

        # Exit the checker and do not re-render if nothing is consumed since
        # the checker will have nothing to work on anyways.
        if not consumed_types:
            return

        # Render only last request if not in exhaustive (expensive) mode.
        # If that last request does not consume anything, stop here.
        if self._mode != 'exhaustive' and not self._sequence.last_request.consumes:
            return

        self._render_original_sequence_start(self._sequence)

        for type in consumed_types:
           hijacked_values[type] = dependencies.get_variable(type)

        self._checker_log.checker_print(f"Hijacked values: {hijacked_values}")
        RAW_LOGGING(f"Hijacked values: {hijacked_values}")


        for i, req in enumerate(self._sequence):
            # Render only last request if not in exhaustive (expensive) mode.
            if self._mode != 'exhaustive' and i != self._sequence.length - 1:
                continue
            # Skip requests that are not consumers.
            if not req.consumes:
                continue
            dependencies.reset_tlb()
            self._render_attacker_subsequence(req)

            # Feed hijacked values.
            for type in hijacked_values:
                dependencies.set_variable(type, hijacked_values[type])
            self._render_hijack_request(req)

    def _render_attacker_subsequence(self, req):
        """ Helper to render attacker user and try to hijack @param target_type
        objects.

        @param req: The hijack request.
        @type  req: Request Class object.

        @return: None
        @rtype : None

        """
        # Render subsequnce up to before any producer of @param consumed_types.
        consumed_types = req.consumes
        for stopping_length, req in enumerate(self._sequence):
            # Stop before producing the target type.
            if req.produces.intersection(consumed_types):
                break

        for i in range(stopping_length):
            request = self._sequence.requests[i]
            rendered_data, parser,list_values, list_values_default, whethergen, datacollect.seq_which = request.render_current_lyu2(self._req_collection.candidate_values_pool, 0)
            rendered_data = self._sequence.resolve_dependencies(rendered_data)
            rendered_data = self._change_user_identity(rendered_data)
            response = self._send_request(parser, rendered_data)
            request_utilities.call_response_parser(parser, response)

            if response:
                if response.status_code[0] == '2':
                    datacollect.namespace_rule_checker_former_200 += 1
                elif response.status_code[0] == '5':
                    datacollect.namespace_rule_checker_former_500 += 1
                elif response.status_code[0] == '4':
                    datacollect.namespace_rule_checker_former_400 += 1

                if '?' in list_values_default:  # otherwise there is no node to mutate
                    if response.status_code[0] == '2':
                        if whethergen == 1:
                            datacollect.gen200 += 1
                        else:
                            datacollect.nogen200 += 1

                        datacollect.countid += 1
                        tmp_list_values_default = "".join(list_values_default)
                        if len(datacollect.requestid) == 0:
                            datacollect.requestid[tmp_list_values_default] = 0
                        elif tmp_list_values_default  not in datacollect.requestid:
                            datacollect.requestid[tmp_list_values_default] = max(datacollect.requestid.values()) + 1

                        countid = datacollect.countid
                        request_name = datacollect.requestid[tmp_list_values_default]
                        start_loc = datacollect.reverseindex(list_values_default, '?')
                        statelyu = 0
                        tmp_status_code = 'P'
                        for lyui in range(start_loc, len(list_values_default)):
                            if list_values_default[lyui][0] == ' ':
                                break   # finish find node + mutation results in _default

                            if  list_values_default[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values_default[lyui]
                                if tmpnode not in list_values:
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(['deletebylyu']) # operator: delete
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)
                                else:   # tmpnode in prev_list_values
                                    tmplist = []
                                    tmplist2 = []
                                    start_loc2 = list_values.index(tmpnode)
                                    for lyuj in range(start_loc2 + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    for lyuj in range(lyui + 1, len(list_values_default)):
                                        if list_values_default[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist2.append(list_values_default[lyuj])
                                    if tmplist != tmplist2:
                                        tmpset = [countid, request_name]
                                        tmpset.append(tmpnode)  # node
                                        tmpset.append(tmplist)  # mutated value
                                        tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                        datacollect.trainingset.append(tmpset)
                        start_loc = datacollect.reverseindex(list_values, '?')
                        statelyu = 0
                        for lyui in range(start_loc, len(list_values)):
                            if list_values[lyui] == ' ':
                                break  # finish find node + mutation results in prev_list_values

                            if list_values[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values[lyui]
                                if tmpnode not in list_values_default:
                                    tmplist = []
                                    for lyuj in range(lyui + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(tmplist)  # mutated value
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)

                        if datacollect.seq_which == 1:
                            datacollect.seq_gen200 += 1
                        elif datacollect.seq_which == 2:
                            datacollect.seq_nogen200 += 1

                    elif response.status_code[0] == '5':
                        if whethergen == 1:
                            datacollect.gen500 += 1
                        else:
                            datacollect.nogen500 += 1

                        datacollect.countid += 1
                        tmp_list_values_default = "".join(list_values_default)
                        if len(datacollect.requestid) == 0:
                            datacollect.requestid[tmp_list_values_default] = 0
                        elif tmp_list_values_default  not in datacollect.requestid:
                            datacollect.requestid[tmp_list_values_default] = max(datacollect.requestid.values()) + 1

                        countid = datacollect.countid
                        request_name = datacollect.requestid[tmp_list_values_default]
                        start_loc = datacollect.reverseindex(list_values_default, '?')
                        statelyu = 0
                        tmp_status_code = 'E'
                        for lyui in range(start_loc, len(list_values_default)):
                            if list_values_default[lyui][0] == ' ':
                                break   # finish find node + mutation results in _default

                            if  list_values_default[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values_default[lyui]
                                if tmpnode not in list_values:
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(['deletebylyu']) # operator: delete
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)
                                else:   # tmpnode in prev_list_values
                                    tmplist = []
                                    tmplist2 = []
                                    start_loc2 = list_values.index(tmpnode)
                                    for lyuj in range(start_loc2 + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    for lyuj in range(lyui + 1, len(list_values_default)):
                                        if list_values_default[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist2.append(list_values_default[lyuj])
                                    if tmplist != tmplist2:
                                        tmpset = [countid, request_name]
                                        tmpset.append(tmpnode)  # node
                                        tmpset.append(tmplist)  # mutated value
                                        tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                        datacollect.trainingset.append(tmpset)
                        start_loc = datacollect.reverseindex(list_values, '?')
                        statelyu = 0
                        for lyui in range(start_loc, len(list_values)):
                            if list_values[lyui] == ' ':
                                break  # finish find node + mutation results in prev_list_values

                            if list_values[lyui] in ['?', '&']:
                                statelyu = 0
                                continue
                            if statelyu == 0:
                                statelyu = 1
                                tmpnode = list_values[lyui]
                                if tmpnode not in list_values_default:
                                    tmplist = []
                                    for lyuj in range(lyui + 1, len(list_values)):
                                        if list_values[lyuj][0] in ['&', ' ']:
                                            break
                                        tmplist.append(list_values[lyuj])
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(tmplist)  # mutated value
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)

                                # else tmpnode in prev_list_values_default-> have done
                        if datacollect.seq_which == 1:
                            datacollect.seq_gen500 += 1
                        elif datacollect.seq_which == 2:
                            datacollect.seq_nogen500 += 1

                    elif response.status_code[0] == '4':
                        if datacollect.seq_which == 1:
                            datacollect.seq_gen400 += 1
                        elif datacollect.seq_which == 2:
                            datacollect.seq_nogen400 += 1

        self._checker_log.checker_print("Subsequence rendering up to: {}".\
                            format(stopping_length))
        RAW_LOGGING(f"Subsequence rendering  up to: {stopping_length}")


    def _render_hijack_request(self, req):
        """ Render the last request of the sequence and inspect the status
        code of the response. If it's any of 20x, we have probably hit a bug.

        @param req: The hijack request.
        @type  req: Request Class object.

        @return: None
        @rtype : None

        """
        self._checker_log.checker_print("Hijack request rendering")
        RAW_LOGGING("Hijack request rendering")

        rendered_data, parser, list_values, list_values_default, whethergen = req.render_current_lyu(self._req_collection.candidate_values_pool, 2)
        rendered_data = self._sequence.resolve_dependencies(rendered_data)
        rendered_data = self._change_user_identity(rendered_data)

        response = self._send_request(parser, rendered_data)
        request_utilities.call_response_parser(parser, response)
        if response and self._rule_violation(self._sequence, response):
            self._print_suspect_sequence(self._sequence, response)
            BugBuckets.Instance().update_bug_buckets(
                self._sequence, response.status_code, origin=self.__class__.__name__, reproduce=False
            )

            if response.status_code[0] == '2':
                datacollect.namespace_rule_checker_laster_200 += 1
            elif response.status_code[0] == '5':
                datacollect.namespace_rule_checker_laster_500 += 1
            elif response.status_code[0] == '4':
                datacollect.namespace_rule_checker_laster_400 += 1

            if '?' in list_values_default:  # otherwise there is no node to mutate
                if response.status_code[0] == '2':
                    if whethergen == 1:
                        datacollect.gen200 += 1
                    else:
                        datacollect.nogen200 += 1

                    datacollect.countid += 1
                    tmp_list_values_default = "".join(list_values_default)
                    if len(datacollect.requestid) == 0:
                        datacollect.requestid[tmp_list_values_default] = 0
                    elif tmp_list_values_default  not in datacollect.requestid:
                        datacollect.requestid[tmp_list_values_default] = max(datacollect.requestid.values()) + 1

                    countid = datacollect.countid
                    request_name = datacollect.requestid[tmp_list_values_default]
                    start_loc = datacollect.reverseindex(list_values_default, '?')
                    statelyu = 0
                    tmp_status_code = 'P'
                    for lyui in range(start_loc, len(list_values_default)):
                        if list_values_default[lyui][0] == ' ':
                            break   # finish find node + mutation results in _default

                        if  list_values_default[lyui] in ['?', '&']:
                            statelyu = 0
                            continue
                        if statelyu == 0:
                            statelyu = 1
                            tmpnode = list_values_default[lyui]
                            if tmpnode not in list_values:
                                tmpset = [countid, request_name]
                                tmpset.append(tmpnode)  # node
                                tmpset.append(['deletebylyu']) # operator: delete
                                tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                datacollect.trainingset.append(tmpset)
                            else:   # tmpnode in prev_list_values
                                tmplist = []
                                tmplist2 = []
                                start_loc2 = list_values.index(tmpnode)
                                for lyuj in range(start_loc2 + 1, len(list_values)):
                                    if list_values[lyuj][0] in ['&', ' ']:
                                        break
                                    tmplist.append(list_values[lyuj])
                                for lyuj in range(lyui + 1, len(list_values_default)):
                                    if list_values_default[lyuj][0] in ['&', ' ']:
                                        break
                                    tmplist2.append(list_values_default[lyuj])
                                if tmplist != tmplist2:
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(tmplist)  # mutated value
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)
                    start_loc = datacollect.reverseindex(list_values, '?')
                    statelyu = 0
                    for lyui in range(start_loc, len(list_values)):
                        if list_values[lyui] == ' ':
                            break  # finish find node + mutation results in prev_list_values

                        if list_values[lyui] in ['?', '&']:
                            statelyu = 0
                            continue
                        if statelyu == 0:
                            statelyu = 1
                            tmpnode = list_values[lyui]
                            if tmpnode not in list_values_default:
                                tmplist = []
                                for lyuj in range(lyui + 1, len(list_values)):
                                    if list_values[lyuj][0] in ['&', ' ']:
                                        break
                                    tmplist.append(list_values[lyuj])
                                tmpset = [countid, request_name]
                                tmpset.append(tmpnode)  # node
                                tmpset.append(tmplist)  # mutated value
                                tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                datacollect.trainingset.append(tmpset)

                    if datacollect.seq_which == 1:
                        datacollect.seq_gen200 += 1
                    elif datacollect.seq_which == 2:
                        datacollect.seq_nogen200 += 1

                elif response.status_code[0] == '5':
                    if whethergen == 1:
                        datacollect.gen500 += 1
                    else:
                        datacollect.nogen500 += 1

                    datacollect.countid += 1
                    tmp_list_values_default = "".join(list_values_default)
                    if len(datacollect.requestid) == 0:
                        datacollect.requestid[tmp_list_values_default] = 0
                    elif tmp_list_values_default  not in datacollect.requestid:
                        datacollect.requestid[tmp_list_values_default] = max(datacollect.requestid.values()) + 1

                    countid = datacollect.countid
                    request_name = datacollect.requestid[tmp_list_values_default]
                    start_loc = datacollect.reverseindex(list_values_default, '?')
                    statelyu = 0
                    tmp_status_code = 'E'
                    for lyui in range(start_loc, len(list_values_default)):
                        if list_values_default[lyui][0] == ' ':
                            break   # finish find node + mutation results in _default

                        if  list_values_default[lyui] in ['?', '&']:
                            statelyu = 0
                            continue
                        if statelyu == 0:
                            statelyu = 1
                            tmpnode = list_values_default[lyui]
                            if tmpnode not in list_values:
                                tmpset = [countid, request_name]
                                tmpset.append(tmpnode)  # node
                                tmpset.append(['deletebylyu']) # operator: delete
                                tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                datacollect.trainingset.append(tmpset)
                            else:   # tmpnode in prev_list_values
                                tmplist = []
                                tmplist2 = []
                                start_loc2 = list_values.index(tmpnode)
                                for lyuj in range(start_loc2 + 1, len(list_values)):
                                    if list_values[lyuj][0] in ['&', ' ']:
                                        break
                                    tmplist.append(list_values[lyuj])
                                for lyuj in range(lyui + 1, len(list_values_default)):
                                    if list_values_default[lyuj][0] in ['&', ' ']:
                                        break
                                    tmplist2.append(list_values_default[lyuj])
                                if tmplist != tmplist2:
                                    tmpset = [countid, request_name]
                                    tmpset.append(tmpnode)  # node
                                    tmpset.append(tmplist)  # mutated value
                                    tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                    datacollect.trainingset.append(tmpset)
                    start_loc = datacollect.reverseindex(list_values, '?')
                    statelyu = 0
                    for lyui in range(start_loc, len(list_values)):
                        if list_values[lyui] == ' ':
                            break  # finish find node + mutation results in prev_list_values

                        if list_values[lyui] in ['?', '&']:
                            statelyu = 0
                            continue
                        if statelyu == 0:
                            statelyu = 1
                            tmpnode = list_values[lyui]
                            if tmpnode not in list_values_default:
                                tmplist = []
                                for lyuj in range(lyui + 1, len(list_values)):
                                    if list_values[lyuj][0] in ['&', ' ']:
                                        break
                                    tmplist.append(list_values[lyuj])
                                tmpset = [countid, request_name]
                                tmpset.append(tmpnode)  # node
                                tmpset.append(tmplist)  # mutated value
                                tmpset.append(tmp_status_code)  # status_code: 'P'ass or 'E'rror
                                datacollect.trainingset.append(tmpset)

                            # else tmpnode in prev_list_values_default-> have done

                    if datacollect.seq_which == 1:
                        datacollect.seq_gen500 += 1
                    elif datacollect.seq_which == 2:
                        datacollect.seq_nogen500 += 1

                elif response.status_code[0] == '4':
                    if datacollect.seq_which == 1:
                        datacollect.seq_gen400 += 1
                    elif datacollect.seq_which == 2:
                        datacollect.seq_nogen400 += 1

    def _false_alarm(self, seq, response):
        """ Catches namespace rule violation false alarms that
        occur when a GET request returns an empty list as its body

        @param seq: The sequence to check
        @type  seq: Sequence Class object.
        @param response: Body of response.
        @type  response: Str

        @return: True if false alarm detected
        @rtype : Bool

        """
        try:
            if seq.last_request.method.startswith('GET') and response.body == '[]':
                return True
        except Exception:
            pass

        return False

    def _get_authentication_method(self):
        """ Trys to find out the authentication method used (if any).

        @return: The authenctication methid used.
        @rtype : Str

        """
        try:
            token1 = self._custom_mutations[primitives.CUSTOM_PAYLOAD][STATIC_OAUTH_TOKEN]
            token2 = self._custom_mutations[primitives.SHADOW_VALUES][primitives.CUSTOM_PAYLOAD][STATIC_OAUTH_TOKEN]
            return STATIC_OAUTH_TOKEN
        except Exception:
            pass

        from engine.core.request_utilities import latest_token_value as token1
        from engine.core.request_utilities import latest_shadow_token_value as token2
        if token1 is not NO_TOKEN_SPECIFIED and token2 is not NO_SHADOW_TOKEN_SPECIFIED:
            return primitives.REFRESHABLE_AUTHENTICATION_TOKEN

        return 'ONLY_ONE_USER'

    def _change_user_identity(self, data):
        """ Chandes user identity by substituting original token with shadow
        token.

        @param data: The payload whose token we will substitute
        @param data: Str

        @return: The new payload with the token substituted
        @rtype : Str

        """
        if self._authentication_method == primitives.REFRESHABLE_AUTHENTICATION_TOKEN:
            from engine.core.request_utilities import latest_token_value
            from engine.core.request_utilities import latest_shadow_token_value
            token1 = latest_token_value
            token2 = latest_shadow_token_value
            data = data.replace(token1, token2)
        else:
            shadow_values = self._custom_mutations[primitives.SHADOW_VALUES]
            for shadow_type in shadow_values:
                for shadow_key, shadow_val in shadow_values[shadow_type].items():
                    try:
                        victim_val = self._custom_mutations[shadow_type][shadow_key]
                        # Replace will do nothing if "replaced" value is not found.
                        data = data.replace(victim_val, shadow_val)
                    except Exception as error:
                        print(f"Exception: {error!s}")
                        continue
        return data
