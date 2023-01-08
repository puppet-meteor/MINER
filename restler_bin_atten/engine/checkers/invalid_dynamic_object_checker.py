# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

""" Implements logic for invalid dynamic object checker. """
from __future__ import print_function

from checkers.checker_base import *
import time
import uuid

from engine.bug_bucketing import BugBuckets
import engine.dependencies as dependencies
import engine.core.sequences as sequences
from utils.logger import raw_network_logging as RAW_LOGGING

import engine.core.datacollect as datacollect  # lyu

class InvalidDynamicObjectChecker(CheckerBase):
    """ Checker for invalid dynamic object violations. """
    # Dictionary used for determining whether or not a request has already
    # been sent for the current generation.
    # { generation : set(request.hex_definitions) }
    generation_executed_requests = dict()

    def __init__(self, req_collection, fuzzing_requests):
        CheckerBase.__init__(self, req_collection, fuzzing_requests)

    def apply(self, rendered_sequence, lock):
        """ Applies check for invalid dynamic object rule violations.

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
        last_request = self._sequence.last_request

        # If the last request is not a consumer then this checker is not applicable
        if not last_request.consumes:
            return

        generation = self._sequence.length

        if InvalidDynamicObjectChecker.generation_executed_requests.get(generation) is None:
            # This is the first time this checker has seen this generation, create empty set of requests
            InvalidDynamicObjectChecker.generation_executed_requests[generation] = set()
        elif last_request.hex_definition in InvalidDynamicObjectChecker.generation_executed_requests[generation]:
            # This request type has already been tested for this generation
            return

        # Add the last request to the generation_executed_requests dictionary for this generation
        InvalidDynamicObjectChecker.generation_executed_requests[generation].add(last_request.hex_definition)

        # Get the current rendering of the sequence, which will be the valid rendering of the last request
        last_rendering, last_request_parser, list_values, list_values_default, whethergen = last_request.render_current_lyu(self._req_collection.candidate_values_pool, 1)

        # Execute the sequence up until the last request
        new_seq = self._execute_start_of_sequence()
        # Add the last request of the sequence to the new sequence
        new_seq = new_seq + sequences.Sequence(last_request)

        # Get and send each invalid request
        self._checker_log.checker_print("\nSending invalid request(s):")
        for data in self._prepare_invalid_requests(last_rendering):
            self._checker_log.checker_print(repr(data))
            response = self._send_request(last_request_parser, data)
            request_utilities.call_response_parser(last_request_parser, response)
            if response and self._rule_violation(new_seq, response):
                # Append the data that we just sent to the sequence's sent list
                new_seq.append_data_to_sent_list(data, last_request_parser, response)
                BugBuckets.Instance().update_bug_buckets(new_seq, response.status_code, origin=self.__class__.__name__)
                self._print_suspect_sequence(new_seq, response)

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

                        #  node  + mutation results
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
                                else:   # tmpnode in list_values
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
                                        #continue
                        start_loc = datacollect.reverseindex(list_values, '?')
                        statelyu = 0
                        for lyui in range(start_loc, len(list_values)):
                            if list_values[lyui] == ' ':
                                break  # finish find node + mutation results in list_values

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

                                # else tmpnode in list_values_default-> have done

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

                        #  node  + mutation results
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
                                else:   # tmpnode in list_values
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

    def _execute_start_of_sequence(self):
        """ Send all requests in the sequence up until the last request

        @return: Sequence of n predecessor requests send to server
        @rtype : Sequence

        """
        RAW_LOGGING("Re-rendering and sending start of sequence")
        new_seq = sequences.Sequence([])

        has_500 = False
        has_400 = False
        has_200 = True

        for request in self._sequence.requests[:-1]:
            new_seq = new_seq + sequences.Sequence(request)
            response, _ = self._render_and_send_data(new_seq, request, False)
            if response.status_code[0] == '2':
                datacollect.invalid_dynamic_object_checker_former_200 += 1
            elif response.status_code[0] == '5':
                datacollect.invalid_dynamic_object_checker_former_500 += 1
            elif response.status_code[0] == '4':
                datacollect.invalid_dynamic_object_checker_former_400 += 1

            if response:
                if response.status_code[0] == '5':
                    has_500 = True
                    has_200 = False
                elif response.status_code[0] == '4':
                    has_400 = True
                    has_200 = False

                if has_500 and not has_400:
                    datacollect.invalid_dynamic_object_checker_part_500 += 1
                elif has_400 and not has_500:
                    datacollect.invalid_dynamic_object_checker_part_400 += 1
                elif has_400 and has_500:
                    datacollect.invalid_dynamic_object_checker_part_non200 += 1
                elif has_200:
                    datacollect.invalid_dynamic_object_checker_part_200 += 1
            # Check to make sure a bug wasn't uncovered while executing the sequence
            if response and response.has_bug_code():
                self._print_suspect_sequence(new_seq, response)
                BugBuckets.Instance().update_bug_buckets(new_seq, response.status_code, origin=self.__class__.__name__)


        if has_500 and not has_400:
            datacollect.invalid_dynamic_object_checker_overall_500 += 1
        elif has_400 and not has_500:
            datacollect.invalid_dynamic_object_checker_overall_400 += 1
        elif has_400 and has_500:
            datacollect.invalid_dynamic_object_checker_overall_non200 += 1
        elif has_200:
            datacollect.invalid_dynamic_object_checker_overall_200 += 1

        return new_seq

    def _prepare_invalid_requests(self, data):
        """ Prepares requests with invalid dynamic objects.
        Each combination of valid/invalid for requests with multiple
        objects will be prepared

        @param data: The rendered payload with dependency placeholders.
        @type data: String

        @return: Each request rendered
        @rtype : Generator of strings

        """
        # If this string is found in an invalid object string, replace it with
        # the actual valid dynamic object.
        # Example: valid object = name123, invalid object string = VALID_REPLACE_STR/?/,
        # new invalid object string = name123/?/
        VALID_REPLACE_STR = 'valid-object'

        RAW_LOGGING("Preparing requests with invalid objects")
        # Split data string into the following format:
        # [0] = start_of_data, [1] = dependency, [2] = data_until_next_dependency
        # [3] = dependency (if more exist), [4] = data_until_next_dependency ...
        data = str(data).split(dependencies.RDELIM)

        consumer_types = []
        # Save off the valid dependencies.
        # Iterate through data list; starting at first dependency and skipping
        # to each subsequent dependency
        for i in range(1, len(data), 2):
            consumer_types.append(dependencies.get_variable(data[i]))

        default_invalids = [f'{VALID_REPLACE_STR}?injected_query_string=123',\
                            f'{VALID_REPLACE_STR}/?/',\
                            f'{VALID_REPLACE_STR}??',\
                            f'{VALID_REPLACE_STR}/{VALID_REPLACE_STR}',\
                            '{}']

        invalid_strs = []
        if not Settings().get_checker_arg(self._friendly_name, 'no_defaults'):
            invalid_strs = default_invalids

        user_invalids = Settings().get_checker_arg(self._friendly_name, 'invalid_objects')
        if isinstance(user_invalids, list):
            # Add the default checks
            invalid_strs.extend(user_invalids)

        for invalid_str in invalid_strs:
            # Iterate through every possible combination (2^n) of invalid/valid objects
            # Stop before the last combination (all valid)
            for valid_mask in range(2**len(consumer_types) - 1):
                index = 0
                for i in range(1, len(data), 2):
                    if ((valid_mask >> index) & 1):
                        # Set valid object to the previously saved variable
                        data[i] = consumer_types[index]
                    else:
                        data[i] = invalid_str.replace(VALID_REPLACE_STR, consumer_types[index])
                    index = index + 1
                yield "".join(data)

    def _false_alarm(self, seq, response):
        """ Catches invalid dynamic object rule violation false alarms that
        occur when a DELETE request receives a 204 as a response status_code

        @param seq: The sequence that contains the request with the rule violation
        @type  seq: Sequence
        @param response: Body of response.
        @type  response: Str

        @return: True if false alarm detected
        @rtype : Bool

        """
        try:
            # If a DELETE request was sent and the status code returned was a 204,
            # we can assume that this was not a failure because many services use a 204
            # response code when there is nothing to delete
            return response.status_code.startswith("204")\
                and seq.last_request.method.startswith('DELETE')
        except Exception:
            return False
