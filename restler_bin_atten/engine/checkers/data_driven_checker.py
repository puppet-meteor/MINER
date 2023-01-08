
""" Implements logic for data driven checker. """
from __future__ import print_function

from checkers.checker_base import *

import time
import itertools
import copy

from engine.bug_bucketing import BugBuckets
import engine.dependencies as dependencies
import engine.core.sequences as sequences
import engine.core.datacollect as datacollect
import engine.core.sequences as sequences


class DataDrivenChecker(CheckerBase):
    def __init__(self, req_collection, fuzzing_requests):
        CheckerBase.__init__(self, req_collection, fuzzing_requests, enabled=True)


    def apply(self, rendered_sequence, lock):
    
        """ Applies check for data driven generations.

        @param rendered_sequence: Object containing the rendered sequence information
        @type  rendered_sequence: RenderedSequence
        @param lock: Lock object used to sync more than one fuzzing job
        @type  lock: thread.Lock

        @return: None
        @rtype : None

        """
   
        if not datacollect.mutationtrainingset:
            return 

        if len(datacollect.mutationtrainingset) < 1:
            return

        if not rendered_sequence.valid:
            return

        self._sequence = rendered_sequence.sequence
        # render n-1 requests
        self._checker_log.checker_print("\nRe-rendering start of original sequence   data-driven")
        RAW_LOGGING("Re-rendering start of original sequence  data-driven")
        new_seq = sequences.Sequence([])

        for request in self._sequence.requests[:-1]:
            new_seq = new_seq + sequences.Sequence(request)
            response, _ = self._render_and_send_data(new_seq, request, False)
            if response:
                if response.status_code[0] == '2':
                    datacollect.data_driven_checker_former_200 += 1
                elif response.status_code[0] == '5':
                    datacollect.data_driven_checker_former_500 += 1
                elif response.status_code[0] == '4':
                    datacollect.data_driven_checker_former_400 += 1
        # render n-1 requests finish

        # render last requests start
        new_seq = new_seq + sequences.Sequence(self._sequence.requests[-1])
        rendered_data, parser, list_values, list_values_default, whethergen = self._sequence.requests[-1].render_current_lyu3(self._req_collection.candidate_values_pool)
        rendered_data = new_seq.resolve_dependencies(rendered_data)
        response = self._send_request(parser, rendered_data)
        request_utilities.call_response_parser(parser, response)
        new_seq.append_data_to_sent_list(rendered_data, parser, response)
        if response:
            if  self._rule_violation(new_seq, response):
                sent_request_data_list = new_seq.sent_request_data_list
                for req in sent_request_data_list:
                    data = repr(req.rendered_data).strip("'")
                self._print_suspect_sequence(new_seq, response)
                BugBuckets.Instance().update_bug_buckets(
                    new_seq, response.status_code, origin=self.__class__.__name__) #, reproduce=False)

            if response.status_code[0] == '2':
                datacollect.data_driven_checker_laster_200 += 1
            elif response.status_code[0] == '5':
                datacollect.data_driven_checker_laster_500 += 1
            elif response.status_code[0] == '4':
                datacollect.data_driven_checker_laster_400 += 1

            if '?' in list_values_default:  # otherwise there is no node to mutate
                if response.status_code[0] == '2':
                    if whethergen == 1:
                        datacollect.gen200 += 1
                    else:
                        datacollect.nogen200 += 1
                    datacollect.countid += 1

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

                    if datacollect.seq_which == 1:
                        datacollect.seq_gen500 += 1
                    elif datacollect.seq_which == 2:
                        datacollect.seq_nogen500 += 1

                elif response.status_code[0] == '4':
                    if datacollect.seq_which == 1:
                        datacollect.seq_gen400 += 1
                    elif datacollect.seq_which == 2:
                        datacollect.seq_nogen400 += 1
