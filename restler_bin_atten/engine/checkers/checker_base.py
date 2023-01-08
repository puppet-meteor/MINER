# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from abc import ABCMeta, abstractmethod
from checkers.checker_log import CheckerLog

import engine.core.async_request_utilities as async_request_utilities
import engine.core.request_utilities as request_utilities
import engine.transport_layer.messaging as messaging
from engine.transport_layer.response import *

from restler_settings import Settings
from engine.errors import ResponseParsingException
from engine.errors import TransportLayerException
from engine.core.fuzzing_monitor import Monitor

from utils.logger import raw_network_logging as RAW_LOGGING

import engine.core.datacollect as datacollect  # lyu

class CheckerBase:
    __metaclass__ = ABCMeta

    def __init__(self, req_collection, fuzzing_requests, enabled=False):
        """ Abstract class constructor

        @param req_collection: The shared request collection
        @type  req_collection: RequestCollection
        @param fuzzing_requests: The collection of requests to fuzz
        @type  fuzzing_requests: FuzzingRequestCollection
        @param enabled: Set to True to enable this checker by default when fuzzing
        @type  enabled: Bool

        """
        self._checker_log = CheckerLog(self.__class__.__name__)
        self._req_collection = req_collection
        self._fuzzing_requests = fuzzing_requests
        self._connection_settings = Settings().connection_settings
        self._enabled = enabled
        self._friendly_name = self.__class__.__name__[:-len("Checker")].lower()
        self._mode = Settings().get_checker_arg(self._friendly_name, 'mode') or 'normal'

    @property
    def friendly_name(self):
        return self._friendly_name

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enable):
        self._enabled = enable

    @abstractmethod
    def apply(self, rendered_sequence, lock):
        """ Required to be implemented by all checkers. This is the function
        that is called by driver.apply_checkers to perform each checker's task

        @param rendered_sequence: Object containing the rendered sequence information
        @type  rendered_sequence: RenderedSequence
        @param lock: Lock object used to sync more than one fuzzing job
        @type  lock: thread.Lock

        """
        pass

    def _send_request(self, parser, rendered_data):
        """ Send a request and invoke the response parser.

        @param parser: A parser to parse the data
        @type  parser: Function pointer
        @param rendered_data: The request's rendered data to send
        @type  rendered_data: Str

        @return: The response from the server
        @rtype : HttpResponse
        """
        try:
            sock = messaging.HttpSock(self._connection_settings)
        except TransportLayerException as error:
            RAW_LOGGING(f"{error!s}")
            # connection failed
            return HttpResponse()

        success, response = sock.sendRecv(
            rendered_data, req_timeout_sec=Settings().max_request_execution_time
        )
        if not success:
            RAW_LOGGING(response.to_str)
        Monitor().increment_requests_count(self.__class__.__name__)

        return response

    def _render_and_send_data(self, seq, request, check_async=True, is_last=False, whetherE=2):
        """ Helper that renders data for a request, sends the request to the server,
        and then adds that rendered data and its response to a sequence's sent-request-data
        list. This is here so that checkers can send their own requests without needing to
        run through the sequences.render function. Adding the data to the sent-request-data
        list is required when replaying a sequence, which occurs when a bug is detected.

        @param seq: The sequence to append the rendered data to
        @type  seq: Sequence
        @param request: The request to render and append
        @type  request: Request
        @param check_async: If set to True (default), the function will check for resources
                            that are created asynchronously and wait for them if so.
        @type  check_async: Boolean

        @return: Tuple containing the response received after sending the request and the response
                 that should be parsed. The response_to_parse will differ from response only if
                 the response_to_parse was from a GET request that followed an asynchronous resource creation.
        @rtype : Tuple(HttpResponse, HttpResponse)

        """
        if is_last:
            rendered_data, parser, list_values, list_values_default, whethergen = request.render_current_lyu(self._req_collection.candidate_values_pool, whetherE)
        else:
            rendered_data, parser, list_values, list_values_default, whethergen, datacollect.seq_which = request.render_current_lyu2(self._req_collection.candidate_values_pool, 0)
        rendered_data = seq.resolve_dependencies(rendered_data)
        response = self._send_request(parser, rendered_data)
        response_to_parse = response
        async_wait = Settings().get_max_async_resource_creation_time(request.request_id)

        if '?' in list_values_default:
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
                tmp_status_code = ''
                if response.status_code[0] == '2':
                    tmp_status_code = 'P'
                elif response.status_code[0] == '5':
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
                        else:   # tmpnode in prev_list_values`
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
                tmp_status_code = ''
                if response.status_code[0] == '2':
                    tmp_status_code = 'P'
                elif response.status_code[0] == '5':
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

        if check_async:
            response_to_parse, _, _ = async_request_utilities.try_async_poll(
                rendered_data, response, async_wait)
        request_utilities.call_response_parser(parser, response_to_parse)
        seq.append_data_to_sent_list(rendered_data, parser, response, producer_timing_delay=0, max_async_wait_time=async_wait)
        return response, response_to_parse


    def _rule_violation(self, seq, response, valid_response_is_violation=True):
        """ Helper to check whether rule is violated.

        @param seq: The sequence whose last request we will try to render.
        @type  seq: Sequence Class object.
        @param response: Body of response.
        @type  response: Str.
        @param valid_response_is_violation: If set to True, a 20x status code
                in the response is treated as a violation
        @type  valid_response_is_violation: Bool

        @return: Whether rule is violated or not.
        @rtype : Bool

        """
        # This is the default general rule for this checker.
        # If a 500 (server error) is returned then it is an obvious bug.
        # If a 20x is returned and valid_response_is_violation is set to True
        # then the checker is sending requests that it assumes should be handled by
        # the server replying with a 4xx client error status code (i.e. an invalid request)
        if response and (response.has_bug_code()\
        or (valid_response_is_violation and response.has_valid_code())):
            return not self._false_alarm(seq, response)

        # If we reach this point no violation has occured.
        return False

    def _false_alarm(self, seq, response):
        """ Called by _rule_violation when a rule violation is detected.
        The purpose of this function is to catch scenarios that fail the rule
        violation check, but are not actually a rule violation.

        By default this method is not implemented and returns False. This function
        should be overriden by an individual checker if there are false alarms to catch.

        @param seq: The sequence whose last request we will try to render.
        @type  seq: Sequence Class object.
        @param response: Body of response.
        @type  response: Str.

        @return: True if false alarm detected
        @rtype : Bool

        """
        return False

    def _format_status_code(self, status_code):
        """ Formats status code for logging

        @param status_code: The original status code
        @type  status_code: Str

        @return: The new, formatted, status code
        @rtype : Str

        """
        if status_code == TIMEOUT_CODE:
            return 'Timeout'
        elif status_code == CONNECTION_CLOSED_CODE:
            return 'Connection_Closed'
        return status_code

    def _print_suspect_sequence(self, seq, response):
        """ Helper function that prints the sequence's definition.

        @param seq: The sequence whose last request we will try to render.
        @type  seq: Sequence Class object.
        @param response: The HTTP response received.
        @type  response: Str

        @return: None
        @rtype : None

        """
        if response and response.status_code:
            status_code = self._format_status_code(response.status_code)
            self._checker_log.checker_print(f"\nSuspect sequence: {status_code}")
        for req in seq:
            self._checker_log.checker_print(f"{req.method} {req.endpoint}")
