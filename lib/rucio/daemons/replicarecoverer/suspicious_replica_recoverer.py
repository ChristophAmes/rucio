# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
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
#
# Authors:
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

"""
Suspicious-Replica-Recoverer is a daemon that declares suspicious replicas as bad if they are found available on other RSE.
Consequently, automatic replica recovery is triggered via necromancer daemon, which creates a rule for such bad replica(s).
"""

from __future__ import print_function

import logging
import os
import socket
import threading
import time
import traceback
from datetime import datetime, timedelta
from re import match
from sys import argv

import rucio.db.sqla.util
from rucio.common.config import config_get_bool
from rucio.common.exception import DatabaseException, VONotFound, InvalidRSEExpression
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.replica import list_replicas, declare_bad_file_replicas, get_suspicious_files
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla.constants import BadFilesStatus
from rucio.db.sqla.util import get_db_time

from rucio.core.rse import list_rses

# # From example (sent by Cedric)
# import json
# import sys
# import requests
# import rucio.common.policy
# import rucio.core.did
# import rucio.core.rule
# from rucio.core.lifetime_exception import list_exceptions
# from rucio.db.sqla.constants import LifetimeExceptionsState
# from rucio.core.did import get_metadata
# from rucio.common.utils import sizefmt
# from rucio.common.exception import DataIdentifierNotFound


GRACEFUL_STOP = threading.Event()


def declare_suspicious_replicas_bad2(once=False, younger_than=3, nattempts=10, rse_expression='MOCK', vos=None, max_replicas_per_rse=100):

    """
    Main loop to check for available replicas which are labeled as suspicious

    Gets a list of suspicious replicas that are listed as AVAILABLE in 'replicas' table
    and available on other RSE. Finds surls of these replicas and declares them as bad.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param younger_than: The number of days since which bad_replicas table will be searched
                         for finding replicas declared 'SUSPICIOUS' at a specific RSE ('rse_expression'),
                         but 'AVAILABLE' on other RSE(s).
    :param nattempts: The minimum number of appearances in the bad_replica DB table
                      in order to appear in the resulting list of replicas for recovery.
    :param rse_expression: Search for suspicious replicas on RSEs matching the 'rse_expression'.
    :param vos: VOs on which to look for RSEs. Only used in multi-VO mode.
                If None, we either use all VOs if run from "def",
    :param max_replicas_per_rse: Maximum number of replicas which are allowed to be labeled as bad per RSE.
                                 If more is found, processing is skipped and warning is printed.
    :returns: None
    """

    # assembling the worker name identifier ('executable') including the rses from <rse_expression>
    # in order to have the possibility to detect a start of a second instance with the same set of RSES

    executable = argv[0]

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logging.warning('Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = ['def']
    else:
        if vos:
            invalid = set(vos) - set([v['vo'] for v in list_vos()])
            if invalid:
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logging.info('replica_recoverer: This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
    rses = []
    exceptions_raised = 0
    for vo in vos:
        try:
            parsed_rses = parse_expression(expression=rse_expression, filter={'vo': vo})
        except InvalidRSEExpression:
            exceptions_raised += 1
            parsed_rses = []
        for rse in parsed_rses:
            rses.append(rse['id'])
    if exceptions_raised == len(vos):
        raise InvalidRSEExpression('RSE Expression resulted in an empty set.')

    rses.sort()
    executable += ' --rse-expression ' + str(rses)

    sanity_check(executable=executable, hostname=socket.gethostname())

    # make an initial heartbeat - expected only one replica-recoverer thread on one node
    # heartbeat mechanism is used in this daemon only for information purposes
    # (due to expected low load, the actual DB query does not filter the result based on worker number)
    live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())

    # wait a moment in case all workers started at the same time
    GRACEFUL_STOP.wait(1)

    while not GRACEFUL_STOP.is_set():
        try:
            # issuing the heartbeat for a second time to make all workers aware of each other (there is only 1 worker allowed for this daemon)
            heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
            total_workers = heartbeat['nr_threads']
            worker_number = heartbeat['assign_thread']

            # there is only 1 worker allowed for this daemon
            if total_workers != 1:
                logging.error('replica_recoverer: Another running instance on %s has been detected. Stopping gracefully.', socket.gethostname())
                die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
                break

            start = time.time()

            logging.info('replica_recoverer[%i/%i]: ready to query replicas at RSE %s,'
                         + ' reported suspicious in the last %i days at least %i times which are available on other RSEs.',  # NOQA: W503
                         worker_number, total_workers, rse_expression, younger_than, nattempts)

            getfileskwargs = {'younger_than': younger_than,
                              'nattempts': nattempts,
                              'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                              'available_elsewhere': True,
                              'is_suspicious': True}

            # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
            recoverable_replicas = []
            exceptions_raised = 0
            for vo in vos:
                try:
                    recoverable_replicas.extend(get_suspicious_files(rse_expression, filter={'vo': vo}, **getfileskwargs))
                except InvalidRSEExpression:
                    exceptions_raised += 1
            if exceptions_raised == len(vos):
                raise InvalidRSEExpression('RSE Expression resulted in an empty set.')

            logging.info('replica_recoverer[%i/%i]: suspicious replica query took %.2f seconds, total of %i replicas were found.',
                         worker_number, total_workers, time.time() - start, len(recoverable_replicas))

            if not recoverable_replicas and not once:
                logging.info('replica_recoverer[%i/%i]: found %i recoverable suspicious replicas. Sleeping for 60 seconds.', worker_number, total_workers, len(recoverable_replicas))
                GRACEFUL_STOP.wait(60)
            else:
                logging.info('replica_recoverer[%i/%i]: looking for replica surls.', worker_number, total_workers)

                start = time.time()
                surls_to_recover = {}  # dictionary of { vo1: {rse1: [surl1, surl2, ... ], rse2: ...}, vo2:... }
                cnt_surl_not_found = 0
                for replica in recoverable_replicas:
                    scope = replica['scope']
                    name = replica['name']
                    vo = scope.vo
                    rse = replica['rse']
                    rse_id = replica['rse_id']
                    if GRACEFUL_STOP.is_set():
                        break
                    if vo not in surls_to_recover:
                        surls_to_recover[vo] = {}
                    if rse_id not in surls_to_recover[vo]:
                        surls_to_recover[vo][rse_id] = []
                    # for each suspicious replica, we get its surl through the list_replicas function
                    surl_not_found = True
                    for rep in list_replicas([{'scope': scope, 'name': name}]):
                        for site in rep['rses']:
                            if site == rse_id:
                                surls_to_recover[vo][rse_id].append(rep['rses'][site][0])
                                surl_not_found = False
                    if surl_not_found:
                        cnt_surl_not_found += 1
                        logging.warning('replica_recoverer[%i/%i]: skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, name, rse)

                logging.info('replica_recoverer[%i/%i]: found %i/%i surls (took %.2f seconds), declaring them as bad replicas now.',
                             worker_number, total_workers, len(recoverable_replicas) - cnt_surl_not_found, len(recoverable_replicas), time.time() - start)

                for vo in surls_to_recover:
                    for rse_id in surls_to_recover[vo]:
                        logging.info('replica_recoverer[%i/%i]: ready to declare %i bad replica(s) on %s: %s.',
                                     worker_number, total_workers, len(surls_to_recover[vo][rse_id]), rse, str(surls_to_recover[vo][rse_id]))
                        if len(surls_to_recover[vo][rse_id]) > max_replicas_per_rse:
                            logging.warning('replica_recoverer[%i/%i]: encountered more than %i suspicious replicas (%s) on %s. Please investigate.',
                                            worker_number, total_workers, max_replicas_per_rse, str(len(surls_to_recover[vo][rse_id])), rse)
                        else:
                            # declare_bad_file_replicas(pfns=surls_to_recover[vo][rse_id], reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), status=BadFilesStatus.BAD, session=None)
                            logging.info('replica_recoverer[%i/%i]: finished declaring bad replicas on %s.', worker_number, total_workers, rse)


            # Sticking this here for now, as I'm not sure what the best way to integrate/call this function is yet.
            check_for_problematic_rses(vos, younger_than, nattempts)

        except (DatabaseException, DatabaseError) as err:
            if match('.*QueuePool.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
            elif match('.*ORA-03135.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
            else:
                logging.critical(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
        except Exception as err:
            logging.critical(traceback.format_exc())
            record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
        if once:
            break

    die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    logging.info('replica_recoverer[%i/%i]: graceful stop done', worker_number, total_workers)












def declare_suspicious_replicas_bad(once=False, younger_than=3, nattempts=10, vos=None, max_replicas_per_rse=100, limit_suspicious_files_on_rse=5):

    """
    Main loop to check for available replicas which are labeled as suspicious

    Gets a list of suspicious replicas that are listed as AVAILABLE in 'replicas' table
    and available on other RSE. Finds surls of these replicas and declares them as bad.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param younger_than: The number of days since which bad_replicas table will be searched
                         for finding replicas declared 'SUSPICIOUS' at a specific RSE ('rse_expression'),
                         but 'AVAILABLE' on other RSE(s).
    :param nattempts: The minimum number of appearances in the bad_replica DB table
                      in order to appear in the resulting list of replicas for recovery.
    :param rse_expression: Search for suspicious replicas on RSEs matching the 'rse_expression'.
    :param vos: VOs on which to look for RSEs. Only used in multi-VO mode.
                If None, we either use all VOs if run from "def",
    :param max_replicas_per_rse: Maximum number of replicas which are allowed to be labeled as bad per RSE.
                                 If more is found, processing is skipped and warning is printed.
    :returns: None
    """

    # assembling the worker name identifier ('executable') including the rses from <rse_expression>
    # in order to have the possibility to detect a start of a second instance with the same set of RSES

    executable = argv[0]

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logging.warning('Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = ['def']
    else:
        if vos:
            invalid = set(vos) - set([v['vo'] for v in list_vos()])
            if invalid:
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logging.info('replica_recoverer: This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    # # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
    # rses = []
    # exceptions_raised = 0
    # for vo in vos:
    #     try:
    #         parsed_rses = parse_expression(expression=rse_expression, filter={'vo': vo})
    #     except InvalidRSEExpression:
    #         exceptions_raised += 1
    #         parsed_rses = []
    #     for rse in parsed_rses:
    #         rses.append(rse['id'])
    # if exceptions_raised == len(vos):
    #     raise InvalidRSEExpression('RSE Expression resulted in an empty set.')
    #
    # rses.sort()
    # executable += ' --rse-expression ' + str(rses)

    sanity_check(executable=executable, hostname=socket.gethostname())

    # make an initial heartbeat - expected only one replica-recoverer thread on one node
    # heartbeat mechanism is used in this daemon only for information purposes
    # (due to expected low load, the actual DB query does not filter the result based on worker number)
    live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())

    # wait a moment in case all workers started at the same time
    GRACEFUL_STOP.wait(1)

    while not GRACEFUL_STOP.is_set():
        try:
            # issuing the heartbeat for a second time to make all workers aware of each other (there is only 1 worker allowed for this daemon)
            heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
            total_workers = heartbeat['nr_threads']
            worker_number = heartbeat['assign_thread']

            # there is only 1 worker allowed for this daemon
            if total_workers != 1:
                logging.error('replica_recoverer: Another running instance on %s has been detected. Stopping gracefully.', socket.gethostname())
                die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
                break

            start = time.time()

            logging.info('replica_recoverer[%i/%i]: Ready to query replicas which were'
                         + ' reported suspicious in the last %i days at least %i times.',  # NOQA: W503
                         worker_number, total_workers, younger_than, nattempts)

            # logging.info('replica_recoverer[%i/%i]: ready to query replicas at RSE %s,'
            #              + ' reported suspicious in the last %i days at least %i times which are available on other RSEs.',  # NOQA: W503
            #              worker_number, total_workers, rse_expression, younger_than, nattempts)

            getfileskwargs = {'younger_than': younger_than,
                              'nattempts': nattempts,
                              'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                              'available_elsewhere': True,
                              'is_suspicious': True}

            # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
            # recoverable_replicas = []
            # exceptions_raised = 0
            # for vo in vos:
            #     try:
            #         recoverable_replicas.extend(get_suspicious_files(rse_expression, filter={'vo': vo}, **getfileskwargs))
            #     except InvalidRSEExpression:
            #         exceptions_raised += 1
            # if exceptions_raised == len(vos):
            #     raise InvalidRSEExpression('RSE Expression resulted in an empty set.')



            for vo in vos:
                logging.info('replica_recoverer[%i/%i]: Start replica recovery for VO: %s', worker_number, total_workers, vo)
                recoverable_replicas = {}
                if vo not in recoverable_replicas:
                    recoverable_replicas[vo]={}
                rse_list = list_rses()
                rse_list[:] = [rse for rse in rse_list if ((rse['deleted'] == False) and (rse['rse'] not in {"MOCK-POSIX", "ru-PNPI_XCACHE", "ru-PNPI_XCACHE_LOCAL", "ru-PNPI_XCACHE_NODES"}) and (rse['rse'].split("_")[-1] in {"DATADISK", "SCRATCHDISK"}))]

                for rse in rse_list:
                    time_start_rse = time.time()
                    rse_expr = rse['rse']
                    cnt_surl_not_found = 0
                    site = '_'.join(rse_expr.split('_')[:-1])
                    if site not in recoverable_replicas[vo]:
                        recoverable_replicas[vo][site] = {}
                    if rse_expr not in recoverable_replicas[vo][site]:
                        recoverable_replicas[vo][site][rse_expr] = {}
                    suspicious_replicas = get_suspicious_files(rse_expr, filter={'vo': vo}, **getfileskwargs)

                    if (rse['availability'] not in {4, 5, 6, 7}) and (len(suspicious_replicas) > 0):
                        logging.warning("%s is labeled as unavailable, yet is has suspicious replicas. Please investigate." % rse_expr)
                        continue
                    if suspicious_replicas:
                        for replica in suspicious_replicas:
                            if vo == replica['scope'].vo:
                                scope = replica['scope']
                                rep_name = replica['name']
                                rse_id = replica['rse_id']
                                # if GRACEFUL_STOP.is_set():
                                #     break
                                surl_not_found = True
                                for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                                    for rse_ in rep['rses']:
                                        if rse_ == rse_id:
                                            recoverable_replicas[vo][site][rse_expr][rep_name] = {'name':rep_name, 'rse_id':rse_id, 'scope':scope, 'surl':rep['rses'][rse_][0]}
                                            surl_not_found = False
                                if surl_not_found:
                                    cnt_surl_not_found += 1
                                    logging.warning('replica_recoverer[%i/%i]: Skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, name, rse_expr)

                    logging.info('replica_recoverer[%i/%i]: Suspicious replica query took %.2f seconds on %s, %i/%i replicas were found.',
                                 worker_number, total_workers, time.time() - time_start_rse, rse_expr, len(suspicious_replicas) - cnt_surl_not_found, len(suspicious_replicas))
                logging.info('replica_recoverer[%i/%i]: All RSEs have been checked for suspicious replicas. Total time: %.2f seconds.', worker_number, total_workers, time.time() - start)
                logging.info('replica_recoverer[%i/%i]: Begin check for problematic sites and RSEs.', worker_number, total_workers)
                time_start_check_probl = time.time()
                for site in list(recoverable_replicas[vo].keys()):
                    clean_rses = 0
                    for rse_key, rse_value in recoverable_replicas[vo][site].items():
                        if len(rse_value) == 0: # If RSE has no suspicious replicas
                            clean_rses += 1
                    if len(recoverable_replicas[vo][site]) == clean_rses:
                        del recoverable_replicas[vo][site]

                for site in list(recoverable_replicas[vo].keys()):
                    count_problematic_rse = 0 # Number of RSEs with less than *limit_suspicious_files_on_rse* suspicious replicas
                    list_problematic_rses = []
                    for rse_key, rse_value in recoverable_replicas[vo][site].items():
                        if len(rse_value) > limit_suspicious_files_on_rse:
                            count_problematic_rse += 1
                            list_problematic_rses.append(rse_key)
                        # if len(rse_value) == 0:
                            # Remove RSEs with no suspicious replicas as it makes it easier to deal with RSEs individually
                            # del recoverable_replicas[vo][site][rse]
                    if len(recoverable_replicas[vo][site].values()) == count_problematic_rse:
                        # All RSEs on the site have been deemed problematic -> site has a problem
                        # Set all of the replicas on the site as TEMPORARY_UNAVAILABLE
                        for rse_key, rse_value in recoverable_replicas[vo][site].items():
                            surls_list = []
                            for replica_key, replica_value in rse_value.items():
                                surls_list.append(replica_value['surl'])
                            ###########
                            # REMOVED FOR TEST:
                            # add_bad_pfns(pfns=surls_list, account=ACCOUNT?, state=TEMPORARY_UNAVAILABLE) # What is an account in this case?
                            ###########
                        logging.info("All RSEs on site %s are problematic. Send a Jira ticket for the site (to be implemented)." % site)
                        # Remove the site from the dictionary as it has been dealt with.
                        del recoverable_replicas[vo][site]
                        continue # Move on to next site.

                    # Only specific RSEs of a site have too many suspicious replicas and are therefore problematic. Check RSEs individually.
                    for rse in list_problematic_rses:
                        if len(recoverable_replicas[vo][site][rse].values()) > limit_suspicious_files_on_rse:
                            # RSE has a problem
                            # Set all of the replicas on the RSE as TEMPORARY_UNAVAILABLE
                            surls_list = []
                            for replica_value in recoverable_replicas[vo][site][rse].values():
                                surls_list.append(replica_value['surl'])
                            ###########
                            # REMOVED FOR TEST:
                            # add_bad_pfns(pfns=surls_list, account=ACCOUNT?, state=TEMPORARY_UNAVAILABLE)
                            ###########
                            logging.info("%s of site %s is problematic. Send a Jira ticket for the RSE (to be implemented)." % (rse, site))
                            # Remove the RSE from the dictionary as it has been dealt with.
                            del recoverable_replicas[vo][site][rse]
                            continue
                # Label remaining suspicious replicas as bad
                for site in recoverable_replicas[vo].keys():
                    for rse_key in list(recoverable_replicas[vo][site].keys()):
                        # Remove remaining RSEs that don't have any suspicious replicas (should only exist for sites that had at least one
                        # RSE with a suspicious replica)
                        if len(recoverable_replicas[vo][site][rse_key]) == 0:
                             del recoverable_replicas[vo][site][rse_key]
                             continue
                        rse_id = list(recoverable_replicas[vo][site][rse_key].values())[0]['rse_id']
                        remaining_surls = []
                        for replica in recoverable_replicas[vo][site][rse_key].values():
                            remaining_surls.append(replica['surl'])

                    # for rse_id in surls_to_recover[vo]:
                        logging.info('replica_recoverer[%i/%i]: Ready to declare %i bad replica(s) on %s (RSE id: %s).',
                                     worker_number, total_workers, len(remaining_surls), rse_key, str(rse_id))
                        # if len(surls_to_recover[vo][rse_id]) > max_replicas_per_rse:
                        #     logging.warning('replica_recoverer[%i/%i]: encountered more than %i suspicious replicas (%s) on %s. Please investigate.',
                        #                     worker_number, total_workers, max_replicas_per_rse, str(len(surls_to_recover[vo][rse_id])), rse)
                        # else:
                            # declare_bad_file_replicas(pfns=remaining_surls, reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), status=BadFilesStatus.BAD, session=None)
                        logging.info('replica_recoverer[%i/%i]: Finished declaring bad replicas on %s.', worker_number, total_workers, rse_key)

                logging.info('replica_recoverer[%i/%i]: Finished checking for problematic sites and RSEs. Total time: %.2f seconds.', worker_number, total_workers, time.time() - time_start_check_probl)

            # Sticking this here for now, as I'm not sure what the best way to integrate/call this function is yet.
            # check_for_problematic_rses(vos, younger_than, nattempts)

        except (DatabaseException, DatabaseError) as err:
            if match('.*QueuePool.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
            elif match('.*ORA-03135.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
            else:
                logging.critical(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
        except Exception as err:
            logging.critical(traceback.format_exc())
            record_counter('replica.recoverer.exceptions.%s', err.__class__.__name__)
        if once:
            break

    die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    logging.info('replica_recoverer[%i/%i]: Graceful stop done.', worker_number, total_workers)









def check_for_problematic_rses(vos, younger_than, nattempts, limit_suspicious_files_on_rse=5):

    """
    All sites/RSEs that have suspicious replicas are checked to see if the sites/RSEs themselves have problems. This is
    indicated by the number of suspicious files on each RSE.
    A dictionary is created, where the suspicious replicas are sorted by vo, site and RSE. If a site/RSE is deemed
    problematic, then the suspicious files on the site/RSE are labeled as TEMPORARY_UNAVAILABLE and removed from the
    dictionary.
    At the end, the dictionary with the remaining replicas is returned. It is assumed that these replicas themselves
    have a problem.
    """

    getfileskwargs = {'younger_than': younger_than,
                        'nattempts': nattempts,
                        'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                        'is_suspicious': True}

    recoverable_replicas = {}
    # End result: {vo1: {site1: {rse1: {replica1:{name:replica_name1, rse_id:replica_rse_id1, scope:scope1, surl:surl1}, replica2_name:{...}, ...], rse_2: {...}, ...}, site2: {...}  },    vo2: {...}}
    # Each surl describes a replica on a specific RSE
    for vo in vos:
        if vo not in recoverable_replicas:
            recoverable_replicas[vo]={}
        rse_list = list_rses()
        # Remove some RSEs from the list that don't fulfill specific criteria
        rse_list[:] = [rse for rse in rse_list if ((rse['deleted'] == False) and (rse['rse'] not in {"MOCK-POSIX", "ru-PNPI_XCACHE", "ru-PNPI_XCACHE_LOCAL", "ru-PNPI_XCACHE_NODES"}) and (rse['rse'].split("_")[-1] in {"DATADISK", "SCRATCHDISK"}))]

        for rse in rse_list:
            rse_expr = rse['rse']
            site = rse_expr.split('_')[0] # This assumes that the RSE expression has the strucutre site_X, e.g. LRZ-LMU_DATADISK
            if site not in recoverable_replicas[vo]:
                recoverable_replicas[vo][site] = {}
            if rse_expr not in recoverable_replicas[vo][site]:
                recoverable_replicas[vo][site][rse_expr] = {}
            # recoverable_replicas should now look like this:
            # {vo1: {site1: {rse1: [], rse_2: [], ...}, site2: {...}  },    vo2: {...}}
            # print("RSE: ", rse_expr)
            suspicious_replicas = get_suspicious_files(rse_expr, filter={'vo': vo}, **getfileskwargs)

            if (rse['availability'] not in {4, 5, 6, 7}) and (len(suspicious_replicas) > 0):
                logging.warning("RSE %s is labeled as unavailable, yet is has suspicious replicas. Please investigate." % rse_expr)
                continue

            # Not all RSEs have suspicious replicas on them. However, they should still be added to the list as makes it possibl to
            # check if a site has problems (by checking whether all the RSEs on it have a certain number of suspicious files).

            # Get the surls for the suspicious replicas
            if suspicious_replicas:
                # If suspicious replicas isn't empty then there is at least one suspcicious replica on the RSE
                cnt_surl_not_found = 0
                for replica in suspicious_replicas:
                    if vo == replica['scope'].vo:
                        scope = replica['scope']
                        rep_name = replica['name']
                        # rse = replica['rse']
                        rse_id = replica['rse_id']
                        # if GRACEFUL_STOP.is_set():
                        #     break
                        surl_not_found = True
                        for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                            for rse_ in rep['rses']:
                                if rse_ == rse_id:
                                    # Only replicas for which an surl can be found on the appropriate RSE are added
                                    recoverable_replicas[vo][site][rse_expr][rep_name] = {'name':rep_name, 'rse_id':rse_id, 'scope':scope, 'surl':rep['rses'][rse_][0]}
                                    # print("surl found: %s" % recoverable_replicas[vo][site][rse_expr][rep_name]['surl'])
                                    surl_not_found = False
                if surl_not_found:
                    cnt_surl_not_found += 1
                    # logging.warning('replica_recoverer[%i/%i]: skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, name, rse)

            # recoverable_replicas should now look like this: {vo1: {site1: {rse1: [surl1, surl2, ...], rse_2: [...], ...}, site2: {...}  },    vo2: {...}}
            # At this point in time there will be RSEs with empty lists, as they have no suspicious replicas

        for site in list(recoverable_replicas[vo].keys()):
            # print("Site name: ", site)
        # Check if a site is in the list of known unavailable sites. If it is, remove it from the dictionary (should probably also send some sort of logging warning, as
        # replicas on a site that is down during a scheduled time shouldn't be labeled as suspicious when there is an attempt to access them).
            clean_rses = 0
            for rse_key, rse_value in recoverable_replicas[vo][site].items():
                # print(rse)
                # print(len(rse_value))
                if len(rse_value) == 0: # If RSE has no suspicious replicas
                    clean_rses += 1
            # Remove sites where all RSEs have no suspicious replicas
            # print("len: ", len(recoverable_replicas[vo][site]))
            # print("clean: ", clean_rses)
            if len(recoverable_replicas[vo][site]) == clean_rses:
                # print("Site %s is clean; removing" % site)
                # Site is clean; it can be removed from the dictionary
                del recoverable_replicas[vo][site]

        # recoverable_replicas should now only have sites where at least one RSE has a suspicious replica
        # Set a limit to the total count of all suspicious replicas on an RSE combined. If this limit if exceeded on all RSEs of a site, then the site is considered
        # problematic, meaning the replicas are marked as TEMPORARY_UNAVAILABLE and a ticket is sent to the site managers.
        # If an RSE has more than limit_suspicious_files_on_rse suspicious files, it is marked as problematic

        for site in list(recoverable_replicas[vo].keys()):
            # print("Checking if %s is problematic" % site)
            count_problematic_rse = 0 # Number of RSEs with less than *limit_suspicious_files_on_rse* suspicious replicas
            list_problematic_rses = [] # List of RSEs that are deemed problematic
            for rse_key, rse_value in recoverable_replicas[vo][site].items():
                if len(rse_value) > limit_suspicious_files_on_rse:
                    count_problematic_rse += 1
                    # print("%s has more than 5 suspicious replicas" % rse_key)
                    list_problematic_rses.append(rse_key)
            # print("len(values): ", len(recoverable_replicas[vo][site].values()))
            # print("Count probl. RSEs: ", count_problematic_rse)
            if len(recoverable_replicas[vo][site].values()) == count_problematic_rse:
                # Site has a problem
                # Set all of the replicas on the site as TEMPORARY_UNAVAILABLE
                for rse_key, rse_value in recoverable_replicas[vo][site].items():
                    surls_list = []
                    for replica_key, replica_value in rse_value.items():
                        # print("replica key: ", replica_key)
                        # print("replica_value surl: ", replica_value['surl'])
                        surls_list.append(replica_value['surl'])
                # print("Site: ", site)
                # print(surls_list)
                    # REMOVED FOR TEST:
                    # add_bad_pfns(pfns=surls_list, account=ACCOUNT?, state=TEMPORARY_UNAVAILABLE) # What is an account in this case?
                logging.info("All RSEs on site %s are problematic. Send a Jira ticket for the site (to be implemented)." % site)
                # Remove the site from the dictionary as it has been dealt with.
                del recoverable_replicas[vo][site]
                continue # Move on to next site.

            # Only specific RSEs of a site have too many suspicious replicas and are therefore problematic. Check RSEs individually.
            for rse in list_problematic_rses:
                if len(recoverable_replicas[vo][site][rse]) > limit_suspicious_files_on_rse:
                    # RSE has a problem
                    # Set all of the replicas on the RSE as TEMPORARY_UNAVAILABLE
                    surls_list = []
                    for replica_value in recoverable_replicas[vo][site][rse].values():
                        surls_list.append(replica_value['surl'])
                    # print("surls_list: ")
                    # print(surls_list)
                    # REMOVED FOR TEST:
                    # add_bad_pfns(pfns=surls_list, account=ACCOUNT?, state=TEMPORARY_UNAVAILABLE)
                    logging.info("RSE %s of site %s is problematic. Send a Jira ticket for the RSE (to be implemented)." % (rse, site))
                    # Remove the RSE from the dictionary as it has been dealt with.
                    del recoverable_replicas[vo][site][rse]
                # else:
                #     print("RSE %s only has %d suspicious replicas" % (rse, len(recoverable_replicas[vo][site][rse])))

    # recoverable_replicas should now only have RSEs that have less than *limit_suspicious_files_on_rse* suspicious replicas.
    # These replicas need to be dealt with individually
    # print(recoverable_replicas)
    return recoverable_replicas

















def run(once=False, younger_than=3, nattempts=10, rse_expression='MOCK', vos=None, max_replicas_per_rse=100):
    """
    Starts up the Suspicious-Replica-Recoverer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    client_time, db_time = datetime.utcnow(), get_db_time()
    max_offset = timedelta(hours=1, seconds=10)
    if isinstance(db_time, datetime):
        if db_time - client_time > max_offset or client_time - db_time > max_offset:
            logging.critical('Offset between client and db time too big. Stopping Suspicious-Replica-Recoverer.')
            return

    sanity_check(executable='rucio-replica-recoverer', hostname=socket.gethostname())

    if once:
        # declare_suspicious_replicas_bad(once, younger_than, nattempts, rse_expression, vos, max_replicas_per_rse)
        declare_suspicious_replicas_bad(once, younger_than, nattempts, vos, max_replicas_per_rse)
    else:
        logging.info('Suspicious file replicas recovery starting 1 worker.')
        # t = threading.Thread(target=declare_suspicious_replicas_bad,
        #                      kwargs={'once': once, 'younger_than': younger_than,
        #                              'nattempts': nattempts, 'rse_expression': rse_expression,
        #                              'vos': vos, 'max_replicas_per_rse': max_replicas_per_rse})
        t = threading.Thread(target=declare_suspicious_replicas_bad,
                             kwargs={'once': once, 'younger_than': younger_than,
                                     'nattempts': nattempts,
                                     'vos': vos, 'max_replicas_per_rse': max_replicas_per_rse})
        t.start()
        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while t.isAlive():
            t.join(timeout=3.14)


def stop():
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()

run(once=True)
