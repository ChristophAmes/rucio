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
# - Christoph Ames <christoph.ames@cern.ch>, 2021

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

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get_bool
from rucio.common.exception import DatabaseException, VONotFound
from rucio.common.logging import setup_logging
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.replica import list_replicas, get_suspicious_files
from rucio.core.rse import list_rses
from rucio.core.vo import list_vos
from rucio.db.sqla.util import get_db_time

GRACEFUL_STOP = threading.Event()


logging.basicConfig(filename='suspicious_replica_recoverer.log', level=logging.DEBUG)

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
            worker_number = heartbeat['assign_thread'] + 1

            # there is only 1 worker allowed for this daemon
            if total_workers != 1:
                logging.error('replica_recoverer: Another running instance on %s has been detected. Stopping gracefully.', socket.gethostname())
                die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
                break

            start = time.time()

            logging.info('replica_recoverer[%i/%i]: Ready to query replicas which were'
                         + ' reported as suspicious in the last %i days at least %i times.',  # NOQA: W503
                         worker_number, total_workers, younger_than, nattempts)

            getfileskwargs = {'younger_than': younger_than,
                              'nattempts': nattempts,
                              'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                              'available_elsewhere': True,
                              'is_suspicious': True}

            for vo in vos:
                logging.info('replica_recoverer[%i/%i]: Start replica recovery for VO: %s', worker_number, total_workers, vo)
                recoverable_replicas = {}
                if vo not in recoverable_replicas:
                    recoverable_replicas[vo]={}
                rse_list = list_rses()
                logging.debug("List of RSEs: \n %s", rse_list)
                # Remove RSEs from the list that have been labeled as deleted or where the RSE expression does not end with "DATADISK" or "SCRATCHDISK"
                rse_list[:] = [rse for rse in rse_list if ((rse['deleted'] is False) and (rse['rse'].split("_")[-1] in {"DATADISK", "SCRATCHDISK"}))]

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
                    logging.debug('Suspicious replicas on RSE %s: \n %s', rse_expr, suspicious_replicas)

                    if (rse['availability'] not in {4, 5, 6, 7}) and (len(suspicious_replicas) > 0):
                        logging.warning("replica_recoverer[%i/%i]: %s is labeled as unavailable, yet is has suspicious replicas. Please investigate." % rse_expr)
                        continue
                    if suspicious_replicas:
                        for replica in suspicious_replicas:
                            if vo == replica['scope'].vo:
                                scope = replica['scope']
                                rep_name = replica['name']
                                rse_id = replica['rse_id']
                                surl_not_found = True
                                for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                                    for rse_ in rep['rses']:
                                        if rse_ == rse_id:
                                            recoverable_replicas[vo][site][rse_expr][rep_name] = {'name': rep_name, 'rse_id': rse_id, 'scope': scope, 'surl': rep['rses'][rse_][0]}
                                            surl_not_found = False
                                if surl_not_found:
                                    cnt_surl_not_found += 1
                                    logging.warning('replica_recoverer[%i/%i]: Skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, rep_name, rse_expr)
                    logging.info('replica_recoverer[%i/%i]: Suspicious replica query took %.2f seconds on %s, %i/%i replicas were found.',
                                 worker_number, total_workers, time.time() - time_start_rse, rse_expr, len(suspicious_replicas) - cnt_surl_not_found, len(suspicious_replicas))
                    logging.debug('List of replicas on %s for which the pfns have been found: %s' % (rse_expr, recoverable_replicas[vo][site][rse_expr]))
                logging.info('replica_recoverer[%i/%i]: All RSEs have been checked for suspicious replicas. Total time: %.2f seconds.', worker_number, total_workers, time.time() - start)
                logging.info('replica_recoverer[%i/%i]: Begin check for problematic sites and RSEs.', worker_number, total_workers)
                time_start_check_probl = time.time()

                for site in list(recoverable_replicas[vo].keys()):
                    logging.debug('All RSEs and their suspicious replicas on site %s: \n %s', site, recoverable_replicas[vo][site])
                    clean_rses = 0
                    for rse_key, rse_value in recoverable_replicas[vo][site].items():
                        if len(rse_value) == 0:
                            # RSE has no suspicious replicas
                            clean_rses += 1
                    if len(recoverable_replicas[vo][site]) == clean_rses:
                        logging.info('replica_recoverer[%i/%i]: No RSEs on site %s have suspicious replicas.', worker_number, total_workers, site)
                        del recoverable_replicas[vo][site]
                        continue

                # for site in list(recoverable_replicas[vo].keys()):
                    count_problematic_rse = 0  # Number of RSEs with less than *limit_suspicious_files_on_rse* suspicious replicas
                    list_problematic_rses = []
                    for rse_key, rse_value in recoverable_replicas[vo][site].items():
                        if len(rse_value) > limit_suspicious_files_on_rse:
                            count_problematic_rse += 1
                            list_problematic_rses.append(rse_key)
                    if len(recoverable_replicas[vo][site].values()) == count_problematic_rse:
                        # All RSEs on the site have been deemed problematic -> site has a problem
                        # Mark all of the replicas on the site as TEMPORARY_UNAVAILABLE
                        for rse_key, rse_value in recoverable_replicas[vo][site].items():
                            surls_list = []
                            for replica_key, replica_value in rse_value.items():
                                surls_list.append(replica_value['surl'])
                            logging.debug('List of pfns that will be labeled as TEMPORARY_UNAVAILABLE on %s: \n %s', rse_key, surls_list)
                            ###########
                            # REMOVED FOR TEST:
                            # add_bad_pfns(pfns=surls_list, account=ACCOUNT?, state=TEMPORARY_UNAVAILABLE) # What is an account in this case?
                            ###########
                        logging.info("replica_recoverer[%i/%i]: All RSEs on site %s are problematic. Send a Jira ticket for the site (to be implemented).", worker_number, total_workers, site)
                        # Remove the site from the dictionary as it has been dealt with.
                        del recoverable_replicas[vo][site]
                        continue

                    # Only specific RSEs of a site have too many suspicious replicas and are therefore problematic. Check RSEs individually.
                    for rse in list_problematic_rses:
                        logging.debug('Suspicious replicas on %s: \n %s', rse, recoverable_replicas[vo][site][rse].values())
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
                            logging.info("replica_recoverer[%i/%i]: %s on site %s is problematic (more than %i suspicious replicas). Send a Jira ticket for the RSE (to be implemented).", worker_number, total_workers, rse, site, limit_suspicious_files_on_rse)
                            # Remove the RSE from the dictionary as it has been dealt with.
                            del recoverable_replicas[vo][site][rse]

                # Label remaining suspicious replicas as bad
                # for site in recoverable_replicas[vo].keys():
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
                        logging.debug('(%s) Remaining pfns that will be marked BAD: \n %s', rse_key, remaining_surls)
                        logging.info('replica_recoverer[%i/%i]: Ready to declare %i bad replica(s) on %s (RSE id: %s).',
                                     worker_number, total_workers, len(remaining_surls), rse_key, str(rse_id))
                        ###########
                        # REMOVED FOR TEST:
                        # declare_bad_file_replicas(pfns=remaining_surls, reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), status=BadFilesStatus.BAD, session=None)
                        ###########
                        logging.info('replica_recoverer[%i/%i]: Finished declaring bad replicas on %s.', worker_number, total_workers, rse_key)

                logging.info('replica_recoverer[%i/%i]: Finished checking for problematic sites and RSEs. Total time: %.2f seconds.', worker_number, total_workers, time.time() - time_start_check_probl)

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
        declare_suspicious_replicas_bad(once, younger_than, nattempts, vos, max_replicas_per_rse)
    else:
        logging.info('Suspicious file replicas recovery starting 1 worker.')
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
