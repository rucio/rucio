from datetime import datetime
from datetime import timedelta
from nose.tools import eq_
from nose.tools import ok_
from rucio.common.dumper import consistency
from rucio.common.dumper import data_models
from rucio.daemons import auditor
from rucio.daemons.auditor import srmdumps
from rucio.tests.common import stubbed
import tempfile


def test_total_seconds():
    dif = timedelta(days=1, hours=1, minutes=1, seconds=1, microseconds=1)
    ok_(abs(auditor.total_seconds(dif) - 90061) < 0.01)


def test_auditor_download_dumps_with_expected_dates():
    def mock_fn_wrapper(return_value):
        calls = []

        def mock_fn(*args, **kwargs):
            calls.append({
                'args': args,
                'kwargs': kwargs,
            })
            return return_value

        return mock_fn, calls

    date = datetime.strptime('01-01-2015', '%d-%m-%Y')

    fake_srm_download, fake_srm_download_calls = mock_fn_wrapper(('', date))
    fake_rrd_download, fake_rrd_download_calls = mock_fn_wrapper('')
    fake_consistency_dump, fake_consistency_dump_calls = mock_fn_wrapper('')
    tmp_dir = tempfile.mkdtemp()

    with stubbed(srmdumps.download_rse_dump, fake_srm_download):
        with stubbed(data_models.Replica.download, fake_rrd_download):
            with stubbed(consistency.Consistency.dump, fake_consistency_dump):
                auditor.consistency('RSENAME', timedelta(days=3), None, cache_dir=tmp_dir, results_dir=tmp_dir)

    eq_(
        fake_rrd_download_calls[0]['args'][2],
        date.strptime('29-12-2014', '%d-%m-%Y')
    )

    eq_(
        fake_rrd_download_calls[1]['args'][2],
        date.strptime('04-01-2015', '%d-%m-%Y')
    )


# def test_auditor_check_survives_failures():
#     queue = Queue.Queue()
#     queue.put(('RSE_WITH_EXCEPTION', 0))
#     queue.put(('RSE_SHOULD_WORK', 0))
#     queue.put(('RSE_WITH_ERROR', 0))
#     rd_pipe, wr_pipe = multiprocessing.Pipe(False)
#
#     def fake_consistency(rse, delta, configuration, cache_dir, results_dir):
#         if rse == 'RSE_WITH_EXCEPTION':
#             raise Exception
#         elif rse == 'RSE_SHOULD_WORK':
#             pass
#         else:
#             return 1 / 0
#
#     state = {'call': 0}
#
#     def fake_event_is_set(slf):
#         state['call'] += 1
#         if state['call'] < 4:
#             return False
#         return True
#
#     terminate = multiprocessing.Event()
#     with stubbed(auditor.consistency, fake_consistency):
#         with stubbed(terminate.is_set, fake_event_is_set):
#             auditor.check(queue, terminate, wr_pipe, None, None)
