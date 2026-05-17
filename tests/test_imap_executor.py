import threading

from postara.imap_executor import ImapExecutor


def test_imap_executor_runs_sync_work_off_calling_thread():
    caller_thread = threading.get_ident()
    executor = ImapExecutor(max_workers=1)

    worker_thread = executor.run(account_id=1, func=threading.get_ident)

    assert worker_thread != caller_thread
