import pytest

from backend.core.jobs import JobManager
from backend.exceptions import JobNotFound
from backend.schemas import JobStatus, Report, ScanRequest, StageStatus, TargetType

STAGES = [("a", "Stage A", 1.0), ("b", "Stage B", 3.0)]


def _request():
    return ScanRequest(target_type=TargetType.GITHUB_REPO, target="https://github.com/a/b")


def test_lifecycle_and_weighted_progress():
    jobs = JobManager()
    job = jobs.create(_request(), label="a/b")
    assert jobs.view(job.job_id).status == JobStatus.QUEUED

    assert jobs.start(job.job_id, STAGES)
    jobs.begin_stage(job.job_id, "a")
    jobs.finish_stage(job.job_id, "a")
    assert jobs.view(job.job_id).progress == 25

    jobs.begin_stage(job.job_id, "b")
    jobs.update_stage(job.job_id, "b", detail="halfway", fraction=0.5)
    view = jobs.view(job.job_id)
    assert view.progress == 62
    assert view.current_stage == "Stage B"
    assert view.stages[1].detail == "halfway"

    jobs.update_stage(job.job_id, "b", fraction=0.1)
    assert jobs.view(job.job_id).progress == 62

    report = Report(target="a/b")
    jobs.complete(job.job_id, report)
    view = jobs.view(job.job_id)
    assert view.status == JobStatus.COMPLETED
    assert view.progress == 100
    assert view.report_id == report.report_id
    assert all(stage.status == StageStatus.DONE for stage in view.stages)


def test_failure_marks_open_stages():
    jobs = JobManager()
    job = jobs.create(_request())
    jobs.start(job.job_id, STAGES)
    jobs.begin_stage(job.job_id, "a")
    jobs.fail(job.job_id, "boom")
    view = jobs.view(job.job_id)
    assert view.status == JobStatus.FAILED and view.error == "boom"
    assert [s.status for s in view.stages] == [StageStatus.FAILED, StageStatus.SKIPPED]


def test_cancelling_a_queued_job_prevents_it_from_starting():
    jobs = JobManager()
    job = jobs.create(_request())
    view = jobs.cancel(job.job_id)
    assert view.status == JobStatus.CANCELLED
    assert job.token.cancelled
    assert not jobs.start(job.job_id, STAGES)


def test_cancelling_a_running_job_signals_the_token():
    jobs = JobManager()
    job = jobs.create(_request())
    jobs.start(job.job_id, STAGES)
    assert jobs.cancel(job.job_id).status == JobStatus.RUNNING
    assert job.token.cancelled


def test_unknown_job_raises():
    with pytest.raises(JobNotFound):
        JobManager().view("job_missing")


def test_trim_keeps_unfinished_jobs_and_orders_newest_first():
    jobs = JobManager(max_jobs=2)
    first = jobs.create(_request())
    jobs.start(first.job_id, STAGES)
    second = jobs.create(_request())
    jobs.fail(second.job_id, "x")
    third = jobs.create(_request())
    ids = [view.job_id for view in jobs.list_views()]
    assert ids == [third.job_id, first.job_id]
    assert jobs.counts() == (1, 1)
