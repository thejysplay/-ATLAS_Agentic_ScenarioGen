"""
spectra_oracle.py - AppWorld DB diff 기반 공용 오라클 러너 (뼈대).

무엇을 하나
-----------
AppWorld 의 정답 채점기(evaluator)는 task 별 ground_truth 파이썬 모듈에 의존한다.
SPECTRA 는 "공격이 실제로 세계 상태를 바꿨는가"를 task 와 무관하게 보고 싶으므로,
채점기 대신 **DB 스냅샷 diff** 를 오라클로 쓴다.

파이프라인 (evaluator.py:478-500 이 쓰는 것과 동일한 구조):

    Task.load(task_id)                      -> task.model_collection  = START 상태
    ModelCollection.load(from_db_home_path) -> 실행 후 dbs/           = END 상태
    ModelCollectionPair(start, end)         -> .changed_model_names()
                                               .changed_records(model_name)
                                                  -> (added, updated, removed)

즉 "어느 앱의 어느 테이블의 어느 행이 추가/수정/삭제됐는지"가 나온다.

주의
----
- 시간이 얼어있어야 한다. AppWorld 는 task.datetime 으로 시간을 고정한 채 DB 를
  만들었기 때문에, diff 를 뜰 때도 set_local_date_and_time(task.datetime) 을 건다.
  (evaluator.py:470 과 동일)
- END dbs 경로는 두 군데일 수 있다:
    experiments/outputs/<exp>/tasks/<id>/dbs   (다음 실행 때 rmtree 로 삭제됨)
    spectra_backups/<exp>/<id>/<ts>/dbs        (spectra_backup.py 가 뜬 스냅샷, 안전)
  둘 다 지원한다.

사용법
------
    from spectra_oracle import diff_task

    report = diff_task(task_id="6bdbc26_1", experiment_name="my_exp")
    print(report.summary())
    for change in report.changes:
        print(change.model_name, change.kind, change.record_id, change.fields)

CLI
---
    python spectra_oracle.py <task_id> <experiment_name>
    python spectra_oracle.py <task_id> --end-dbs <백업디렉터리>/dbs
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

# APPWORLD_ROOT 확정 (appworld import 이전이어야 한다)
APPWORLD_ROOT = os.environ.setdefault(
    "APPWORLD_ROOT", os.path.dirname(os.path.abspath(__file__))
)

# diff 에서 기본으로 무시할 앱/테이블. (인프라성 테이블은 노이즈)
DEFAULT_IGNORE_MODELS: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# 결과 자료구조
# ---------------------------------------------------------------------------
@dataclass
class RecordChange:
    model_name: str  # "spotify.SongLike" 형태 (app.ModelClass)
    kind: str  # "added" | "updated" | "removed"
    record_id: Any
    fields: dict


@dataclass
class DiffReport:
    task_id: str
    instruction: str
    start_db_home_path: str
    end_db_home_path: str
    changed_model_names: list[str] = field(default_factory=list)
    changes: list[RecordChange] = field(default_factory=list)

    @property
    def num_added(self) -> int:
        return sum(1 for c in self.changes if c.kind == "added")

    @property
    def num_updated(self) -> int:
        return sum(1 for c in self.changes if c.kind == "updated")

    @property
    def num_removed(self) -> int:
        return sum(1 for c in self.changes if c.kind == "removed")

    @property
    def state_changed(self) -> bool:
        return bool(self.changes)

    def summary(self) -> str:
        lines = [
            f"task_id            : {self.task_id}",
            f"instruction        : {self.instruction}",
            f"start dbs          : {self.start_db_home_path}",
            f"end   dbs          : {self.end_db_home_path}",
            f"changed models     : {len(self.changed_model_names)} "
            f"-> {sorted(self.changed_model_names)}",
            f"records            : +{self.num_added} added / "
            f"~{self.num_updated} updated / -{self.num_removed} removed",
            f"STATE_CHANGED      : {self.state_changed}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "instruction": self.instruction,
            "start_db_home_path": self.start_db_home_path,
            "end_db_home_path": self.end_db_home_path,
            "changed_model_names": sorted(self.changed_model_names),
            "state_changed": self.state_changed,
            "counts": {
                "added": self.num_added,
                "updated": self.num_updated,
                "removed": self.num_removed,
            },
            "changes": [
                {
                    "model_name": c.model_name,
                    "kind": c.kind,
                    "record_id": c.record_id,
                    "fields": c.fields,
                }
                for c in self.changes
            ],
        }


# ---------------------------------------------------------------------------
# 경로 해석
# ---------------------------------------------------------------------------
def output_dbs_path(experiment_name: str, task_id: str) -> str:
    return os.path.join(
        APPWORLD_ROOT, "experiments", "outputs", experiment_name, "tasks", task_id, "dbs"
    )


# ---------------------------------------------------------------------------
# 핵심
# ---------------------------------------------------------------------------
def diff_task(
    task_id: str,
    experiment_name: str | None = None,
    end_dbs_path: str | None = None,
    max_records_per_model: int = 50,
    include_fields: bool = True,
) -> DiffReport:
    """
    task 의 초기 DB(START) 와 실행 후 DB(END) 를 비교한 DiffReport 반환.

    experiment_name 또는 end_dbs_path 중 하나는 반드시 줘야 한다.
    end_dbs_path 를 주면 그쪽이 우선한다 (백업 스냅샷 재평가용).
    """
    from appworld.apps.api_lib import set_local_date_and_time
    from appworld.apps.model_lib import get_db_home_path
    from appworld.collections.models import ModelCollection, ModelCollectionPair
    from appworld.task import Task

    if not end_dbs_path:
        if not experiment_name:
            raise ValueError("experiment_name 또는 end_dbs_path 중 하나는 필요하다.")
        end_dbs_path = output_dbs_path(experiment_name, task_id)
    if not os.path.isdir(end_dbs_path):
        raise FileNotFoundError(f"END dbs 디렉터리가 없다: {end_dbs_path}")

    # ground truth 는 diff 에 필요 없다. 로딩 비용/실패 회피를 위해 끈다.
    task = Task.load(task_id=task_id, load_ground_truth=False)

    # evaluator.py:470 과 동일하게 시간 고정
    time_freezer = set_local_date_and_time(task.datetime)
    try:
        models_start = task.model_collection
        start_db_home_path = task.model_collection.from_db_home_path

        # END 는 디스크의 dbs 를 읽어 in-memory 로 올린다 (evaluator.py:490 과 동일 패턴).
        # to_db_home_path 를 메모리로 둬야 원본 백업 파일을 건드리지 않는다.
        end_db_home_path_in_memory = get_db_home_path(
            storage_type="memory",
            type="task_output",
            task_id=task_id + "__spectra_oracle",
        )
        models_end = ModelCollection.load(
            to_db_home_path=end_db_home_path_in_memory,
            from_db_home_path=end_dbs_path,
            load_apps=task.allowed_apps,
        )
        pair = ModelCollectionPair(
            start_db_home_path=start_db_home_path,
            start_model_collection=models_start,
            end_db_home_path=end_db_home_path_in_memory,
            end_model_collection=models_end,
        )

        changed = sorted(pair.changed_model_names())
        report = DiffReport(
            task_id=task_id,
            instruction=task.instruction,
            start_db_home_path=start_db_home_path,
            end_db_home_path=end_dbs_path,
            changed_model_names=changed,
        )

        for model_name in changed:
            if model_name in DEFAULT_IGNORE_MODELS:
                continue
            added, updated, removed = pair.changed_records(model_name)
            for kind, records in (
                ("added", added),
                ("updated", updated),
                ("removed", removed),
            ):
                for record in records[:max_records_per_model]:
                    report.changes.append(
                        RecordChange(
                            model_name=model_name,
                            kind=kind,
                            record_id=getattr(record, "id", None),
                            fields=_record_fields(record) if include_fields else {},
                        )
                    )
        return report
    finally:
        time_freezer.stop()


def _record_fields(record: Any, max_len: int = 300) -> dict:
    """SQLModel 레코드를 JSON 직렬화 가능한 dict 로."""
    try:
        raw = record.to_dict()
    except Exception:  # noqa: BLE001
        try:
            raw = {c.name: getattr(record, c.name) for c in record.__table__.columns}
        except Exception:  # noqa: BLE001
            return {"_repr": str(record)[:max_len]}
    out: dict = {}
    for key, value in raw.items():
        if isinstance(value, (str, bytes)) and len(value) > max_len:
            value = value[:max_len] + f"...<{len(value)} chars>"
        elif not isinstance(value, (str, int, float, bool, type(None))):
            value = str(value)[:max_len]
        out[key] = value
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="AppWorld DB diff 오라클")
    parser.add_argument("task_id")
    parser.add_argument("experiment_name", nargs="?", default=None)
    parser.add_argument("--end-dbs", dest="end_dbs", default=None)
    parser.add_argument("--json", dest="as_json", action="store_true")
    parser.add_argument("--max-records", type=int, default=50)
    args = parser.parse_args()

    report = diff_task(
        task_id=args.task_id,
        experiment_name=args.experiment_name,
        end_dbs_path=args.end_dbs,
        max_records_per_model=args.max_records,
    )
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str))
    else:
        print(report.summary())
        print()
        for change in report.changes:
            print(f"[{change.kind:<7}] {change.model_name} id={change.record_id}")
            for key, value in change.fields.items():
                print(f"          {key} = {value!r}")


if __name__ == "__main__":
    main()
