"""
spectra_backup.py - AppWorld 실험 산출물(DB/로그) 백업 유틸.

왜 필요한가
-----------
AppWorld.__init__ -> _prepare_directories() 는 매 실행마다
    shutil.rmtree(experiments/outputs/<exp>/tasks/<task_id>)
를 무조건 호출한다 (environment.py:434).
즉 같은 (experiment_name, task_id) 로 두 번째 실행하는 순간
첫 실행의 DB(dbs/*.db) 와 로그가 통째로 삭제된다.
실험 후 재평가/포렌식이 필요한 SPECTRA 쪽에서는 치명적이므로,
종료 시점에 rmtree 가 절대 닿지 않는 곳으로 스냅샷을 떠둔다.

AppWorld 패키지는 건드리지 않는다. 바깥에서 감싸는 방식만 쓴다.

백업 위치
---------
    <APPWORLD_ROOT>/spectra_backups/<experiment_name>/<task_id>/<UTC타임스탬프>[__label]/
        dbs/        <- 앱별 sqlite (종료 시점 최종 상태)
        logs/       <- api_calls.jsonl, environment_io.md
        misc/
        version/
        manifest.json  <- 백업 메타데이터 (SPECTRA 가 추가로 붙임)

사용법
------
1) 컨텍스트 매니저 (권장)

    from spectra_backup import backed_up_world

    with backed_up_world(task_id="6bdbc26_1", experiment_name="my_exp") as world:
        world.execute("print(apis.api_docs.show_app_descriptions())")
    # 블록을 나갈 때 자동 백업. world.spectra_backup_path 에 경로가 담긴다.

2) 수동 호출

    from spectra_backup import backup_task_output, flush_world_state
    flush_world_state(world)                       # 디스크에 최신 상태 강제 기록
    path = backup_task_output("my_exp", "6bdbc26_1", label="after_attack")

3) 조회 / 복원

    list_backups("my_exp")                         # 백업 목록
    latest_backup("my_exp", "6bdbc26_1")           # 가장 최근 백업 경로
    restore_backup(path, "my_exp", "6bdbc26_1")    # outputs 로 되돌리기
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# APPWORLD_ROOT 고정. appworld 를 import 하기 전에 반드시 끝나야 한다.
# (path_store.py:14 -- os.environ.get("APPWORLD_ROOT", os.getcwd()))
# ---------------------------------------------------------------------------
APPWORLD_ROOT = os.environ.setdefault(
    "APPWORLD_ROOT", os.path.dirname(os.path.abspath(__file__))
)

BACKUP_ROOT = os.path.join(APPWORLD_ROOT, "spectra_backups")

# 백업 대상 하위 디렉터리. AppWorld 가 tasks/<id>/ 아래 만드는 것들.
_SUBDIRS = ("dbs", "logs", "misc", "version", "checkpoints")


# ---------------------------------------------------------------------------
# 경로 헬퍼
# ---------------------------------------------------------------------------
def task_output_dir(experiment_name: str, task_id: str) -> str:
    """AppWorld 가 실제로 쓰는(그리고 다음 실행 때 지우는) 디렉터리."""
    return os.path.join(
        APPWORLD_ROOT, "experiments", "outputs", experiment_name, "tasks", task_id
    )


def backup_dir(experiment_name: str, task_id: str) -> str:
    return os.path.join(BACKUP_ROOT, experiment_name, task_id)


def _real_now() -> datetime:
    """
    진짜 현재 시각.

    주의: AppWorld 는 task.datetime 으로 프로세스 전역 시간을 얼린다(freezegun).
    그래서 world 안/직후에 datetime.now() 를 부르면 실행 시각이 아니라
    task 의 가상 시각(예: 2023-05-18 12:00:00)이 나오고,
    서로 다른 두 실행이 완전히 같은 타임스탬프를 갖게 된다.
    freezegun 이 보관한 real_datetime 을 우선 쓴다.
    """
    try:
        from freezegun.api import real_datetime  # type: ignore[attr-defined]

        return real_datetime.now(timezone.utc)
    except Exception:  # noqa: BLE001
        return datetime.now(timezone.utc)


def _timestamp() -> str:
    # 얼린 시간이 뚫리는 경우까지 대비해 짧은 랜덤 접미사로 충돌을 원천 차단한다.
    return (
        _real_now().strftime("%Y%m%dT%H%M%S_%fZ")
        + "_"
        + uuid.uuid4().hex[:6]
    )


# ---------------------------------------------------------------------------
# 상태 flush
# ---------------------------------------------------------------------------
def flush_world_state(world: Any) -> None:
    """
    메모리 DB -> 디스크로 강제 기록.

    AppWorld 는 execute() 끝날 때마다 _save_state() 를 부르므로 보통은 이미
    최신이지만, execute 없이 apis 를 직접 호출한 경우엔 디스크가 뒤처진다.
    백업 직전에 한 번 더 부른다. (private 메서드지만 패키지 수정은 아니다.)
    """
    try:
        world._save_state(world.output_db_home_path_on_disk)
    except Exception as error:  # noqa: BLE001
        print(f"[spectra_backup] WARN: _save_state 실패: {error!r}")
    try:
        world.save_logs()
    except Exception as error:  # noqa: BLE001
        print(f"[spectra_backup] WARN: save_logs 실패: {error!r}")


# ---------------------------------------------------------------------------
# 백업
# ---------------------------------------------------------------------------
def backup_task_output(
    experiment_name: str,
    task_id: str,
    label: str | None = None,
    extra: dict | None = None,
    quiet: bool = False,
) -> str | None:
    """
    experiments/outputs/<exp>/tasks/<task_id> 를 spectra_backups/ 로 복사.

    반환: 백업 디렉터리 절대경로. 원본이 없으면 None.
    """
    source = task_output_dir(experiment_name, task_id)
    if not os.path.isdir(source):
        if not quiet:
            print(f"[spectra_backup] 원본 없음, 건너뜀: {source}")
        return None

    name = _timestamp() + (f"__{label}" if label else "")
    destination = os.path.join(backup_dir(experiment_name, task_id), name)
    os.makedirs(destination, exist_ok=True)

    copied: dict[str, dict] = {}
    for sub in _SUBDIRS:
        src_sub = os.path.join(source, sub)
        if not os.path.isdir(src_sub):
            continue
        dst_sub = os.path.join(destination, sub)
        shutil.copytree(src_sub, dst_sub, dirs_exist_ok=True)
        files = sorted(os.listdir(dst_sub))
        copied[sub] = {
            "num_files": len(files),
            "bytes": sum(
                os.path.getsize(os.path.join(dst_sub, f))
                for f in files
                if os.path.isfile(os.path.join(dst_sub, f))
            ),
            "files": files[:50],
        }

    # tasks/<id> 바로 아래 떨어지는 낱개 파일도 챙긴다.
    for entry in sorted(os.listdir(source)):
        full = os.path.join(source, entry)
        if os.path.isfile(full):
            shutil.copy2(full, os.path.join(destination, entry))

    manifest = {
        "experiment_name": experiment_name,
        "task_id": task_id,
        "label": label,
        "backed_up_at_utc": _real_now().isoformat(),
        "appworld_root": APPWORLD_ROOT,
        "source_dir": source,
        "backup_dir": destination,
        "copied": copied,
    }
    if extra:
        manifest["extra"] = extra
    with open(os.path.join(destination, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)

    if not quiet:
        total = sum(v["bytes"] for v in copied.values())
        print(f"[spectra_backup] 백업 완료 -> {destination}  ({total:,} bytes)")
    return destination


# ---------------------------------------------------------------------------
# 컨텍스트 매니저
# ---------------------------------------------------------------------------
@contextmanager
def backed_up_world(
    task_id: str,
    experiment_name: str,
    label: str | None = None,
    backup_on_error: bool = True,
    **appworld_kwargs: Any,
) -> Iterator[Any]:
    """
    AppWorld 를 열고, 블록을 나갈 때 산출물을 자동 백업한다.

    with backed_up_world(task_id="6bdbc26_1", experiment_name="exp") as world:
        world.execute(...)

    백업 경로는 world.spectra_backup_path 에 들어간다.
    예외가 나도 (backup_on_error=True 면) 백업은 뜨고 예외는 그대로 올라간다.
    """
    from appworld import AppWorld  # noqa: PLC0415  (APPWORLD_ROOT 확정 후 import)

    world = AppWorld(task_id=task_id, experiment_name=experiment_name, **appworld_kwargs)
    world.spectra_backup_path = None
    failed = False
    try:
        yield world
    except BaseException:
        failed = True
        raise
    finally:
        try:
            if not failed or backup_on_error:
                flush_world_state(world)
                world.spectra_backup_path = backup_task_output(
                    experiment_name,
                    task_id,
                    label=(label or ("error" if failed else None)),
                    extra={
                        "instruction": getattr(world.task, "instruction", None),
                        "num_interactions": getattr(world, "num_interactions", None),
                        "task_completed": _safe_task_completed(world),
                        "errored": failed,
                    },
                )
        finally:
            world.close()


def _safe_task_completed(world: Any) -> Any:
    try:
        return world.task_completed()
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# 조회 / 복원
# ---------------------------------------------------------------------------
def list_backups(experiment_name: str, task_id: str | None = None) -> list[str]:
    root = os.path.join(BACKUP_ROOT, experiment_name)
    if not os.path.isdir(root):
        return []
    task_ids = [task_id] if task_id else sorted(os.listdir(root))
    out: list[str] = []
    for tid in task_ids:
        tdir = os.path.join(root, tid)
        if not os.path.isdir(tdir):
            continue
        out += [os.path.join(tdir, d) for d in sorted(os.listdir(tdir))]
    return out


def latest_backup(experiment_name: str, task_id: str) -> str | None:
    backups = list_backups(experiment_name, task_id)
    return backups[-1] if backups else None


def restore_backup(backup_path: str, experiment_name: str, task_id: str) -> str:
    """백업을 experiments/outputs 자리로 되돌린다 (재평가용)."""
    destination = task_output_dir(experiment_name, task_id)
    os.makedirs(destination, exist_ok=True)
    for sub in _SUBDIRS:
        src_sub = os.path.join(backup_path, sub)
        if os.path.isdir(src_sub):
            shutil.copytree(src_sub, os.path.join(destination, sub), dirs_exist_ok=True)
    print(f"[spectra_backup] 복원 완료 {backup_path} -> {destination}")
    return destination


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 3 and sys.argv[1] == "backup":
        backup_task_output(sys.argv[2], sys.argv[3], label=(sys.argv[4] if len(sys.argv) > 4 else None))
    elif len(sys.argv) >= 3 and sys.argv[1] == "list":
        for p in list_backups(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None):
            print(p)
    else:
        print(__doc__)
        print(f"APPWORLD_ROOT = {APPWORLD_ROOT}")
        print(f"BACKUP_ROOT   = {BACKUP_ROOT}")
