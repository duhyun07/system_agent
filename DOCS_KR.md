# System Agent — 한국어 문서

System Agent는 Google의 공식 **kernelCTF** 프로그램 전용 로컬 우선(local-first)
Linux 커널 연구 플랫폼입니다. 공식 문서 기반 환경 설정(온라인)에서 시작해,
오프라인 커널 소스 분석·크래시 트리아지·보고서 작성까지 이어지는 워크플로를
제공합니다. 두 가지 AI 책임을 엄격히 분리합니다.

- **온라인 (OpenAI GPT):** 공식 문서 조사, 환경 준비 안내, 환경 검증. (Phase A)
- **오프라인 (Ollama):** 로컬 커널 소스 분석, 후보 취약점 발견, 크래시 트리아지,
  리그레션 분석, 보고. (Phase B)

메인 오케스트레이터 클래스는 `core.orchestrator.SystemAgent`, CLI 명령은
`system-agent`입니다.

> **범위 / 안전 원칙**
> 산출물은 **근거 기반 근본원인 분석·트리아지·보고서**이며, 익스플로잇 코드,
> 권한 상승, 지속성(persistence), 커널 보호 우회는 구현하지 않습니다. 동적
> 테스트는 승인된 격리 VM에서만 수행합니다. 후보 발견(finding)은 재현되기
> 전까지는 항상 **가설(hypothesis)** 이며, 검증되지 않은 발견을 확정 취약점으로
> 표시하지 않습니다.

---

## 1. 설치

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/system-agent doctor
```

의존성: `httpx`, 공식 `openai` SDK, `PyYAML`, `jsonschema`, `regex`.
API 키는 환경변수에서 읽으며 `.env`는 자동 로드되지 않습니다.

테스트 실행(이 호스트의 ROS pytest 플러그인 충돌을 피하기 위해):

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q
```

---

## 2. 모드와 프로바이더

- **offline** (기본): 루프백의 로컬 Ollama. Phase B 연구에 사용.
- **online**: OpenAI Responses API. Phase A 문서/설정에 사용.
  `OPENAI_API_KEY`, `openai_model`, 백만 토큰당 단가, 양수 `max_spend_usd`를
  `configs/online.yaml`에 설정해야 합니다.
- **hybrid**: 연구는 Ollama, 클라우드 추론은 명시적 `cloud` 명령(정확한 페이로드의
  SHA-256 승인)으로만. 자동 클라우드 폴백은 없습니다.

```bash
system-agent mode show
system-agent mode set offline   # 연구
system-agent mode set online    # 문서/설정
```

### 로컬 모델과 GPU

오프라인 프로바이더는 `127.0.0.1:11434`의 Ollama와 통신합니다. 기본값:
`qwen3:4b`(일반), `qwen2.5-coder:7b`(선택적 코드 분석), 컨텍스트 8192,
동시에 하나의 추론만 수행.

`configs/offline.yaml`의 `llm.num_gpu: 999`는 **GPU에 최대한 많은 레이어를
오프로드**합니다(RTX 4060 8GB). Ollama가 가용 VRAM에 맞춰 자동 조정합니다.
CPU 전용으로 강제하려면 `num_gpu: 0`으로 설정하세요. 배치 확인:

```bash
ollama ps        # qwen3:4b 가 "100% GPU" 로 표시되면 정상
```

---

## 3. 워크플로 단계 (상태 머신)

영속 상태 머신(`.system-agent-phase`)이 다음 진행을 강제합니다.

```
UNINITIALIZED → ONLINE_DOCUMENTATION → ONLINE_PROVISIONING
            → ENVIRONMENT_VERIFICATION → READY_FOR_OFFLINE
            → OFFLINE_RESEARCH → LOCAL_REPORTING
```

**핵심 안전 속성:** `OFFLINE_RESEARCH` 단계에 들어가면 자동으로 온라인 단계로
돌아가지 않습니다(오류가 온라인 복귀 사유가 되지 않음). 설정으로 재진입하려면
사용자의 명시적 행위(`reset_online`)가 필요합니다. 또한 오프라인 연구는 모드의
허용 도메인과 무관하게 **모든 네트워크 스킬이 비활성화된 상태**로 실행됩니다.

---

## 4. 처음 사용하기 (명령 순서)

```bash
# 1) 상태 점검
system-agent doctor          # 파이썬 의존성, 툴체인, QEMU/KVM, Ollama, 워크스페이스
system-agent status          # 현재 단계 + 오프라인 준비 상태 요약

# 2) 온라인 설정 (Phase A, 'setup docs'는 online 모드 필요)
system-agent mode set online
system-agent setup docs                 # 공식 kernelCTF 문서 조회/요약
system-agent setup known-issues         # 알려진/수정된 버그 + 패치 정보 수집(선택)
system-agent setup target list          # 설정된 타깃 인스턴스 목록
system-agent setup target select --instance lts --source /path/to/linux
system-agent setup dependencies         # 툴체인/QEMU/Ollama 점검
system-agent setup kernel               # 커널 트리 + 빌드 프로비넌스
system-agent setup qemu                 # 격리 VM용 QEMU/KVM 상태
system-agent setup verify               # 준비 게이트 → READY_FOR_OFFLINE

# 3) 오프라인 연구 진입
system-agent mode set offline
system-agent research prepare           # 전제조건 표시
system-agent research start --offline   # 게이트 통과 후 OFFLINE_RESEARCH 진입

# 4) 오프라인 커널 연구 (Ollama 전용, 네트워크 차단)
system-agent research source --subsystem mm
system-agent research memory --subsystem net/tls
system-agent research concurrency --subsystem fs
system-agent research patches --subsystem mm/slub.c

# 5) 크래시 분석/트리아지
system-agent crash analyze --input ./crash.log
system-agent crash triage --input ./crash.log --source /path/to/linux
system-agent crash list
system-agent crash known list

# 6) 발견(finding)과 보고서
system-agent findings list
system-agent findings show KERNEL-LOCAL-0001
system-agent report generate --program kctf

# 7) 감사 로그
system-agent audit show --task <task_id>
```

`models list`는 구성된 모델 로스터와 설치된 Ollama 모델을 보여주고,
`models test --provider ollama|openai`는 최소 연결 라운드트립을 수행합니다.

---

## 5. 스킬 (Skills)

- **파일시스템:** `read_file`, `write_file`, `edit_file`, `list_dir`,
  `search_files`, `grep`, `file_info`, `apply_patch`
- **네트워크:** `fetch`, `web_search`
- **커널 연구:** `kernel_source_search`, `kernel_function_lookup`,
  `kernel_callgraph_lookup`, `kernel_config_lookup`, `kernel_commit_diff`,
  `kernel_log_parse`, `kernel_crash_deduplicate`, `kernel_build_info`,
  `kernel_coverage_read`, `kernel_vm_status`, 그리고 CLI 전용·승인 게이트
  `kernel_test_run`.

모든 스킬에는 JSON 스키마 입력 검증, 구조화된 출력, 타임아웃, 권한 규칙,
워크스페이스 경로 검증, 감사 로깅, 명시적 오류 처리가 있습니다. **제한 없는 셸
스킬은 제공하지 않습니다.** `kernel_test_run`은 모델에게 노출되지 않고, 1회용
승인을 요구하며, 명시적 VM 격리 확인 없이는 실행을 거부하고, 모델이 생성한
코드를 절대 실행하지 않습니다.

모든 외부 문서·소스 파일·크래시 로그는 **신뢰할 수 없는 데이터**로 취급되며,
명령으로 해석되지 않습니다.

---

## 6. 크래시 트리아지와 신규성(Novelty) 판정

`crash triage`는 (신뢰할 수 없는) 로그를 파싱하고 원본을 **불변(immutable)** 으로
저장한 뒤, 해당 크래시가 이미 알려진 것인지 판정합니다.

- 로컬 크래시 인덱스(중복)와 알려진 이슈 레지스트리에 대해 시그니처를 대조하고,
  로컬 커널 git 히스토리에서 결함 심볼에 대한 업스트림 수정 커밋(1-day 지표)을
  상관분석합니다.
- **알려짐(known)** → 다른 크래시를 계속 탐색하도록 권고합니다.
- **신규(novel)** → 후보 발견(가설)을 기록하고 `reports/<finding_id>.md`에
  보고서 초안을 작성합니다.

알려진 이슈 레지스트리는 온라인에서(`setup known-issues`) 또는 수동으로
채웁니다.

```bash
system-agent crash known add --signature crash:3bb7d2a5 --fix-commit <sha> --note "already submitted"
```

---

## 7. 발견(Findings)과 보고서

발견은 기본적으로 `hypothesis`/`not_tested` 상태이며, 저장소는 재현되지 않은
발견을 확정으로 표시하는 것을 거부합니다. `validated`는 오직
`validation.status=reproduced`(그리고 `reproducible=true`)일 때만 허용됩니다.

기록되는 발견 스키마(핵심 필드): `finding_id`, `status`, `bug_class`,
`subsystem`, `source_file`, `function`, `line_range`, `kernel_commit`,
`target_config`, `reasoning`, `evidence`, `contradictory_evidence`,
`validation{status, reproducible}`, `confidence`, `fix_references`.

---

## 8. 로컬 재현 환경과 동적 테스트

```bash
system-agent env init kctf --instance lts --source /path/to/linux
```

검토 가능한 로컬 QEMU 재현/디버그 환경(부팅 스크립트, gdb 헬퍼, config 노트,
fetch 체크리스트, 매니페스트)을 생성합니다. **아무것도 다운로드·빌드·실행하지
않습니다.** 공식 릴리스 아티팩트는 사용자가 직접 받고, 스크립트를 검토하고, VM을
직접 실행합니다.

동적 테스트는 CLI 전용·승인 게이트인 `kernel_test_run`을 통해서만 수행되며,
명시적 VM 격리 확인이 없으면 거부합니다. WSL 자체는 샌드박스로 취급하지
않습니다. 호스트 커널 퍼징은 범위 밖이며, syzkaller 어댑터는 읽기 전용(기존
인가된 실행 결과 요약만)입니다.

---

## 9. 보안 모델 요약

- 권한은 Python에서 강제됩니다. 모델은 스킬 인자로 워크스페이스 루트, 허용 목록,
  승인 상태, 타임아웃, 한도를 바꿀 수 없습니다.
- 파일 접근은 인가된 루트만 사용하고, 경로 이탈·보호 경로를 거부하며, 디렉터리
  구성요소를 `O_NOFOLLOW`로 엽니다. 읽기/쓰기는 심링크를 거부합니다. 쓰기는 임시
  파일 + `fsync` + 원자적 교체를 사용합니다.
- 오프라인 모드는 네트워크를 차단합니다. 온라인/하이브리드는 정확한(또는 명시적
  와일드카드) 도메인 허용 목록을 요구하고, IP 리터럴·비표준 포트·사설/루프백/링크
  로컬/예약/메타데이터 주소를 거부하며, 요청/리다이렉트마다 DNS를 검증하고 검증된
  IP로 연결을 고정합니다.
- 원본 크래시 증거는 불변(`0444`, `O_EXCL`)입니다.
- 감사 로그(`logs/audit.jsonl`)는 스킬 이름, task/origin, 인자·결과 해시, 상태,
  소요 시간만 기록하며 인자나 내용 자체는 저장하지 않습니다.

---

## 10. 설정 파일

- `configs/offline.yaml` — 오프라인(Ollama) 모델/GPU/컨텍스트, 워크스페이스 루트,
  연구 소스용 네트워크 허용 목록, 한도.
- `configs/online.yaml` — OpenAI 모델/단가/예산.
- `configs/hybrid.yaml` — 하이브리드 설정.
- `configs/models.yaml` — 모델 로스터(오프라인/온라인).
- `configs/resources.yaml` — 자원 예산(동시 추론 1, 빌드/테스트 1 등).
- `configs/skills.yaml` — 스킬별 권한 규칙(파일시스템/커널/네트워크).
- `configs/programs.yaml` — kernelCTF 프로그램 프로파일(범위, 버그 클래스→심각도,
  보고서 필드, 체크리스트, 타깃 인스턴스).

---

## 11. 알려진 제한 사항

- `syz-manager` 미설치 → syzkaller 어댑터는 읽기 전용이며 퍼징 오케스트레이션은
  없습니다.
- 선택적 코드 모델 `qwen2.5-coder:7b`는 기본 미설치입니다
  (`ollama pull qwen2.5-coder:7b`로 활성화).
- 콜그래프/함수 조회는 휴리스틱입니다(cscope/clang 인덱스 미사용).
- 온라인 에이전트는 `OPENAI_API_KEY`, 구성된 모델, 예산이 필요합니다.
- WSL2에서 KVM 가속은 보장되지 않습니다. `kernel_vm_status`가 실제 상태를
  보고합니다(미가속 시 TCG 소프트웨어 에뮬레이션으로 느려짐).

---

영어 문서는 [README.md](README.md), 단계별 예시는 [EXAMPLE.md](EXAMPLE.md),
보안 모델 상세는 [SECURITY.md](SECURITY.md)를 참고하세요.
